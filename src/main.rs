// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Certora

use {
    bzip2::bufread::BzDecoder,
    cargo_metadata::{camino::Utf8Path, CrateType, Metadata, MetadataCommand, Package, Target},
    clap::{CommandFactory, FromArgMatches, Parser},
    clap_verbosity_flag::VerbosityFilter,
    itertools::Itertools,
    log::{debug, error, info},
    semver::Version,
    serde_json::{json, to_string_pretty, Value},
    solana_file_download::download_file,
    std::{
        cell::RefCell,
        env,
        ffi::OsStr,
        fmt::Display,
        fs::{self, File},
        io::{self, prelude::*, BufReader, BufWriter},
        path::{Path, PathBuf},
        process::{exit, Command, Stdio},
    },
    tar::Archive,
};

const CERTORA_META_KEY: &str = "certora";
const SOURCES_META_KEY: &str = "sources";
const SOLANA_INLINING_KEY: &str = "solana_inlining";
const SOLANA_SUMMARIES_KEY: &str = "solana_summaries";

const DEFAULT_PLATFORM_TOOLS_VERSION: &str = "v1.41";
const PLATFORM_TOOLS_PACKAGE: &str = "platform-tools-certora";
const PLATFORM_TOOLS_URL: &str =
    "https://github.com/Certora/certora-solana-platform-tools/releases/download";

/// Default location of the root of all platform tools installations
fn default_platform_tools_root() -> PathBuf {
    home::home_dir()
        .unwrap_or_default()
        .join(".cache")
        .join("solana")
}

/// Location of a specific platform tools version
fn platform_tools_ver_root(root: &Path, ver: &str) -> PathBuf {
    root.join(ver).join(PLATFORM_TOOLS_PACKAGE)
}

#[derive(Debug, Default)]
struct RustFlags {
    flags: Vec<String>,
}

/// Join path to a json value
///
/// if v is a String, join it to the path
/// if v is an Array, apply join_path to all array elements
/// otherwise, return the value as is
fn join_path(path: &Utf8Path, v: &Value) -> Value {
    match v {
        Value::String(s) => serde_json::to_value(path.join(s)).unwrap(),
        Value::Array(items) => {
            serde_json::to_value(items.iter().map(|x| join_path(path, x)).collect::<Vec<_>>())
                .unwrap()
        }
        _ => v.clone(),
    }
}

/// Returns `true` if the directory exists and is empty, `false` if it exists and is not empty.
/// Returns an error if the path does not exist or is not a directory.
pub fn is_empty_dir(path: &Path) -> io::Result<bool> {
    if path.is_dir() {
        let mut entries = fs::read_dir(path)?;
        Ok(entries.next().is_none())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{path:?}` is not a directory"),
        ))
    }
}

impl RustFlags {
    pub fn new() -> Self {
        Self { flags: vec![] }
    }
    /// Add flags from an iterator
    pub fn add<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.flags.extend(iter)
    }

    pub fn add_flag(&mut self, flag: &str) {
        self.flags.push(flag.to_string())
    }

    /// Add flags from environment variable
    pub fn add_from_env(&mut self, env_var: &str) {
        if let Ok(val) = env::var(env_var) {
            self.add_from_str(&val);
        }
    }

    /// Add flags from a whitespace separated string
    pub fn add_from_str(&mut self, args: &str) {
        self.add(args.split_whitespace().map(|s| s.to_string()))
    }

    /// Add an llvm-args flag, if it is not already present
    pub fn add_llvm_flag(&mut self, arg: &str) {
        if self.flags.iter().any(|v| v.ends_with(arg)) {
            return;
        }
        self.flags.push(format!("-C llvm-args={}", arg))
    }

    /// Add an llvm-args argument (i.e., with value), if not present
    pub fn add_llvm_arg(&mut self, arg: &str, val: &str) {
        if self.flags.iter().any(|v| v.contains(arg)) {
            return;
        }
        self.flags.push(format!("-C llvm-args={}={}", arg, val))
    }

    pub fn add_c_arg(&mut self, arg: &str, val: &str) {
        if self.flags.iter().any(|v| v.contains(arg)) {
            return;
        }
        self.flags.push(format!("-C {}={}", arg, val));
    }

    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }
}

impl Display for RustFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.flags.iter().format(" ").fmt(f)
    }
}

fn spawn<I, S>(
    program: &Path,
    args: I,
    generate_child_script_on_failure: bool,
) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let args = Vec::from_iter(args);
    let msg = args
        .iter()
        .map(|arg| arg.as_ref().to_str().unwrap_or("?"))
        .join(" ");
    info!("spawn: {} {msg}", program.to_string_lossy());

    let child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| format!("Failed to execute {}: {}", program.display(), err))?;

    let output = child
        .wait_with_output()
        .map_err(|err| format!("Failed to wait on child process: {err}"))?;
    if !output.status.success() {
        if !generate_child_script_on_failure {
            return Err(format!(
                "execution of {:?} terminated with {}",
                program, output.status
            ));
        }
        debug!("generating dump script for failed spawn");
        let script_name = format!(
            "cargo-certora-sbf-child-script-{}.sh",
            program.file_name().unwrap().to_str().unwrap(),
        );
        let file = File::create(&script_name).unwrap();
        let mut out = BufWriter::new(file);
        for (key, value) in env::vars() {
            writeln!(out, "{key}=\"{value}\" \\").unwrap();
        }
        write!(out, "{}", program.display()).unwrap();
        writeln!(out, "{}", msg).unwrap();
        out.flush().unwrap();
        error!(
            "to rerun the failed command for debugging use {}",
            script_name,
        );
        return Err("Script failed. See debug dump for detail".into());
    }

    Ok(output
        .stdout
        .as_slice()
        .iter()
        .map(|&c| c as char)
        .collect::<String>())
}

/* fn is_version_string(arg: &str) -> Result<(), String> {
    let ver = if arg.matches('.').count() == 1 {
        arg.to_string() + ".0"
    } else {
        arg.to_string()
    };
    if ver.starts_with('v') && Version::parse(&ver[1..]).is_ok() {
        Ok(())
    } else {
        Err("a version string may start with 'v' and contains major and minor version numbers separated by a dot, e.g. v1.32 or 1.32".to_string())
    }
} */

fn get_home_dir_path() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "missing HOME environment variable".to_string())
}

fn find_installed_platform_tools() -> io::Result<Vec<String>> {
    let solana_cache_dir = get_home_dir_path()
        .map_err(io::Error::other)?
        .join(".cache")
        .join("solana");
    let package = PLATFORM_TOOLS_PACKAGE;

    Ok(std::fs::read_dir(solana_cache_dir)?
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.is_dir() && path.join(package).is_dir() {
                Some(path.to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect::<Vec<_>>())
}

fn get_latest_platform_tools_version() -> Result<String, String> {
    let url = "https://github.com/Certora/certora-solana-platform-tools/releases/latest";
    let resp = reqwest::blocking::get(url).map_err(|err| format!("Failed to GET {url}: {err}"))?;
    let path = std::path::Path::new(resp.url().path());
    let version = path.file_name().unwrap().to_string_lossy().to_string();
    Ok(version
        .strip_suffix("-certora")
        .ok_or_else(|| {
            format!(
                "Unexpected version `{version}`. \
            The version must end with suffix `-certora`."
            )
        })?
        .into())
}

fn to_semver(version: &str) -> String {
    let starts_with_v = version.starts_with('v');
    let dots = version.as_bytes().iter().fold(
        0,
        |n: u32, c| if *c == b'.' { n.saturating_add(1) } else { n },
    );
    match (dots, starts_with_v) {
        (0, false) => format!("{version}.0.0"),
        (0, true) => format!("{}.0.0", &version[1..]),
        (1, false) => format!("{version}.0"),
        (1, true) => format!("{}.0", &version[1..]),
        (_, false) => version.to_string(),
        (_, true) => version[1..].to_string(),
    }
}

#[derive(Parser)] // requires `derive` feature
#[command(name = "cargo")]
#[command(bin_name = "cargo")]
#[command(styles = CLAP_STYLING)]
enum CertoraSbfCargoCli {
    CertoraSbf(CertoraSbfArgs),
}

// See also `clap_cargo::style::CLAP_STYLING`
pub const CLAP_STYLING: clap::builder::styling::Styles = clap::builder::styling::Styles::styled()
    .header(clap_cargo::style::HEADER)
    .usage(clap_cargo::style::USAGE)
    .literal(clap_cargo::style::LITERAL)
    .placeholder(clap_cargo::style::PLACEHOLDER)
    .error(clap_cargo::style::ERROR)
    .valid(clap_cargo::style::VALID)
    .invalid(clap_cargo::style::INVALID);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, clap::ValueEnum)]
enum SbfArch {
    /// sbfv1 from platform tools <= 1.41
    Sbf,
    /// SBPF v0
    V0,
    /// SBPF v1
    V1,
    /// SBPF v2
    V2,
    /// SBPF v3
    V3,
}

impl std::fmt::Display for SbfArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SbfArch::Sbf => "sbf-solana-solana",
            SbfArch::V0 => "sbpf-solana-solana",
            SbfArch::V1 => "sbpfv1-solana-solana",
            SbfArch::V2 => "sbpfv2-solana-solana",
            SbfArch::V3 => "sbpfv3-solana-solana",
        };
        write!(f, "{}", s)
    }
}

#[derive(clap::Args, Debug)]
#[command(version, about, long_about = None)]
struct CertoraSbfArgs {
    #[command(flatten)]
    manifest: clap_cargo::Manifest,
    #[command(flatten)]
    features: clap_cargo::Features,
    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity,

    #[arg(long,
        env = "CERTORA_PLATFORM_TOOLS_ROOT",
        help = "Location of platform tools installations",
        value_name = "PATH",
        default_value_os_t = default_platform_tools_root(),
    )]
    platform_tools_root: PathBuf,
    #[arg(long, help = "Additional arguments to pass to cargo")]
    cargo_args: Option<Vec<String>>,
    #[arg(long)]
    remap_cwd: bool,
    #[arg(long, help = "Enable debug information in compiled binary")]
    debug: bool,
    #[arg(long, help = "Force fresh install of platform tools")]
    force_tools_install: bool,
    #[arg(long, help = "Do not install platform tools")]
    no_tools_install: bool,
    #[arg(long, help = "Do not attempt to build any packages")]
    no_build: bool,
    #[arg(long, help = "Do not create rustup entry for platform tools")]
    no_rustup: bool,
    #[arg(long, help = "Generate shell script on failure for debugging")]
    generate_child_script_on_failure: bool,
    #[arg(
        long,
        default_value_t = DEFAULT_PLATFORM_TOOLS_VERSION.to_string(),
        id = "tools_version",
        value_name = "VERSION",
        help = "Platform tools version to use")]
    tools_version: String,
    #[arg(long, short, help = "Number of parallel jobs")]
    jobs: Option<usize>,
    #[arg(long, value_enum, default_value_t = SbfArch::Sbf, help = "Specify sbf/sbpf architecture")]
    arch: SbfArch,
    #[arg(long, help = "Output JSON summary of the build")]
    json: bool,

    #[clap(skip)]
    metadata: RefCell<Option<Metadata>>,
}

fn find_first_cdylib_target(package: &Package) -> Option<&Target> {
    package
        .targets
        .iter()
        .find(|t| t.crate_types.contains(&CrateType::CDyLib))
}

/// This implementation provides functionality for managing and validating
/// platform tools versions, installing platform tools, and building Solana
/// packages using the Certora SBF SDK.
///
/// # Usage
///
/// This implementation is designed to be used as part of the Certora SBF SDK
/// for managing platform tools and building Solana packages. It provides
/// comprehensive error handling and logging to ensure a smooth development
/// experience.
///
/// - Ensure that the Solana CLI is installed and properly configured before
///   using this implementation.
/// - The implementation relies on specific environment variables and paths for
///   configuring the build process and linking the toolchain.
impl CertoraSbfArgs {
    fn get_rustc_path(&self, ver: &str) -> PathBuf {
        self.platform_tools_path(ver)
            .join("rust")
            .join("bin")
            .join("rustc")
    }

    fn get_cargo_path(&self, ver: &str) -> PathBuf {
        self.platform_tools_path(ver)
            .join("rust")
            .join("bin")
            .join("cargo")
    }

    fn check_platform_tools_version(&self, tools_version: &str) -> Result<(), String> {
        // -- quick check of known good version
        if tools_version == DEFAULT_PLATFORM_TOOLS_VERSION {
            return Ok(());
        }

        // -- check if requested matches available
        let normalized_requested = to_semver(tools_version);
        let requested_semver =
            Version::parse(&normalized_requested).map_err(|err| err.to_string())?;

        let installed_versions = find_installed_platform_tools().map_err(|e| e.to_string())?;
        if installed_versions.iter().any(|v| v == tools_version) {
            return Ok(());
        }

        // -- sanity check -- at least requested is not newer than what is available online
        let latest_version = get_latest_platform_tools_version()?;
        let normalized_latest = to_semver(&latest_version);

        let latest_semver = Version::parse(&normalized_latest).map_err(|err| err.to_string())?;
        if requested_semver <= latest_semver {
            Ok(())
        } else {
            Err(format!(
                "version `{tools_version}` appears to be newer than latest available version. \
            Latest available version is `{latest_version}`"
            ))
        }
    }

    fn platform_tools_path(&self, ver: &str) -> PathBuf {
        platform_tools_ver_root(&self.platform_tools_root, ver)
    }

    /// This function ensures that the specified platform tools version is downloaded, unpacked,
    /// and placed in the target path. If the `force_tools_install` flag is set, it will clean up
    /// any existing installation before proceeding. Additionally, it creates a symbolic link
    /// in the `platform-tools-sdk/sbf/dependencies` directory pointing to the installed tools.
    ///
    /// # Arguments
    ///
    /// * `download_file_name` - The name of the file to be downloaded.
    /// * `platform_tools_version` - The version of the platform tools to be installed.
    /// * `target_path` - The path where the platform tools should be installed.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the installation is successful.
    /// * `Err(String)` if an error occurs during the installation process.
    ///
    /// # Errors
    ///
    /// This function may return an error if:
    /// - The target path cannot be cleaned up or created.
    /// - The platform tools cannot be downloaded or unpacked.
    /// - A symbolic link cannot be created.
    ///
    /// # Behavior
    ///
    /// - If the `force_tools_install` flag is set, any existing installation at the target path
    ///   or in the dependencies directory will be removed.
    /// - If the target path is an empty directory, it will be removed before proceeding.
    /// - If the platform tools are already installed and valid, no further action is taken.
    /// - If the installation fails, the target path is cleaned up to recover from the failure.
    fn install_if_missing(
        &self,
        download_file_name: &str,
        platform_tools_version: &str,
        target_path: &Path,
    ) -> io::Result<()> {
        if self.force_tools_install {
            // if forcing install, clean up first
            if target_path.is_dir() {
                debug!("Removing directory: `{target_path:?}`");
                fs::remove_dir_all(target_path)?;
            }
        }

        // Check whether the target path is an empty directory, and remove it.
        if target_path.is_dir() && is_empty_dir(target_path)? {
            info!("Removing directory: {target_path:?}");
            fs::remove_dir(target_path)?;
        }

        if !target_path.is_dir()
            && !target_path
                .symlink_metadata()
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false)
        {
            if target_path.exists() {
                info!("Removing file: `{target_path:?}`");
                fs::remove_file(target_path)?;
            }
            fs::create_dir_all(target_path)?;

            let url = format!(
                "{PLATFORM_TOOLS_URL}/{platform_tools_version}-certora/{download_file_name}"
            );
            let download_file_path = target_path.join(download_file_name);
            if download_file_path.exists() {
                fs::remove_file(&download_file_path)?;
            }
            info!("downloading from: {url}");
            download_file(url.as_str(), &download_file_path, true, &mut None)
                .map_err(io::Error::other)?;
            let zip = File::open(&download_file_path)?;
            let tar = BzDecoder::new(BufReader::new(zip));
            let mut archive = Archive::new(tar);
            info!("unpacking to: `{target_path:?}`");
            archive.unpack(target_path)?;
            info!("removing: `{download_file_path:?}`");
            fs::remove_file(download_file_path)?;
        }
        Ok(())
    }

    fn install_platform_tools(&self, requested_version: Option<&str>) -> Result<PathBuf, String> {
        let arch = if cfg!(target_arch = "aarch64") {
            "aarch64"
        } else {
            "x86_64"
        };

        let requested_version = requested_version.unwrap_or(&self.tools_version);
        self.check_platform_tools_version(requested_version)?;

        let platform_tools_download_file_name = if cfg!(target_os = "macos") {
            format!("platform-tools-osx-{arch}.tar.bz2")
        } else {
            format!("platform-tools-linux-{arch}.tar.bz2")
        };

        let target_path = self.platform_tools_path(requested_version);
        if let Err(err) = self.install_if_missing(
            &platform_tools_download_file_name,
            requested_version,
            &target_path,
        ) {
            if target_path.exists() {
                fs::remove_dir_all(&target_path).map_err(|err| {
                    format!(
                        "failed to remove {:?} while recovering from installation failure: {err}",
                        target_path
                    )
                })?;
            }
            Err(format!("Failed to install platform-tools: {err}"))
        } else {
            Ok(target_path)
        }
    }

    fn rustup_link_toolchain(&self, toolchain_path: &Path) -> Result<(), String> {
        if self.no_rustup {
            return Ok(());
        }

        let toolchain_path = toolchain_path.join("rust");
        let rustup = PathBuf::from("rustup");
        let rustup_args = vec!["toolchain", "list", "-v"];
        let rustup_output = spawn(&rustup, &rustup_args, self.generate_child_script_on_failure)?;
        info!("rustup {}", rustup_args.join(" "));
        info!("{rustup_output}");

        let mut do_link = true;
        for line in rustup_output.lines() {
            if line.starts_with("certora-solana") {
                let mut it = line.split_whitespace();
                let _ = it.next();
                let path = it.next();
                if path.unwrap() != toolchain_path.to_str().unwrap() {
                    let rustup_args = vec!["toolchain", "uninstall", "certora-solana"];
                    let output =
                        spawn(&rustup, &rustup_args, self.generate_child_script_on_failure)?;
                    info!("rustup {}", rustup_args.join(" "));
                    info!("{output}");
                } else {
                    do_link = false;
                }
                break;
            }
        }
        if do_link {
            let rustup_args = vec![
                "toolchain",
                "link",
                "certora-solana",
                toolchain_path.to_str().unwrap(),
            ];

            match spawn(&rustup, &rustup_args, self.generate_child_script_on_failure) {
                Ok(output) => {
                    info!("rustup {}", rustup_args.join(" "));
                    info!("{output}");
                }
                Err(err) => {
                    info!("rustup {}", rustup_args.join(" "));
                    error!("{err}");
                    error!(
                        "toolchain registration failed. \
                            Try reinstalling certora-platform-tools using \
                             `cargo certora-sbf --force-tools-install`"
                    );
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    pub fn exec(&self) -> Result<Value, String> {
        // -- install platform tools if needed (or forced)
        if !self.no_tools_install {
            let tools_version = &self.tools_version;
            info!("installing platform tools: {tools_version}");
            let tools_path = self.install_platform_tools(Some(tools_version))?;
            self.rustup_link_toolchain(&tools_path)?;
        }

        if !self.no_build {
            // -- find solana package and compile it
            let package = self.find_solana_package(&self.tools_version)?;
            self.build_solana_package(&package, &self.tools_version)
        } else {
            Ok(serde_json::Value::Null)
        }
    }

    /// Returns reference to metadata
    ///
    /// Metadata is computed if necessary
    fn get_metadata_ref<'a>(&'a self, ver: &str) -> Result<&'a RefCell<Option<Metadata>>, String> {
        let mut metadata = self.metadata.borrow_mut();
        if metadata.is_none() {
            let mut metadata_command = MetadataCommand::new();
            metadata_command
                .cargo_path(self.get_cargo_path(ver))
                .env("RUSTC", self.get_rustc_path(ver));

            // -- forward manifest path
            if let Some(ref path) = self.manifest.manifest_path {
                metadata_command.manifest_path(path);
            }

            info!("{metadata_command:?}");
            // -- compute and cache metadata
            *metadata = Some(metadata_command.exec().map_err(|err| err.to_string())?);
        }
        drop(metadata);

        // -- get a reference to simplify the rest of the code
        Ok(&self.metadata)
    }

    /// Find the first solana package to compile
    ///
    /// # Arguments
    ///
    /// `ver` -- the version of platform-tools to use
    fn find_solana_package(&self, ver: &str) -> Result<Package, String> {
        let metadata_ref = self.get_metadata_ref(ver)?.borrow();
        let metadata = metadata_ref.as_ref().unwrap();

        // -- if there is a root package, stick with it
        if let Some(root_package) = metadata.root_package() {
            return Ok(root_package.clone());
        }

        // -- otherwise, find the only cdylib package
        let all_cdylib_packages = metadata
            .packages
            .iter()
            .filter(|p| {
                metadata.workspace_members.contains(&p.id)
                    && p.targets
                        .iter()
                        .any(|t| t.crate_types.contains(&CrateType::CDyLib))
            })
            .collect::<Vec<_>>();

        // -- fail if number of cdylib packages is unexpected
        let len = all_cdylib_packages.len();
        match len {
            0 => Err(
                "no cargo package with a cdylib target was found in the current workspace. \
                    Ensure that your Cargo.toml specifies a cdylib target."
                    .to_string(),
            ),
            1 => Ok(all_cdylib_packages[0].clone()),
            _ => Err("more than one cdylib package found".to_string()),
        }
    }

    /// Build a package using specific tools version
    ///
    /// # Arguments
    ///
    ///  * `package` -- Solana cdylib package to build
    ///  * `tools_version` -- Version of platform tools to use
    fn build_solana_package(
        &self,
        package: &Package,
        tools_version: &str,
    ) -> Result<Value, String> {
        let package_dir = package.manifest_path.parent().ok_or_else(|| {
            format!(
                "unexpected missing parent directory of {}",
                package.manifest_path
            )
        })?;
        env::set_current_dir(package_dir)
            .map_err(|err| format!("unable to change cwd to {}: {}", package_dir, err))?;

        let target = find_first_cdylib_target(package).ok_or_else(|| {
            "no cargo package with a cdylib target was found in the current workspace. \
            Ensure that your Cargo.toml specifies a cdylib target."
                .to_string()
        })?;

        let target_triple = self.arch.to_string();

        let platform_tools_path = self.platform_tools_path(tools_version);
        let llvm_bin = platform_tools_path.join("llvm").join("bin");
        env::set_var("CC", llvm_bin.join("clang"));
        env::set_var("AR", llvm_bin.join("llvm-ar"));
        env::set_var("OBJDUMP", llvm_bin.join("llvm-objdump"));
        env::set_var("OBJCOPY", llvm_bin.join("llvm-objcopy"));

        let cargo_target_rustflags = format!(
            "CARGO_TARGET_{}_RUSTFLAGS",
            target_triple.to_uppercase().replace("-", "_")
        );

        // -- space separated arguments. Multiple arguments per-entry are allowed
        let mut rust_flags = RustFlags::new();
        rust_flags.add_from_env("RUSTFLAGS");
        rust_flags.add_from_env(&cargo_target_rustflags);

        if self.remap_cwd && !self.debug {
            rust_flags.add_flag("-Zremap-cwd-prefix=");
        }

        if self.debug {
            // Replace with -Zsplit-debuginfo=packed when stabilized.
            rust_flags.add_flag("-g");
        }

        rust_flags.add_llvm_arg("--combiner-store-merging", "false");
        rust_flags.add_llvm_arg("--combiner-load-merging", "false");
        rust_flags.add_llvm_arg("--aggressive-instcombine-max-scan-instrs", "0");
        rust_flags.add_llvm_arg("--combiner-reduce-load-op-store-width", "false");
        rust_flags.add_llvm_arg("--combiner-shrink-load-replace-store-with-store", "false");
        rust_flags.add_llvm_arg("--sroa-max-memcpy-split", "8");
        rust_flags.add_c_arg("strip", "none");
        rust_flags.add_c_arg("debuginfo", "2");

        if self.tools_version.starts_with("v1.41") {
            // -- this option is not available in later platform tools
            rust_flags.add_llvm_flag("--sbf-expand-memcpy-in-order");
        }

        if !rust_flags.is_empty() {
            env::set_var(&cargo_target_rustflags, rust_flags.to_string());
        }
        info!(
            "{}=\"{}\"",
            cargo_target_rustflags,
            env::var(&cargo_target_rustflags).ok().unwrap_or_default(),
        );

        let cargo_build = if self.no_rustup {
            self.get_cargo_path(tools_version)
        } else {
            PathBuf::from("cargo")
        };

        let mut cargo_build_args: Vec<&str> = vec![];

        // always create for ownership reasons
        let rustc_path = self.get_rustc_path(tools_version);
        let build_rustc = format!("build.rustc=\"{}\"", rustc_path.to_string_lossy());
        if self.no_rustup {
            cargo_build_args.push("--config");
            cargo_build_args.push(&build_rustc);
        } else {
            cargo_build_args.push("+certora-solana");
        };

        cargo_build_args.push("build");
        cargo_build_args.push("--release");
        cargo_build_args.push("--target");
        cargo_build_args.push(&target_triple);

        cargo_build_args.push("--features=certora");

        if self.features.no_default_features {
            cargo_build_args.push("--no-default-features");
        }
        for feature in &self.features.features {
            cargo_build_args.push("--features");
            cargo_build_args.push(feature);
        }
        if self.verbose.filter() == VerbosityFilter::Debug {
            cargo_build_args.push("--verbose");
        }

        let jobs = self.jobs.map(|x| x.to_string());
        if let Some(jobs) = jobs.as_ref() {
            cargo_build_args.push("--jobs");
            cargo_build_args.push(jobs);
        }

        if let Some(cargo_args) = self.cargo_args.as_ref() {
            cargo_build_args.extend(cargo_args.iter().map(|x| x.as_str()));
        }

        let output = spawn(
            &cargo_build,
            &cargo_build_args,
            self.generate_child_script_on_failure,
        )?;
        info!("{}", output);

        let name = target.name.replace('-', "_");
        let metadata_ref = self.metadata.borrow();
        let metadata = metadata_ref.as_ref().unwrap();
        let workspace_root = &metadata.workspace_root;
        let target_build_directory = metadata
            .target_directory
            .join(&target_triple)
            .join("release");
        let rel_target_build_dir = target_build_directory
            .strip_prefix(workspace_root)
            .map_err(|err| format!("cannot compute relative directory due to {err}"))?;

        // -- absolute package root
        let package_root = package.manifest_path.parent().unwrap();
        // -- relative package root
        let rel_package_root = package_root.strip_prefix(workspace_root).unwrap();

        let sources = package
            .metadata
            .get(CERTORA_META_KEY)
            .and_then(|x| x.get(SOURCES_META_KEY).cloned())
            .unwrap_or_else(|| json!([]));

        let mut sources = join_path(rel_package_root, &sources);

        // add Cargo.toml from the workspace root
        sources.as_array_mut().unwrap().push("Cargo.toml".into());

        let mut data = json!({
             "project_directory": workspace_root,
             "executables": rel_target_build_dir.join(format!("{name}.so")),
             "sources": sources,
             "success": true,
             "return_code": 0,
        });

        package
            .metadata
            .get(CERTORA_META_KEY)
            .and_then(|x| x.get(SOLANA_INLINING_KEY))
            .map(|x| {
                data.as_object_mut()
                    .unwrap()
                    .insert(SOLANA_INLINING_KEY.into(), join_path(rel_package_root, x))
            });

        package
            .metadata
            .get(CERTORA_META_KEY)
            .and_then(|x| x.get(SOLANA_SUMMARIES_KEY))
            .map(|x| {
                data.as_object_mut()
                    .unwrap()
                    .insert(SOLANA_SUMMARIES_KEY.into(), join_path(rel_package_root, x))
            });

        Ok(data)
    }
}

fn main() {
    let cmd = CertoraSbfCargoCli::command();
    let matches = cmd.get_matches();

    // if let Some((_name, matches)) = matches.subcommand() {
    //     use clap::parser::ValueSource;
    //     if matches.value_source(&"tools_version") == Some(ValueSource::DefaultValue) {
    //         println!("source for tools version is default");
    //     } else {
    //         println!("tools version is explicitly requested");
    //     }
    // }

    let CertoraSbfCargoCli::CertoraSbf(args) = CertoraSbfCargoCli::from_arg_matches(&matches)
        .unwrap_or_else(|e| {
            e.exit();
        });
    // let CertoraSbfCargoCli::CertoraSbf(mut args) = CertoraSbfCargoCli::parse();

    // setup log level
    env_logger::builder()
        .format(|buf, record| {
            let level = record.level();
            let style = buf.default_level_style(level);
            let level = level.to_string().to_lowercase();
            writeln!(buf, "{style}{}{style:#}: {}", level, record.args())
        })
        .filter_level(args.verbose.log_level_filter())
        .init();

    match args.exec() {
        Ok(json) => {
            if args.json {
                println!("{}", to_string_pretty(&json).unwrap());
            }
        }
        Err(err) => {
            error!("{err}");
            if args.json {
                let data = json!({
                    "success": "false",
                    "return_code": 1,
                    "error_reason": err.to_string(),
                });
                println!("{}", to_string_pretty(&data).unwrap());
            }
            exit(1);
        }
    }
}
