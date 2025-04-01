// based on https://github.com/anza-xyz/agave/tree/master/platform-tools-sdk/cargo-certora-sbf
use {
    bzip2::bufread::BzDecoder,
    cargo_metadata::camino::Utf8PathBuf,
    clap::{crate_description, crate_name, crate_version, Arg},
    itertools::Itertools,
    log::*,
    regex::Regex,
    semver::Version,
    serde_json::json,
    solana_file_download::download_file,
    solana_keypair::{write_keypair_file, Keypair},
    std::{
        collections::HashMap,
        env,
        ffi::OsStr,
        fs::{self, File},
        io::{prelude::*, BufReader, BufWriter},
        path::{Path, PathBuf},
        process::{exit, Command, Stdio},
        str::FromStr,
    },
    tar::Archive,
};

const DEFAULT_PLATFORM_TOOLS_VERSION: &str = "v1.41";
const PLATFORM_TOOLS_PACKAGE: &str = "platform-tools-certora";

#[derive(Debug, Default)]
struct RustFlags {
    flags: Vec<String>,
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
        self.flags.extend(iter.into_iter())
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

    pub fn to_string(&self) -> String {
        self.flags.join(" ")
    }

    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }
}

#[derive(Debug)]
struct Config<'a> {
    cargo_args: Vec<&'a str>,
    target_directory: Option<Utf8PathBuf>,
    sbf_out_dir: Option<PathBuf>,
    sbf_sdk: PathBuf,
    platform_tools_version: Option<&'a str>,
    dump: bool,
    features: Vec<String>,
    force_tools_install: bool,
    skip_tools_install: bool,
    no_rustup_override: bool,
    generate_child_script_on_failure: bool,
    no_default_features: bool,
    offline: bool,
    remap_cwd: bool,
    debug: bool,
    verbose: bool,
    jobs: Option<String>,
    arch: &'a str,
    json: bool,
}

impl Default for Config<'_> {
    fn default() -> Self {
        let solana_exe = which::which("solana").expect("No `solana` CLI found on the PATH");
        let sbf_sdk_path = solana_exe
            .parent()
            .expect("Unable to get parent directory of `solana` CLI")
            .to_path_buf()
            .join("sdk")
            .join("sbf");

        // try one path if it exists. If not, assume it is the other
        // the actual path might be overridden on command line, so we should not abort yet
        let sbf_sdk_path = if sbf_sdk_path.is_dir() {
            sbf_sdk_path
        } else {
            solana_exe
                .parent()
                .expect("Unable to get parent directory of `solana` CLI")
                .to_path_buf()
                .join("platform-tools-sdk")
                .join("sbf")
        };

        Self {
            cargo_args: vec![],
            target_directory: None,
            sbf_sdk: sbf_sdk_path,
            sbf_out_dir: None,
            platform_tools_version: None,
            dump: false,
            features: vec![],
            force_tools_install: false,
            skip_tools_install: false,
            no_rustup_override: false,
            generate_child_script_on_failure: false,
            no_default_features: false,
            offline: false,
            remap_cwd: true,
            debug: false,
            verbose: false,
            jobs: None,
            arch: "sbf",
            json: false,
        }
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
    info!("spawn: {:?} {}", program, msg);

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
            return Err("Unexpected error".into());
        }
        error!("cargo-certora-sbf exited on command execution failure");
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
            "To rerun the failed command for debugging use {}",
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

pub fn is_version_string(arg: &str) -> Result<(), String> {
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
}

fn home_dir() -> Result<PathBuf, String> {
    let home_var = env::var_os("HOME")
        .ok_or_else(|| -> String { "Missing HOME in the environment".into() })?;

    Ok(PathBuf::from(home_var))
}

fn find_installed_platform_tools() -> Result<Vec<String>, String> {
    let solana_cache_dir = home_dir()?.join(".cache").join("solana");
    let package = PLATFORM_TOOLS_PACKAGE;

    if let Ok(dir) = std::fs::read_dir(solana_cache_dir) {
        Ok(dir
            .filter_map(|e| match e {
                Err(_) => None,
                Ok(e) => {
                    if e.path().join(package).is_dir() {
                        Some(e.path().file_name().unwrap().to_string_lossy().to_string())
                    } else {
                        None
                    }
                }
            })
            .collect::<Vec<_>>())
    } else {
        Ok(Vec::new())
    }
}

fn get_latest_platform_tools_version() -> Result<String, String> {
    let url = "https://github.com/Certora/certora-solana-platform-tools/releases/latest";
    let resp = reqwest::blocking::get(url).map_err(|err| format!("Failed to GET {url}: {err}"))?;
    let path = std::path::Path::new(resp.url().path());
    let version = path.file_name().unwrap().to_string_lossy().to_string();
    Ok(version
        .strip_suffix("-certora")
        .ok_or_else(|| format!("Unexpected version (must end with -certora): {version}"))?
        .to_owned())
}

fn get_base_rust_version(platform_tools_version: &str) -> Result<String, String> {
    let target_path =
        make_platform_tools_path_for_version(PLATFORM_TOOLS_PACKAGE, platform_tools_version)?;
    let rustc = target_path.join("rust").join("bin").join("rustc");
    if !rustc.exists() {
        return Err(format!("rustc not found at {:?}", rustc));
    }
    let args = vec!["--version"];
    let output = spawn(&rustc, args, false)?;
    let rustc_re = Regex::new(r"(rustc [0-9]+\.[0-9]+\.[0-9]+).*").unwrap();
    if rustc_re.is_match(output.as_str()) {
        let captures = rustc_re.captures(output.as_str()).unwrap();
        Ok(captures[1].to_string())
    } else {
        Err(format!("Unrecognized rustc version: {output}"))
    }
}

fn downloadable_version(version: &str) -> String {
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn semver_version(version: &str) -> String {
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

fn validate_platform_tools_version(
    requested_version: &str,
    builtin_version: &str,
) -> Result<String, String> {
    // Early return here in case it's the first time we're running `cargo build-sbf`
    // and we need to create the cache folders
    if requested_version == builtin_version {
        return Ok(builtin_version.to_string());
    }
    let normalized_requested = semver_version(requested_version);
    let requested_semver = Version::parse(&normalized_requested).unwrap();
    let installed_versions = find_installed_platform_tools()?;
    for v in installed_versions {
        if requested_semver <= Version::parse(&semver_version(&v)).unwrap() {
            return Ok(downloadable_version(requested_version));
        }
    }
    let latest_version = get_latest_platform_tools_version().unwrap_or_else(|err| {
        debug!(
            "Can't get the latest version of platform-tools: {}. Using built-in version {}.",
            err, builtin_version,
        );
        builtin_version.to_string()
    });
    let normalized_latest = semver_version(&latest_version);
    let latest_semver = Version::parse(&normalized_latest).unwrap();
    if requested_semver <= latest_semver {
        Ok(downloadable_version(requested_version))
    } else {
        warn!(
            "Version {} is not valid, latest version is {}. Using the built-in version {}",
            requested_version, latest_version, builtin_version,
        );
        Ok(builtin_version.to_string())
    }
}

fn make_platform_tools_path_for_version(package: &str, version: &str) -> Result<PathBuf, String> {
    Ok(home_dir()?
        .join(".cache")
        .join("solana")
        .join(version)
        .join(package))
}

// Check whether a package is installed and install it if missing.
fn install_if_missing(
    config: &Config,
    package: &str,
    url: &str,
    download_file_name: &str,
    platform_tools_version: &str,
    target_path: &Path,
) -> Result<(), String> {
    if config.force_tools_install {
        if target_path.is_dir() {
            debug!("Remove directory {:?}", target_path);
            fs::remove_dir_all(target_path).map_err(|err| err.to_string())?;
        }
        let source_base = config.sbf_sdk.join("dependencies");
        if source_base.exists() {
            let source_path = source_base.join(package);
            if source_path.exists() {
                debug!("Remove file {:?}", source_path);
                fs::remove_file(source_path).map_err(|err| err.to_string())?;
            }
        }
    }
    // Check whether the target path is an empty directory. This can
    // happen if package download failed on previous run of
    // cargo-certora-sbf.  Remove the target_path directory in this
    // case.
    if target_path.is_dir()
        && target_path
            .read_dir()
            .map_err(|err| err.to_string())?
            .next()
            .is_none()
    {
        debug!("Remove directory {:?}", target_path);
        fs::remove_dir(target_path).map_err(|err| err.to_string())?;
    }

    // Check whether the package is already in ~/.cache/solana.
    // Download it and place in the proper location if not found.
    if !target_path.is_dir()
        && !target_path
            .symlink_metadata()
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
    {
        if target_path.exists() {
            debug!("Remove file {:?}", target_path);
            fs::remove_file(target_path).map_err(|err| err.to_string())?;
        }
        fs::create_dir_all(target_path).map_err(|err| err.to_string())?;
        let mut url = String::from(url);
        url.push('/');
        url.push_str(platform_tools_version);
        url.push_str("-certora");
        url.push('/');
        url.push_str(download_file_name);
        let download_file_path = target_path.join(download_file_name);
        if download_file_path.exists() {
            fs::remove_file(&download_file_path).map_err(|err| err.to_string())?;
        }
        download_file(url.as_str(), &download_file_path, true, &mut None)?;
        let zip = File::open(&download_file_path).map_err(|err| err.to_string())?;
        let tar = BzDecoder::new(BufReader::new(zip));
        let mut archive = Archive::new(tar);
        archive.unpack(target_path).map_err(|err| err.to_string())?;
        fs::remove_file(download_file_path).map_err(|err| err.to_string())?;
    }
    // Make a symbolic link source_path -> target_path in the
    // platform-tools-sdk/sbf/dependencies directory if no valid link found.
    let source_base = config.sbf_sdk.join("dependencies");
    if !source_base.exists() {
        fs::create_dir_all(&source_base).map_err(|err| err.to_string())?;
    }
    let source_path = source_base.join(package);
    // Check whether the correct symbolic link exists.
    let invalid_link = if let Ok(link_target) = source_path.read_link() {
        if link_target.ne(target_path) {
            fs::remove_file(&source_path).map_err(|err| err.to_string())?;
            true
        } else {
            false
        }
    } else {
        true
    };
    if invalid_link {
        #[cfg(unix)]
        std::os::unix::fs::symlink(target_path, source_path).map_err(|err| err.to_string())?;
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target_path, source_path)
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

// Process dump file attributing call instructions with callee function names
fn postprocess_dump(program_dump: &Path) {
    if !program_dump.exists() {
        return;
    }
    let postprocessed_dump = program_dump.with_extension("postprocessed");
    let head_re = Regex::new(r"^([0-9a-f]{16}) (.+)").unwrap();
    let insn_re = Regex::new(r"^ +([0-9]+)((\s[0-9a-f]{2})+)\s.+").unwrap();
    let call_re = Regex::new(r"^ +([0-9]+)(\s[0-9a-f]{2})+\scall (-?)0x([0-9a-f]+)").unwrap();
    let relo_re = Regex::new(r"^([0-9a-f]{16})  [0-9a-f]{16} R_BPF_64_32 +0{16} (.+)").unwrap();
    let mut a2n: HashMap<i64, String> = HashMap::new();
    let mut rel: HashMap<u64, String> = HashMap::new();
    let mut name = String::from("");
    let mut state = 0;
    let Ok(file) = File::open(program_dump) else {
        return;
    };
    for line_result in BufReader::new(file).lines() {
        let line = line_result.unwrap();
        let line = line.trim_end();
        if line == "Disassembly of section .text" {
            state = 1;
        }
        if state == 0 {
            if relo_re.is_match(line) {
                let captures = relo_re.captures(line).unwrap();
                let address = u64::from_str_radix(&captures[1], 16).unwrap();
                let symbol = captures[2].to_string();
                rel.insert(address, symbol);
            }
        } else if state == 1 {
            if head_re.is_match(line) {
                state = 2;
                let captures = head_re.captures(line).unwrap();
                name = captures[2].to_string();
            }
        } else if state == 2 {
            state = 1;
            if insn_re.is_match(line) {
                let captures = insn_re.captures(line).unwrap();
                let address = i64::from_str(&captures[1]).unwrap();
                a2n.insert(address, name.clone());
            }
        }
    }
    let Ok(file) = File::create(&postprocessed_dump) else {
        return;
    };
    let mut out = BufWriter::new(file);
    let Ok(file) = File::open(program_dump) else {
        return;
    };
    let mut pc = 0u64;
    let mut step = 0u64;
    for line_result in BufReader::new(file).lines() {
        let line = line_result.unwrap();
        let line = line.trim_end();
        if head_re.is_match(line) {
            let captures = head_re.captures(line).unwrap();
            pc = u64::from_str_radix(&captures[1], 16).unwrap();
            writeln!(out, "{line}").unwrap();
            continue;
        }
        if insn_re.is_match(line) {
            let captures = insn_re.captures(line).unwrap();
            step = if captures[2].len() > 24 { 16 } else { 8 };
        }
        if call_re.is_match(line) {
            if rel.contains_key(&pc) {
                writeln!(out, "{} ; {}", line, rel[&pc]).unwrap();
            } else {
                let captures = call_re.captures(line).unwrap();
                let pc = i64::from_str(&captures[1]).unwrap().checked_add(1).unwrap();
                let offset = i64::from_str_radix(&captures[4], 16).unwrap();
                let offset = if &captures[3] == "-" {
                    offset.checked_neg().unwrap()
                } else {
                    offset
                };
                let address = pc.checked_add(offset).unwrap();
                if a2n.contains_key(&address) {
                    writeln!(out, "{} ; {}", line, a2n[&address]).unwrap();
                } else {
                    writeln!(out, "{line}").unwrap();
                }
            }
        } else {
            writeln!(out, "{line}").unwrap();
        }
        pc = pc.checked_add(step).unwrap();
    }
    fs::rename(postprocessed_dump, program_dump).unwrap();
}

// check whether custom solana toolchain is linked, and link it if it is not.
fn rustup_link_certora_toolchain(config: &Config) -> Result<(), String> {
    let toolchain_path = config
        .sbf_sdk
        .join("dependencies")
        .join(PLATFORM_TOOLS_PACKAGE)
        .join("rust");
    let rustup = PathBuf::from("rustup");
    let rustup_args = vec!["toolchain", "list", "-v"];
    let rustup_output = spawn(
        &rustup,
        rustup_args,
        config.generate_child_script_on_failure,
    )?;
    if config.verbose {
        debug!("{}", rustup_output);
    }
    let mut do_link = true;
    for line in rustup_output.lines() {
        if line.starts_with("certora-solana") {
            let mut it = line.split_whitespace();
            let _ = it.next();
            let path = it.next();
            if path.unwrap() != toolchain_path.to_str().unwrap() {
                let rustup_args = vec!["toolchain", "uninstall", "certora-solana"];
                let output = spawn(
                    &rustup,
                    rustup_args,
                    config.generate_child_script_on_failure,
                )?;
                if config.verbose {
                    debug!("{}", output);
                }
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
        let output = spawn(
            &rustup,
            rustup_args,
            config.generate_child_script_on_failure,
        )?;
        if config.verbose {
            debug!("{}", output);
        }
    }
    Ok(())
}

fn install_platform_tools(
    platform_tools_version: &str,
    arch: &str,
    config: &Config,
) -> Result<String, String> {
    let platform_tools_version =
        validate_platform_tools_version(platform_tools_version, DEFAULT_PLATFORM_TOOLS_VERSION)?;

    let platform_tools_download_file_name = if cfg!(target_os = "windows") {
        format!("platform-tools-windows-{arch}.tar.bz2")
    } else if cfg!(target_os = "macos") {
        format!("platform-tools-osx-{arch}.tar.bz2")
    } else {
        format!("platform-tools-linux-{arch}.tar.bz2")
    };
    let package = PLATFORM_TOOLS_PACKAGE;
    let target_path = make_platform_tools_path_for_version(package, &platform_tools_version)?;
    install_if_missing(
        config,
        package,
        "https://github.com/Certora/certora-solana-platform-tools/releases/download",
        platform_tools_download_file_name.as_str(),
        &platform_tools_version,
        &target_path,
    )
    .map_err(|err| -> String {
        // The package version directory doesn't contain a valid
        // installation, and it should be removed.
        let target_path_parent = target_path.parent();
        if target_path_parent.is_none() {
            return format!("No parent of {:?}", target_path);
        }
        let target_path_parent = target_path_parent.unwrap();
        if target_path_parent.exists() {
            if fs::remove_dir_all(target_path_parent).is_err() {
                return format!(
                    "Failed to remove {} while recovering from installation failure: {}",
                    target_path_parent.to_string_lossy(),
                    err,
                );
            }
        }
        // -- expected error message
        format!("Failed to install platform-tools: {}", err)
    })?;

    Ok(platform_tools_version)
}

fn build_solana_package(
    config: &Config,
    target_directory: &Path,
    package: &cargo_metadata::Package,
    metadata: &cargo_metadata::Metadata,
) -> Result<(), String> {
    let program_name = {
        let cdylib_targets = package
            .targets
            .iter()
            .filter_map(|target| {
                if target.crate_types.contains(&"cdylib".to_string()) {
                    Some(&target.name)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        match cdylib_targets.len() {
            0 => {
                warn!(
                    "Note: {} crate does not contain a cdylib target",
                    package.name
                );
                None
            }
            1 => Some(cdylib_targets[0].replace('-', "_")),
            _ => {
                return Err(format!(
                    "{} crate contains multiple cdylib targets: {:?}",
                    package.name, cdylib_targets
                ));
            }
        }
    };

    let legacy_program_feature_present = package.name == "solana-sdk";
    let root_package_dir = &package.manifest_path.parent().ok_or_else(|| -> String {
        format!("Unable to get directory of {}", package.manifest_path)
    })?;

    let sbf_out_dir = config
        .sbf_out_dir
        .clone()
        .unwrap_or_else(|| target_directory.join("deploy"));

    let target_triple = if config.arch == "v0" {
        "sbpf-solana-solana".to_string()
    } else if config.arch == "sbf" {
        "sbf-solana-solana".to_string()
    } else {
        format!("sbpf{}-solana-solana", config.arch)
    };

    let target_build_directory = target_directory.join(&target_triple).join("release");

    env::set_current_dir(root_package_dir).map_err(|err| {
        format!(
            "unable to set current directory to {}: {}",
            root_package_dir, err
        )
    })?;

    let platform_tools_version = config.platform_tools_version.unwrap_or_else(|| {
        let workspace_tools_version = metadata.workspace_metadata.get("solana").and_then(|v| v.get("tools-version")).and_then(|v| v.as_str());
        let package_tools_version = package.metadata.get("solana").and_then(|v| v.get("tools-version")).and_then(|v| v.as_str());
        match (workspace_tools_version, package_tools_version) {
            (Some(workspace_version), Some(package_version)) => {
                if workspace_version != package_version {
                    warn!("Workspace and package specify conflicting tools versions, {workspace_version} and {package_version}, using package version {package_version}");
                }
                package_version
            },
            (Some(workspace_version), None) => workspace_version,
            (None, Some(package_version)) => package_version,
            (None, None) => DEFAULT_PLATFORM_TOOLS_VERSION,
        }
    });

    info!("Solana SDK: {}", config.sbf_sdk.display());
    if config.no_default_features {
        info!("No default features");
    }
    if !config.features.is_empty() {
        info!("Features: {}", config.features.join(" "));
    }
    if legacy_program_feature_present {
        info!("Legacy program feature detected");
    }
    let arch = if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    };

    // -- update the version based on what is installed, it is possible
    // -- that requested version was not available and another was substituted
    let platform_tools_version = if !config.skip_tools_install {
        install_platform_tools(platform_tools_version, arch, config)?
    } else {
        platform_tools_version.to_string()
    };

    if config.no_rustup_override {
        check_solana_target_installed(&target_triple)?;
    } else {
        rustup_link_certora_toolchain(config)?;
        // RUSTC variable overrides cargo +<toolchain> mechanism of
        // selecting the rust compiler and makes cargo run a rust compiler
        // other than the one linked in Solana toolchain. We have to prevent
        // this by removing RUSTC from the child process environment.
        if env::var("RUSTC").is_ok() {
            warn!(
                "Removed RUSTC from cargo environment, because it overrides +solana cargo command line option."
            );
            env::remove_var("RUSTC")
        }
    }

    let llvm_bin = config
        .sbf_sdk
        .join("dependencies")
        .join(PLATFORM_TOOLS_PACKAGE)
        .join("llvm")
        .join("bin");
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

    if config.remap_cwd && !config.debug {
        rust_flags.add_flag("-Zremap-cwd-prefix=");
    }

    if config.debug {
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

    if platform_tools_version.starts_with("v1.41") {
        // -- this option is not available in later platform tools
        rust_flags.add_llvm_flag("--sbf-expand-memcpy-in-order");
    }

    if !rust_flags.is_empty() {
        env::set_var(&cargo_target_rustflags, &rust_flags.to_string());
    }
    if config.verbose {
        debug!(
            "{}=\"{}\"",
            cargo_target_rustflags,
            env::var(&cargo_target_rustflags).ok().unwrap_or_default(),
        );
    }

    let cargo_build = PathBuf::from("cargo");
    let mut cargo_build_args = vec![];
    if !config.no_rustup_override {
        cargo_build_args.push("+certora-solana");
    };

    cargo_build_args.append(&mut vec!["build", "--release", "--target", &target_triple]);

    cargo_build_args.push("--features=certora");

    if config.no_default_features {
        cargo_build_args.push("--no-default-features");
    }
    for feature in &config.features {
        cargo_build_args.push("--features");
        cargo_build_args.push(feature);
    }
    if legacy_program_feature_present {
        if !config.no_default_features {
            cargo_build_args.push("--no-default-features");
        }
        cargo_build_args.push("--features=program");
    }
    if config.verbose {
        cargo_build_args.push("--verbose");
    }
    if let Some(jobs) = &config.jobs {
        cargo_build_args.push("--jobs");
        cargo_build_args.push(jobs);
    }
    cargo_build_args.append(&mut config.cargo_args.clone());
    let output = spawn(
        &cargo_build,
        &cargo_build_args,
        config.generate_child_script_on_failure,
    )?;
    if config.verbose {
        debug!("{}", output);
    }

    if let Some(program_name) = program_name {
        let program_unstripped_so = target_build_directory.join(format!("{program_name}.so"));
        let program_dump = sbf_out_dir.join(format!("{program_name}-dump.txt"));
        let program_keypair = sbf_out_dir.join(format!("{program_name}-keypair.json"));

        fn file_older_or_missing(
            prerequisite_file: &Path,
            target_file: &Path,
        ) -> Result<bool, String> {
            let prerequisite_metadata = fs::metadata(prerequisite_file).map_err(|err| {
                format!(
                    "Unable to get file metadata for {}: {}",
                    prerequisite_file.display(),
                    err
                )
            })?;

            let res = if let Ok(target_metadata) = fs::metadata(target_file) {
                use std::time::UNIX_EPOCH;
                prerequisite_metadata.modified().unwrap_or(UNIX_EPOCH)
                    > target_metadata.modified().unwrap_or(UNIX_EPOCH)
            } else {
                true
            };
            Ok(res)
        }

        if !program_keypair.exists() {
            write_keypair_file(&Keypair::new(), &program_keypair).map_err(|err| {
                format!(
                    "Unable to get create {}: {}",
                    program_keypair.display(),
                    err
                )
            })?;
        }

        if config.dump && file_older_or_missing(&program_unstripped_so, &program_dump)? {
            let dump_script = config.sbf_sdk.join("scripts").join("dump.sh");
            let output = spawn(
                &dump_script,
                [&program_unstripped_so, &program_dump],
                config.generate_child_script_on_failure,
            )?;
            if config.verbose {
                debug!("{}", output);
            }

            postprocess_dump(&program_dump);
        }
    } else if config.dump {
        warn!("Note: --dump is only available for crates with a cdylib target");
    }

    Ok(())
}

// allow user to set proper `rustc` into RUSTC or into PATH
fn check_solana_target_installed(target: &str) -> Result<(), String> {
    let rustc = env::var("RUSTC").unwrap_or("rustc".to_owned());
    let rustc = PathBuf::from(rustc);
    let output = spawn(&rustc, ["--print", "target-list"], false)?;
    if !output.contains(target) {
        return Err(format!("Provided {:?} does not have {} target. The Solana rustc must be available in $PATH or the $RUSTC environment variable for the build to succeed.", rustc, target));
    }
    Ok(())
}

fn build_solana(config: Config, manifest_path: Option<PathBuf>) -> Result<(), String> {
    let mut metadata_command = cargo_metadata::MetadataCommand::new();
    if let Some(manifest_path) = manifest_path {
        metadata_command.manifest_path(manifest_path);
    }
    if config.offline {
        metadata_command.other_options(vec!["--offline".to_string()]);
    }

    let metadata = metadata_command.exec().map_err(|err| format!("{err}"))?;

    let target_dir = config
        .target_directory
        .clone()
        .unwrap_or(metadata.target_directory.clone());

    if let Some(root_package) = metadata.root_package() {
        return build_solana_package(&config, target_dir.as_ref(), root_package, &metadata);
    }

    let all_sbf_packages = metadata
        .packages
        .iter()
        .filter(|package| {
            if metadata.workspace_members.contains(&package.id) {
                for target in package.targets.iter() {
                    if target.kind.contains(&"cdylib".to_string()) {
                        return true;
                    }
                }
            }
            false
        })
        .collect::<Vec<_>>();

    if all_sbf_packages.len() > 1 {
        return Err("Compiling multiple crates at once in a workspace is not supported.".into());
    }

    for package in all_sbf_packages {
        build_solana_package(&config, target_dir.as_ref(), package, &metadata)?;
    }

    Ok(())
}

// fn app_run() -> Result<(), String> {
//     solana_logger::setup();
//     let default_config = Config::default();
//     let default_sbf_sdk = format!("{}", default_config.sbf_sdk.display());

//     let mut args = env::args().collect::<Vec<_>>();
//     // When run as a cargo subcommand, the first program argument is the subcommand name.
//     // Remove it
//     if let Some(arg1) = args.get(1) {
//         if arg1 == "certora-sbf" {
//             args.remove(1);
//         }
//     }

//     // The following line is scanned by CI configuration script to
//     // separate cargo caches according to the version of platform-tools.
//     // let rust_base_version = get_base_rust_version(DEFAULT_PLATFORM_TOOLS_VERSION)?;
//     // let rust_base_version = "UNKNOWN".to_string();
//     // let version = format!(
//     //     "{}\nplatform-tools-certora {}\n{}",
//     //     crate_version!(),
//     //     DEFAULT_PLATFORM_TOOLS_VERSION,
//     //     rust_base_version,
//     // );
//     let matches = clap::Command::new(crate_name!())
//         .about(crate_description!())
//         .version(crate_version!())
//         .arg(
//             Arg::new("sbf_out_dir")
//                 .env("SBF_OUT_PATH")
//                 .long("sbf-out-dir")
//                 .value_name("DIRECTORY")
//                 .takes_value(true)
//                 .help("Place final SBF build artifacts in this directory"),
//         )
//         .arg(
//             Arg::new("sbf_sdk")
//                 .env("SBF_SDK_PATH")
//                 .long("sbf-sdk")
//                 .value_name("PATH")
//                 .takes_value(true)
//                 .default_value(&default_sbf_sdk)
//                 .help("Path to the Solana SBF SDK"),
//         )
//         .arg(
//             Arg::new("cargo_args")
//                 .help("Arguments passed directly to `cargo build`")
//                 .multiple_occurrences(true)
//                 .multiple_values(true)
//                 .last(true),
//         )
//         .arg(
//             Arg::new("remap_cwd")
//                 .long("disable-remap-cwd")
//                 .takes_value(false)
//                 .help("Disable remap of cwd prefix and preserve full path strings in binaries"),
//         )
//         .arg(
//             Arg::new("debug")
//                 .long("debug")
//                 .takes_value(false)
//                 .help("Enable debug symbols"),
//         )
//         .arg(
//             Arg::new("dump")
//                 .long("dump")
//                 .takes_value(false)
//                 .help("Dump ELF information to a text file on success"),
//         )
//         .arg(
//             Arg::new("features")
//                 .long("features")
//                 .value_name("FEATURES")
//                 .takes_value(true)
//                 .multiple_occurrences(true)
//                 .multiple_values(true)
//                 .help("Space-separated list of features to activate"),
//         )
//         .arg(
//             Arg::new("force_tools_install")
//                 .long("force-tools-install")
//                 .takes_value(false)
//                 .conflicts_with("skip_tools_install")
//                 .help("Download and install platform-tools even when existing tools are located"),
//         )
//         .arg(
//             Arg::new("skip_tools_install")
//                 .long("skip-tools-install")
//                 .takes_value(false)
//                 .conflicts_with("force_tools_install")
//                 .help("Skip downloading and installing platform-tools, assuming they are properly mounted"),
//             )
//             .arg(
//                 Arg::new("no_rustup_override")
//                 .long("no-rustup-override")
//                 .takes_value(false)
//                 .conflicts_with("force_tools_install")
//                 .help("Do not use rustup to manage the toolchain. By default, cargo-certora-sbf invokes rustup to find the Solana rustc using a `+solana` toolchain override. This flag disables that behavior."),
//         )
//         .arg(
//             Arg::new("generate_child_script_on_failure")
//                 .long("generate-child-script-on-failure")
//                 .takes_value(false)
//                 .help("Generate a shell script to rerun a failed subcommand"),
//         )
//         .arg(
//             Arg::new("manifest_path")
//                 .long("manifest-path")
//                 .value_name("PATH")
//                 .takes_value(true)
//                 .help("Path to Cargo.toml"),
//         )
//         .arg(
//             Arg::new("no_default_features")
//                 .long("no-default-features")
//                 .takes_value(false)
//                 .help("Do not activate the `default` feature"),
//         )
//         .arg(
//             Arg::new("offline")
//                 .long("offline")
//                 .takes_value(false)
//                 .help("Run without accessing the network"),
//         )
//         .arg(
//             Arg::new("tools_version")
//                 .long("tools-version")
//                 .value_name("STRING")
//                 .takes_value(true)
//                 .validator(is_version_string)
//                 .help(
//                     "platform-tools version to use or to install, a version string, e.g. \"v1.32\"",
//                 ),
//         )
//         .arg(
//             Arg::new("verbose")
//                 .short('v')
//                 .long("verbose")
//                 .takes_value(false)
//                 .help("Use verbose output"),
//         )
//         .arg(Arg::new("json")
//                 .long("json")
//                 .takes_value(false)
//                 .help("Output status in JSON")
//         )
//        .arg(
//             Arg::new("jobs")
//                 .short('j')
//                 .long("jobs")
//                 .takes_value(true)
//                 .value_name("N")
//                 .validator(|val| val.parse::<usize>().map_err(|e| e.to_string()))
//                 .help("Number of parallel jobs, defaults to # of CPUs"),
//         )
//         .arg(
//             Arg::new("arch")
//                 .long("arch")
//                 .possible_values(["sbf", "v0", "v1", "v2", "v3"])
//                 .default_value("sbf")
//                 .help("Build for the given target architecture"),
//         )
//         .get_matches_from(args);

//     let sbf_sdk: PathBuf = matches.value_of_t_or_exit("sbf_sdk");
//     let sbf_out_dir: Option<PathBuf> = matches.value_of_t("sbf_out_dir").ok();

//     let mut cargo_args = matches
//         .values_of("cargo_args")
//         .map(|vals| vals.collect::<Vec<_>>())
//         .unwrap_or_default();

//     let target_dir_string;
//     let target_directory = if let Some(target_dir) = cargo_args
//         .iter_mut()
//         .skip_while(|x| x != &&"--target-dir")
//         .nth(1)
//     {
//         let target_path = Utf8PathBuf::from(*target_dir);
//         // Directory needs to exist in order to canonicalize it
//         fs::create_dir_all(&target_path)
//             .map_err(|err| format!("Unable to create target-dir directory {target_dir}: {err}"))?;

//         // Canonicalize the path to avoid issues with relative paths
//         let canonicalized = target_path.canonicalize_utf8().map_err(|err| {
//             format!("Unable to canonicalize provided target-dir directory {target_path}: {err}")
//         })?;
//         target_dir_string = canonicalized.to_string();
//         *target_dir = &target_dir_string;
//         Some(canonicalized)
//     } else {
//         None
//     };

//     let config = Config {
//         cargo_args,
//         target_directory,
//         sbf_sdk: fs::canonicalize(&sbf_sdk).map_err(|err| {
//             format!(
//                 "Solana SDK path does not exist: {}: {}",
//                 sbf_sdk.display(),
//                 err
//             )
//         })?,
//         sbf_out_dir: sbf_out_dir.map(|sbf_out_dir| {
//             if sbf_out_dir.is_absolute() {
//                 sbf_out_dir
//             } else {
//                 env::current_dir()
//                     .expect("Unable to get current working directory")
//                     .join(sbf_out_dir)
//             }
//         }),
//         platform_tools_version: matches.value_of("tools_version"),
//         dump: matches.is_present("dump"),
//         features: matches.values_of_t("features").ok().unwrap_or_default(),
//         force_tools_install: matches.is_present("force_tools_install"),
//         skip_tools_install: matches.is_present("skip_tools_install"),
//         no_rustup_override: matches.is_present("no_rustup_override"),
//         generate_child_script_on_failure: matches.is_present("generate_child_script_on_failure"),
//         no_default_features: matches.is_present("no_default_features"),
//         remap_cwd: !matches.is_present("remap_cwd"),
//         debug: matches.is_present("debug"),
//         offline: matches.is_present("offline"),
//         verbose: matches.is_present("verbose"),
//         jobs: matches.value_of_t("jobs").ok(),
//         arch: matches.value_of("arch").unwrap(),
//         json: matches.is_present("json"),
//     };
//     let manifest_path: Option<PathBuf> = matches.value_of_t("manifest_path").ok();
//     if config.verbose {
//         debug!("{:?}", config);
//         debug!("manifest_path: {:?}", manifest_path);
//     }
//     build_solana(config, manifest_path)
// }
// fn main() {
//     if let Err(msg) = app_run() {
//         eprintln!("error: {}", msg);
//         println!("{}", json!({"success": false, "return_code": 1}));
//         exit(1);
//     }
// }

use clap::Parser;

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

#[derive(clap::Args, Debug)]
#[command(version, about, long_about = None)]
struct CertoraSbfArgs {
    #[command(flatten)]
    manifest: clap_cargo::Manifest,
    #[command(flatten)]
    features: clap_cargo::Features,
    #[arg(long, env = "SBF_OUT_PATH", help = "Output directory for build artifacts")]
    sbf_out_dir: Option<PathBuf>,
    #[arg(long, env = "SBF_SDK_PATH", help = "Path to Solana SDK")]
    sbf_sdk: Option<PathBuf>,
    #[arg(long, help = "Additional arguments to pass to cargo")]
    cargo_args: Option<Vec<String>>,
    #[arg(long)]
    remap_cwd: bool,
    #[arg(long, help = "Enable debug information in compiled binary")]
    debug: bool,
    #[arg(long, help = "Dump sbf assembly for compiled binary")]
    dump: bool,
    #[arg(long, help = "Force fresh install of platform tools")]
    force_tools_install: bool,
    #[arg(long, help = "Do not attempt to install platform tools")]
    skip_tools_install: bool,
    #[arg(long, help = "Do not override rustup to point to platform tools")]
    no_rustup_override: bool,
    #[arg(long, help = "Generate shell script on failure for debugging")]
    generate_child_script_on_failure: bool,
    #[arg(long, default_value_t = DEFAULT_PLATFORM_TOOLS_VERSION.to_string(), help = "Platform tools version to use")]
    tools_version: String,
    #[arg(long, short, help = "Verbose output")]
    verbose: bool,
    #[arg(long, short, help = "Number of parallel jobs")]
    jobs: Option<usize>,
    #[arg(long, value_enum, default_value_t = SbfArch::Sbf, help = "Specify sbf/sbpf architecture")]
    arch: SbfArch,
}

fn main() {
    let CertoraSbfCargoCli::CertoraSbf(args) = CertoraSbfCargoCli::parse();
    println!("{:?}", args);
}
