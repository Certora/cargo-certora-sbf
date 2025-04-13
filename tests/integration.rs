use std::path::PathBuf;

use assert_cmd::Command;
use assert_fs::prelude::*;
use predicates::prelude::*;

#[test]
fn test_help() {
    let mut cmd = Command::cargo_bin("cargo-certora-sbf").unwrap();
    cmd.arg("certora-sbf")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage"));
}

#[test]
fn test_on_test_project() {
    // Create a temporary directory
    let temp = assert_fs::TempDir::new().unwrap();
    let temp = temp.into_persistent();

    // Create a minimal Cargo project inside it
    temp.child("Cargo.toml")
        .write_str(
            r#"
[package]
name = "test_proj"
version = "0.1.0"
edition = "2021"
[lib]
crate-type = ["cdylib"]
name = "test_proj"
[features]
certora = []
    "#,
        )
        .unwrap();

    temp.child("src/lib.rs")
        .write_str(
            r#"
        #[no_mangle]
        pub fn foo () {
            println!("Hello, world!");
        }
    "#,
        )
        .unwrap();

    // Run the subcommand inside the temp project
    let mut cmd = Command::cargo_bin("cargo-certora-sbf").unwrap();
    let cmd_path = PathBuf::from(cmd.get_program());
    let tools_root_path = cmd_path.parent().unwrap().join("certora-tools-root");
    let platform_tools_root_arg = format!("--platform-tools-root={}", tools_root_path.to_string_lossy());
    cmd.arg("certora-sbf")
        .arg("--no-rustup")
        .arg("-vv")
        .arg(&platform_tools_root_arg)
        .current_dir(temp.path())
        .env_clear()
        .assert()
        .success()
        .stderr(predicate::str::contains("Finished release"));

    // Cleanup
    temp.close().unwrap();
}
