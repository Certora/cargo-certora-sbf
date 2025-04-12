use assert_cmd::Command;
//use assert_fs::prelude::*;
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

// Needs more thought
// #[test]
// fn test_on_temp_project() {
//     // Create a temporary directory
//     let temp = assert_fs::TempDir::new().unwrap();

//     // Create a minimal Cargo project inside it
//     temp.child("Cargo.toml")
//         .write_str(
//             r#"
//         [package]
//         name = "temp_proj"
//         version = "0.1.0"
//         edition = "2021"
//         [lib]
//         crate-type = ["cdylib"]
//         name = "temp_proj"
//         [features]
//         certora = []
//     "#,
//         )
//         .unwrap();

//     temp.child("src/lib.rs")
//         .write_str(
//             r#"
//         #[no_mangle]
//         pub fn foo () {
//             println!("Hello, world!");
//         }
//     "#,
//         )
//         .unwrap();

//     // Run the subcommand inside the temp project
//     let mut cmd = Command::cargo_bin("cargo-certora-sbf").unwrap();
//     cmd.current_dir(temp.path())
//         .assert()
//         .success()
//         .stdout(predicate::str::contains("expected output"));

//     // Cleanup
//     temp.close().unwrap();
// }
