# cargo-certora-sbf

A Cargo subcommand that integrates [Certora](https://www.certora.com/) formal verification into Rust-based Solana BPF (SBF) smart contract development workflows.

## 📦 Installation

### Requirements ###

1. [rustup](https://rustup.rs/) installer for Rust
2. Rust version >= 1.81 to compile `cargo-certora-sbf` itself
3. (optional) [Solana CLI](https://solana.com/docs/intro/installation) version >= 1.18
3. (optional) Rust version v1.75. This version corresponds to Rust bundled with Solana v1.18. 
4. (optional) Rust version v1.79. This version corresponds to Rust bundled with Solana v2.1

### Instructions ###

Install via `cargo install`:

```sh
cargo install cargo-certora-sbf
```

Ensure you have Rust installed using [rustup](https://rustup.rs/). `cargo-certora-sbf` requires Rust version 1.81 or higher.

## 🚀 Usage

Use from the command line just like any other cargo subcommand:

```sh
cargo certora-sbf [OPTIONS]
```

## 🔧 Options

Run `cargo certora-sbf --help` for the full list of options.

## 🛠 How It Works

`cargo-certora-sbf` automates:
 - Managing Certora Solana Platform Tools (includes a Rust compiler version enhanced for Certora Prover compatibility).
 - Compiling Solana smart contracts into a form suitable for formal verification.

## FAQ
1. How to resolve the error "... cannot be built because it requires rustc 1.79.0 or newer"

   This error typically occurs when you intend to use Solana v1.18, but `cargo` decided to use Solana v2 or above. This usually happens when Rust with version >v1.75 is used to configure the project to create or update `Cargo.lock`. This, in turn, most often happens by `rust-analyzer` in VSCode automatically configuring the project when it is first opened.
   
   To resolve, first undo by restoring or removing `Cargo.lock`. Then, configure using Rust v1.75. For example, simply running

   ```sh
   cargo certora-sbf
   ```
   should work.

   To investigate further, run `check` subcommand manually (but use Rust v1.75!)

   ```sh
   cargo +1.75 check
   ```

2. How to use `cargo-certora-sbf` with projects that require Solana v2 (that require Rust v1.79)

    This requires `platform-tools` version v1.43 or above. Use

    ```sh
    cargo certora-sbf --tools-version v1.43
    ```

3. If you get an error message like below:

    ```
    error: not a directory: '/Users/some_user/.local/share/solana/install/active_release/bin/sdk/sbf/dependencies/platform-tools-certora/rust/bin'
    [ERROR] execution of "rustup" terminated with exit status: 1
    ```

    try reinstalling via `cargo certora-sbf --no-build --force-tools-install`.
4. Is it possible to install platform tools without building a rust project.

   Yes. Use the following command line flags:
   ```sh
   cargo certora-sbf --no-build --force-tools-install
   ```
5. Something is not working, how to get more information on what is going on?
    
    Enable extra verbosity by using `-vv` flag.
    
## 📄 License

Apache 2.0. See LICENSE for details.

## 🙌 Contributions

Issues, pull requests, and feedback are welcome!

⸻

Made with ❤️ by Arie Gurfinkel for Certora
