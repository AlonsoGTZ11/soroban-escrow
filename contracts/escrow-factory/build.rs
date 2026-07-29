//! `EscrowFactory` cross-calls the deployed `EscrowInstance` contract via
//! `soroban_sdk::contractimport!`, which needs the instance's compiled WASM
//! present on disk *before* this crate's `src/lib.rs` is compiled. This
//! script builds it, using a target directory separate from the workspace's
//! so it doesn't contend with the outer `cargo` invocation's target-dir lock.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // contracts/escrow-factory -> contracts -> workspace root
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("failed to locate workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf();

    let instance_manifest = workspace_root
        .join("contracts")
        .join("escrow-instance")
        .join("Cargo.toml");
    let instance_src = workspace_root
        .join("contracts")
        .join("escrow-instance")
        .join("src");
    let instance_target_dir = workspace_root.join("target").join("escrow-instance-wasm");

    println!("cargo:rerun-if-changed={}", instance_src.display());
    println!("cargo:rerun-if-changed={}", instance_manifest.display());

    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .args([
            "build",
            "--manifest-path",
            instance_manifest.to_str().unwrap(),
            "--target",
            "wasm32v1-none",
            "--release",
            "--target-dir",
            instance_target_dir.to_str().unwrap(),
        ])
        .status()
        .expect("failed to invoke cargo to build escrow-instance wasm");

    if !status.success() {
        panic!("building escrow-instance wasm failed");
    }
}
