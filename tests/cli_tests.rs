use std::process::Command;

const VALID_ACCOUNT: &str = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZN36UWBE5XFGT35JA5UMG";
const VALID_CONTRACT: &str = "CCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGZN36UWBE5XFGT35JA5UMG";
const INVALID_ADDRESS: &str = "GSHORT";

fn get_bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_soroban-toolkit")
}

#[test]
fn test_cli_address_validate_success() {
    let output = Command::new(get_bin_path())
        .args(["address", "validate", VALID_ACCOUNT])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Address is valid"));
    assert!(stdout.contains(VALID_ACCOUNT));
}

#[test]
fn test_cli_address_validate_invalid() {
    let output = Command::new(get_bin_path())
        .args(["address", "validate", INVALID_ADDRESS])
        .output()
        .expect("failed to execute process");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Error"));
    assert!(stderr.contains("Address has invalid length"));
}

#[test]
fn test_cli_address_mask_success() {
    let output = Command::new(get_bin_path())
        .args(["address", "mask", VALID_ACCOUNT])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), "GCEZ...5UMG");
}

#[test]
fn test_cli_address_mask_invalid() {
    let output = Command::new(get_bin_path())
        .args(["address", "mask", INVALID_ADDRESS])
        .output()
        .expect("failed to execute process");

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("Error"));
}

#[test]
fn test_cli_address_detect_account() {
    let output = Command::new(get_bin_path())
        .args(["address", "detect-type", VALID_ACCOUNT])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), "Account");
}

#[test]
fn test_cli_address_detect_contract() {
    let output = Command::new(get_bin_path())
        .args(["address", "detect-type", VALID_CONTRACT])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), "Contract");
}

#[test]
fn test_cli_address_detect_invalid() {
    let output = Command::new(get_bin_path())
        .args(["address", "detect-type", INVALID_ADDRESS])
        .output()
        .expect("failed to execute process");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim(), "Invalid");
}