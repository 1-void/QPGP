use encrypto_core::{Backend, PqcPolicy};
use encrypto_pgp::NativeBackend;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn pqc_available() -> bool {
    NativeBackend::new(PqcPolicy::Required).supports_pqc()
}

fn temp_home() -> PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    dir.push(format!("encrypto-cli-test-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_cli(args: &[&str], home: &PathBuf, stdin: Option<&[u8]>) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_encrypto-cli");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("ENCRYPTO_HOME", home)
        .env("RUST_BACKTRACE", "0")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn encrypto-cli");
    if let Some(input) = stdin {
        let mut handle = child.stdin.take().expect("stdin handle");
        handle.write_all(input).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait output");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

#[test]
fn verify_requires_signer_flag() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(&["verify", "sig", "msg"], &home, None);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("verify requires --signer"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn verify_rejects_invalid_signer_format() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["verify", "--signer", "deadbeef", "sig", "msg"],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("fingerprint must be 40 or 64 hex characters"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn encrypt_requires_full_fingerprint() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(&["encrypt", "-r", "short"], &home, Some(b"hi"));
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("full fingerprint required"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn list_keys_rejects_relative_home() {
    if !pqc_available() {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_encrypto-cli");
    let output = Command::new(bin)
        .args(["list-keys"])
        .env("ENCRYPTO_HOME", "relative-home")
        .output()
        .expect("run list-keys");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ENCRYPTO_HOME must be an absolute path"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn keygen_defaults_to_high() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["keygen", "Default <default@example.com>", "--no-passphrase"],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    assert!(
        stdout.contains("MLDSA87_Ed448"),
        "expected high-level algorithm in list-keys output: {stdout}"
    );
}
