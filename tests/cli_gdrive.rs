// SPDX-License-Identifier: Apache-2.0

//! CLI surface tests for the `gdrive` subcommand (offline: no Google).
//! Every test points `--creds-file` at a temp path so a developer's real
//! credential store can never be touched.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("termius-backup").expect("binary present")
}

fn creds_in(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    tmp.path().join("gdrive-creds.tsb")
}

#[test]
fn gdrive_help_lists_subcommands() {
    bin()
        .args(["gdrive", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("login"))
        .stdout(predicate::str::contains("logout"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("backup"))
        .stdout(predicate::str::contains("restore"))
        .stdout(predicate::str::contains("sync"));
}

#[test]
fn gdrive_sync_help_lists_flags() {
    bin()
        .args(["gdrive", "sync", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--name"))
        .stdout(predicate::str::contains("--interval"))
        .stdout(predicate::str::contains("--keep"))
        .stdout(predicate::str::contains("--once"));
}

#[test]
fn gdrive_backup_help_lists_keep_flag() {
    bin()
        .args(["gdrive", "backup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--keep"));
}

#[test]
fn gdrive_sync_without_login_fails_with_login_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir_all(&termius).unwrap();
    fs::write(termius.join("f.txt"), b"data").unwrap();
    bin()
        .args([
            "gdrive",
            "sync",
            "--name",
            "test",
            "--termius-dir",
            &termius.display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn main_help_mentions_gdrive() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("gdrive"));
}

#[test]
fn gdrive_status_without_creds_not_logged_in() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "status",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_backup_without_login_fails_with_login_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir_all(&termius).unwrap();
    fs::write(termius.join("f.txt"), b"data").unwrap();
    let pwfile = tmp.path().join("pw.txt");
    fs::write(&pwfile, b"strong-password-123\n").unwrap();
    bin()
        .args([
            "gdrive",
            "backup",
            "--name",
            "test",
            "--termius-dir",
            &termius.display().to_string(),
            "--password-file",
            &pwfile.display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_restore_without_login_fails_with_login_hint() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "restore",
            "--termius-dir",
            &tmp.path().join("termius").display().to_string(),
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .code(3) // ExitCode::Auth
        .stderr(predicate::str::contains("not logged in"));
}

#[test]
fn gdrive_login_without_env_uses_baked_in_client() {
    // No TSBAK_GDRIVE_CLIENT_ID in the environment -> the baked-in
    // default client id is used, so login gets past client resolution
    // to the email prompt, which fails cleanly in a non-interactive
    // session (no TTY). No network is touched before that point.
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "login",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
        ])
        .env_remove("TSBAK_GDRIVE_CLIENT_ID")
        .env_remove("TSBAK_GDRIVE_CLIENT_SECRET")
        .assert()
        .failure()
        .code(5) // ExitCode::Canceled
        .stderr(predicate::str::contains("non-interactive"));
}

#[test]
fn gdrive_logout_without_creds_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "gdrive",
            "logout",
            "--creds-file",
            &creds_in(&tmp).display().to_string(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Not logged in"));
}
