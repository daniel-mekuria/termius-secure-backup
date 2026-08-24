// SPDX-License-Identifier: Apache-2.0

//! End-to-end CLI tests: backup → restore → rollback journey.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("termius-backup").expect("binary present")
}

/// Write a fake "Termius" data tree.
fn make_termius(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("sub/deeper")).unwrap();
    fs::write(dir.join("root.txt"), b"root-contents").unwrap();
    fs::write(dir.join("sub/deeper/unicode-名前.txt"), "名前".as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join("root.txt"), fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink("root.txt", dir.join("link")).unwrap();
    }
}

/// A strong password used across tests.
const PW: &str = "correct-horse-battery-9";

fn pw_file(tmp: &std::path::Path) -> PathBuf {
    let p = tmp.join("pw.txt");
    fs::write(&p, PW).unwrap();
    p
}

#[test]
fn backup_writes_tsb_with_magic() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    make_termius(&termius);
    let out = tmp.path().join("b.tsb");
    let pw = pw_file(tmp.path());

    bin()
        .args([
            "backup",
            "--termius-dir",
            &termius.display().to_string(),
            "--out",
            &out.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    assert!(out.is_file(), "backup file was written");
    let bytes = fs::read(&out).unwrap();
    assert_eq!(&bytes[..6], b"TSBAK\x01", "magic header present");
}

#[test]
fn info_reads_header_without_password() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    make_termius(&termius);
    let out = tmp.path().join("b.tsb");
    let pw = pw_file(tmp.path());

    bin()
        .args([
            "backup",
            "--termius-dir",
            &termius.display().to_string(),
            "--out",
            &out.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    bin()
        .args(["info", &out.display().to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Argon2id"))
        .stdout(predicate::str::contains("XChaCha20-Poly1305"));
}

#[test]
fn restore_round_trips_contents() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    make_termius(&termius);
    let out = tmp.path().join("b.tsb");
    let pw = pw_file(tmp.path());
    let snaps = tmp.path().join("snapshots");

    // Back up.
    bin()
        .args([
            "backup",
            "--termius-dir",
            &termius.display().to_string(),
            "--out",
            &out.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    // Mutate the live dir.
    fs::write(termius.join("root.txt"), b"CHANGED").unwrap();
    fs::remove_file(termius.join("link")).unwrap_or(());

    // Restore.
    bin()
        .args([
            "restore",
            &out.display().to_string(),
            "--termius-dir",
            &termius.display().to_string(),
            "--snapshots-dir",
            &snaps.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    // Contents match the backup.
    assert_eq!(
        fs::read_to_string(termius.join("root.txt")).unwrap(),
        "root-contents"
    );
    assert_eq!(
        fs::read_to_string(termius.join("sub/deeper/unicode-名前.txt")).unwrap(),
        "名前"
    );
}

#[test]
fn restore_creates_pre_restore_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    make_termius(&termius);
    let out = tmp.path().join("b.tsb");
    let pw = pw_file(tmp.path());
    let snaps = tmp.path().join("snapshots");

    bin()
        .args([
            "backup",
            "--termius-dir",
            &termius.display().to_string(),
            "--out",
            &out.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    fs::write(termius.join("root.txt"), b"PRE-RESTORE-STATE").unwrap();

    bin()
        .args([
            "restore",
            &out.display().to_string(),
            "--termius-dir",
            &termius.display().to_string(),
            "--snapshots-dir",
            &snaps.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    // A pre-restore snapshot must exist with a manifest tagged pre-restore.
    let mut found = false;
    for entry in fs::read_dir(&snaps).unwrap() {
        let entry = entry.unwrap();
        let mp = entry.path().join("manifest.json");
        if mp.is_file() {
            let body = fs::read_to_string(&mp).unwrap();
            if body.contains("\"reason\": \"pre-restore\"") {
                found = true;
                break;
            }
        }
    }
    assert!(found, "a pre-restore snapshot was created");
}

#[test]
fn restore_wrong_password_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    make_termius(&termius);
    let out = tmp.path().join("b.tsb");
    let pw = tmp.path().join("pw.txt");
    fs::write(&pw, PW).unwrap();
    let wrong = tmp.path().join("wrong.txt");
    fs::write(&wrong, "totally-different-pw-99").unwrap();
    let snaps = tmp.path().join("snapshots");

    bin()
        .args([
            "backup",
            "--termius-dir",
            &termius.display().to_string(),
            "--out",
            &out.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    bin()
        .args([
            "restore",
            &out.display().to_string(),
            "--termius-dir",
            &termius.display().to_string(),
            "--snapshots-dir",
            &snaps.display().to_string(),
            "--password-file",
            &wrong.display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("password"));
}

#[test]
fn rollback_reverts_to_pre_restore_state() {
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    make_termius(&termius);
    let out = tmp.path().join("b.tsb");
    let pw = pw_file(tmp.path());
    let snaps = tmp.path().join("snapshots");

    // Backup the original.
    bin()
        .args([
            "backup",
            "--termius-dir",
            &termius.display().to_string(),
            "--out",
            &out.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    // Restore (creates a pre-restore snapshot of the live state).
    fs::write(termius.join("root.txt"), b"INTERMEDIATE").unwrap();
    bin()
        .args([
            "restore",
            &out.display().to_string(),
            "--termius-dir",
            &termius.display().to_string(),
            "--snapshots-dir",
            &snaps.display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    // Now there should be a pre-restore snapshot. List snapshots via CLI.
    let list = bin()
        .args([
            "snapshots",
            "list",
            "--snapshots-dir",
            &snaps.display().to_string(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&list);
    // Find the pre-restore snapshot id (first column).
    let snap_id = stdout
        .lines()
        .find(|l| l.contains("pre-restore"))
        .and_then(|l| l.split_whitespace().next())
        .expect("a pre-restore snapshot is listed");

    // Roll back to it.
    bin()
        .args([
            "rollback",
            "--snap-id",
            snap_id,
            "--termius-dir",
            &termius.display().to_string(),
            "--snapshots-dir",
            &snaps.display().to_string(),
            "--yes",
        ])
        .assert()
        .success();

    // The live dir should now reflect the pre-restore (intermediate) state.
    assert_eq!(
        fs::read_to_string(termius.join("root.txt")).unwrap(),
        "INTERMEDIATE"
    );
}

#[test]
fn backup_refuses_missing_termius_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus = tmp.path().join("does-not-exist");
    let pw = pw_file(tmp.path());
    bin()
        .args([
            "backup",
            "--termius-dir",
            &bogus.display().to_string(),
            "--out",
            &tmp.path().join("x.tsb").display().to_string(),
            "--password-file",
            &pw.display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn info_on_non_tsb_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let notsb = tmp.path().join("random.bin");
    fs::write(&notsb, b"not a tsb file at all").unwrap();
    bin()
        .args(["info", &notsb.display().to_string()])
        .assert()
        .failure();
}
