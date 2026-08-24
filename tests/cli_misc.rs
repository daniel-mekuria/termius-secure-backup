// SPDX-License-Identifier: Apache-2.0

//! CLI surface tests: help, version, snapshots management, empty states.

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

fn bin() -> Command {
    Command::cargo_bin("termius-backup").expect("binary present")
}

#[test]
fn help_lists_subcommands() {
    bin()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("backup"))
        .stdout(predicate::str::contains("restore"))
        .stdout(predicate::str::contains("rollback"))
        .stdout(predicate::str::contains("snapshots"))
        .stdout(predicate::str::contains("info"));
}

#[test]
fn version_is_printed() {
    bin()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("termius-backup"));
}

#[test]
fn snapshots_list_empty() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "snapshots",
            "list",
            "--snapshots-dir",
            &tmp.path().display().to_string(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("No snapshots"));
}

#[test]
fn snapshots_prune_on_empty_does_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "snapshots",
            "prune",
            "--keep",
            "5",
            "--snapshots-dir",
            &tmp.path().display().to_string(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Deleted 0"));
}

#[test]
fn rollback_with_no_snapshots_errors() {
    let tmp = tempfile::tempdir().unwrap();
    bin()
        .args([
            "rollback",
            "--snapshots-dir",
            &tmp.path().display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no snapshots"));
}

#[test]
fn restore_missing_file_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope.tsb");
    bin()
        .args([
            "restore",
            &missing.display().to_string(),
            "--termius-dir",
            &tmp.path().display().to_string(),
            "--snapshots-dir",
            &tmp.path().join("s").display().to_string(),
            "--yes",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn info_missing_file_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope.tsb");
    bin()
        .args(["info", &missing.display().to_string()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn backup_with_weak_password_file_proceeds() {
    // A non-interactive password file with a weak password still backs up
    // (the weak gate is interactive-only; a warning is printed).
    let tmp = tempfile::tempdir().unwrap();
    let termius = tmp.path().join("termius");
    fs::create_dir(&termius).unwrap();
    fs::write(termius.join("f.txt"), b"data").unwrap();
    let out = tmp.path().join("b.tsb");
    let pw = tmp.path().join("pw.txt");
    fs::write(&pw, "weakpass123").unwrap(); // 10 chars but single class-ish; still proceeds

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
    assert!(out.is_file());
    assert_eq!(&fs::read(&out).unwrap()[..6], b"TSBAK\x01");
}
