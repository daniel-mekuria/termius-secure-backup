// SPDX-License-Identifier: Apache-2.0

//! Restore orchestration: confirm, snapshot the live dir, decrypt, restore.

use std::path::{Path, PathBuf};

use crate::archive;
use crate::container;
use crate::error::{Error, Result};
use crate::keyring;
use crate::paths;
use crate::prompt;
use crate::snapshot::{self, Reason};
use crate::util;

/// Options for a restore run.
pub struct Options<'a> {
    pub backup_file: &'a Path,
    pub termius_dir: Option<&'a Path>,
    pub snapshots_dir: Option<&'a Path>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub yes: bool,
    /// Install the archive's carried Termius `localKey` into the OS
    /// keyring (default). Disable to skip — the data still restores,
    /// but hosts/keys only decrypt where that key already exists.
    pub carry_key: bool,
}

/// Run a restore. Returns the path that was restored into.
pub fn run(opts: Options<'_>) -> Result<PathBuf> {
    if !opts.backup_file.is_file() {
        return Err(Error::NotFound(format!(
            "backup file not found: {}",
            opts.backup_file.display()
        )));
    }

    let dest = paths::resolve_termius_dir(opts.termius_dir).or_else(|_| {
        // Restore target may not exist yet (fresh install); allow it.
        match opts.termius_dir {
            Some(p) => Ok(p.to_path_buf()),
            None => paths::default_termius_dir(),
        }
    })?;
    let snaps = paths::resolve_snapshots_dir(opts.snapshots_dir)?;

    // Show what we're about to do and confirm.
    let header = container::read_header(opts.backup_file)?;
    eprintln!("Backup file : {}", opts.backup_file.display());
    eprintln!("Restore into: {}", dest.display());
    eprintln!("{}\n", container::format_info(&header));

    if !opts.yes
        && !prompt::confirm(
            "This will REPLACE the current Termius directory with the \
             contents of this backup. A snapshot of the current directory \
             will be taken first. Proceed?",
        )?
    {
        return Err(Error::Canceled("restore canceled".into()));
    }

    // Take a tagged pre-restore snapshot of whatever is currently on disk.
    let mut snap_taken: Option<snapshot::Manifest> = None;
    if dest.is_dir() {
        let now = util::current_time();
        let trigger_sha = util::sha256_file(opts.backup_file).unwrap_or_default();
        eprintln!("Snapshotting current Termius directory …");
        let m = snapshot::create(
            &snaps,
            &dest,
            Reason::PreRestore,
            Some((opts.backup_file, &trigger_sha)),
            &now,
        )?;
        eprintln!("Created pre-restore snapshot: {}", m.id);
        snap_taken = Some(m);
    } else {
        eprintln!("No existing Termius directory to snapshot; proceeding.");
    }

    // Acquire the password and decrypt. A rejected password re-prompts
    // (a TTY session gets several attempts); the snapshot hint prints
    // once, after the final failure.
    eprintln!("Decrypting …");
    let payload = crate::backup::acquire_and_decrypt(
        opts.password_file,
        opts.password_env,
        /*confirm_reentry*/ false,
        |pw| container::read_and_decrypt(opts.backup_file, pw.as_bytes()),
    )
    .map_err(|e| {
        // Password acquisition errors already describe themselves.
        if !matches!(e, Error::PasswordRejected | Error::WeakPassword { .. }) {
            eprintln!("Decryption failed: {e}");
        }
        if let Some(m) = &snap_taken {
            eprintln!(
                "Your previous data was preserved in snapshot {} — \
                 use `rollback` to restore it.",
                m.id
            );
        }
        e
    })?;

    // Unpack into a temp dir, verify, then swap into place.
    eprintln!("Unpacking …");
    let staging = tempfile::tempdir_in(dest.parent().unwrap_or(Path::new(".")))?;
    let (meta, manifest) = archive::unpack(&payload, staging.path())?;
    eprintln!(
        "Archive metadata: {} entries, {} bytes, created {}",
        meta.entry_count, meta.byte_size, meta.created_at
    );
    if let Err(e) = archive::verify(staging.path(), &meta, &manifest) {
        return Err(Error::Integrity(format!(
            "decrypted archive failed integrity check before restore: {e}"
        )));
    }

    // Install the carried Termius keyring key so the restored data
    // decrypts on this machine. Done before the swap, so a failure
    // aborts with the live directory still untouched.
    install_carried_key(&meta, opts.carry_key)?;

    // Replace the live directory with the staged tree.
    replace_dir(&dest, staging.path())?;
    eprintln!("Restore complete: {}", dest.display());
    Ok(dest)
}

/// Install the carried Termius keyring key, if the archive has one and
/// key carrying is enabled. No-ops (with a note) when the archive has no
/// carried key or carrying is disabled; errors only when a carried key
/// exists, the install was requested, and it failed. `pub(crate)` so the
/// Google Drive restore flow can reuse it.
pub(crate) fn install_carried_key(meta: &crate::archive::ArchiveMeta, carry: bool) -> Result<()> {
    match meta.local_key.as_ref() {
        Some(k) if carry => {
            eprintln!(
                "Installing carried Termius localKey ({}) into the OS keyring …",
                k.describe()
            );
            keyring::install_local_key(&k.key_b64)
                .map(|what| eprintln!("{what}"))
                .map_err(|e| {
                    Error::Other(format!(
                        "the archive carries a Termius localKey, but it could not \
                         be installed into the OS keyring: {e}\n\
                         Aborting before the restore — the current Termius \
                         directory was not modified. Fix keyring access and \
                         retry (or use --no-carry-key to restore the data \
                         without installing the key)."
                    ))
                })
        }
        Some(_) => {
            eprintln!(
                "note: the archive carries a Termius localKey but --no-carry-key \
                 is set, so it was not installed — restored hosts/keys may \
                 appear empty if this machine's Termius uses a different key."
            );
            Ok(())
        }
        None => Ok(()),
    }
}

/// Atomically replace `dest` with the contents of `staging` by renaming.
/// `pub(crate)` so the Google Drive restore flow can reuse it.
pub(crate) fn replace_dir(dest: &Path, staging: &Path) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::Other("restore destination has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    if dest.exists() {
        let backup_name = format!(
            ".{}.old.{}",
            dest.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("termius"),
            util::current_time()
                .format(&time::format_description::well_known::Iso8601::DEFAULT)
                .unwrap_or_default()
                .replace(':', "-")
        );
        let old = parent.join(backup_name);
        std::fs::rename(dest, &old)?;
        if std::fs::rename(staging, dest).is_err() {
            // Roll back the rename on failure.
            let _ = std::fs::rename(&old, dest);
            return Err(Error::Other("failed to move staged tree into place".into()));
        }
        let _ = std::fs::remove_dir_all(&old);
    } else {
        std::fs::rename(staging, dest)?;
    }
    Ok(())
}
