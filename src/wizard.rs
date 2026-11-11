// SPDX-License-Identifier: Apache-2.0

//! Interactive wizard shown when `termius-backup` is run with no subcommand.
//!
//! Page 1 selects the action (backup / restore / sync settings / add to
//! PATH); page 2 selects the backend (local file / Google Drive). The
//! Google Drive branch runs the login flow when no credentials are stored
//! yet, and simply asks for the master password when already logged in
//! (both handled by the session open). "Sync settings" has two options:
//! "Turn on" runs the Google Drive flow (login when needed, master
//! password, vault, backup password) and starts two-way sync in the
//! background; "Turn off" stops it. "Add to PATH" is the interactive
//! version of `termius-backup install`.

use std::io::IsTerminal;
use std::path::Path;

use crate::error::{Error, Result};
use crate::{backup, crypto, gdrive, paths, prompt, restore, sync};

/// Shared global flags the wizard needs. Mirrors the per-command globals so
/// the wizard honors `--termius-dir`, `--snapshots-dir`, `--password-file`,
/// `--password-env`, `--creds-file`, and `--yes` exactly like the subcommands.
pub struct Flags<'a> {
    pub termius_dir: Option<&'a Path>,
    pub snapshots_dir: Option<&'a Path>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub creds_file: Option<&'a Path>,
    pub service_secrets: Option<&'a Path>,
    pub yes: bool,
    /// Carry/install the Termius keyring `localKey` (inverse of
    /// `--no-carry-key`).
    pub carry_key: bool,
}

/// Run the interactive menu. Requires a TTY on stdin; otherwise returns
/// [`Error::NoSubcommand`] so non-interactive callers pass a subcommand.
pub fn run(g: &Flags) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::NoSubcommand);
    }

    // Page 1: action.
    let action = prompt::choose(
        "What would you like to do?",
        &[
            "Backup".to_string(),
            "Restore".to_string(),
            "Sync settings".to_string(),
            "Add to PATH".to_string(),
        ],
        0,
    )?;

    if action == 2 {
        return sync_settings(g);
    }
    if action == 3 {
        return crate::install::run(g.yes);
    }

    // Page 2: backend.
    let backend = prompt::choose(
        match action {
            0 => "Back up to where?",
            _ => "Restore from where?",
        },
        &["Local file".to_string(), "Google Drive".to_string()],
        0,
    )?;

    match (action, backend) {
        (0, 0) => backup_local(g),
        (0, 1) => backup_gdrive(g),
        (1, 0) => restore_local(g),
        (1, 1) => restore_gdrive(g),
        _ => unreachable!("prompt::choose returns a valid index"),
    }
}

/// The sync page: shows whether sync is on, then offers "Turn on" and
/// "Turn off". Turning on runs the Google Drive flow — login when no
/// credentials are stored yet, then the master password, the vault to
/// sync with (one your other devices already use, or a new one), and its
/// backup password — and starts two-way sync as a background service.
fn sync_settings(g: &Flags) -> Result<()> {
    let was_on = sync::is_on();
    eprintln!("Sync is currently {}.", sync::status_line());
    let choice = prompt::choose(
        "Sync",
        &["Turn on".to_string(), "Turn off".to_string()],
        usize::from(was_on),
    )?;
    if choice == 1 {
        sync::turn_off()?;
        if was_on {
            eprintln!(
                "Sync is off: the background sync service was stopped and removed. \
                 Your data on this machine and in the vault on Google Drive is \
                 untouched."
            );
        } else {
            eprintln!("Sync is already off.");
        }
        return Ok(());
    }

    let creds = paths::resolve_gdrive_creds_path(g.creds_file)?;
    if !creds.exists() {
        gdrive::run_login(&creds)?;
    }
    let vault = sync::turn_on(
        &sync::SyncSetup {
            creds_path: &creds,
            termius_dir: g.termius_dir,
            snapshots_dir: g.snapshots_dir,
            password_file: g.password_file,
            password_env: g.password_env,
            secrets_file: g.service_secrets,
            yes: g.yes,
        },
        None,
    )?;
    eprintln!(
        "Sync is on: this machine syncs with vault '{vault}' in the background \
         ({id}), also after reboots.",
        id = crate::service::service_id(&vault),
    );
    eprintln!(
        "Changes you make here are uploaded within about a minute. Changes from \
         your other devices are applied while Termius is closed on this machine, \
         so they show up the next time you start Termius. To sync another \
         device, turn sync on there and pick vault '{vault}'."
    );
    Ok(())
}

/// Local backup: prompts for the destination file, then password.
fn backup_local(g: &Flags) -> Result<()> {
    let opts = backup::Options {
        termius_dir: g.termius_dir,
        out: None, // prompts for the destination with a suggested default
        password_file: g.password_file,
        password_env: g.password_env,
        yes: g.yes,
        carry_key: g.carry_key,
        kdf: crypto::KdfParams::default(),
    };
    let p = backup::run(opts)?;
    eprintln!("Done: {}", p.display());
    Ok(())
}

/// Google Drive backup: login flow if not logged in, then name + password.
fn backup_gdrive(g: &Flags) -> Result<()> {
    let creds = paths::resolve_gdrive_creds_path(g.creds_file)?;
    if !creds.exists() {
        gdrive::run_login(&creds)?;
    }
    let (vault, file_id) = gdrive::run_backup(gdrive::BackupOptions {
        termius_dir: g.termius_dir,
        name: None, // prompts for the vault name
        password_file: g.password_file,
        password_env: g.password_env,
        creds_path: &creds,
        yes: g.yes,
        keep: 0, // one-shot backup keeps everything by default
        carry_key: g.carry_key,
    })?;
    eprintln!("Done: backup in vault '{vault}' (Drive file {file_id})");
    let setup = sync::SyncSetup {
        creds_path: &creds,
        termius_dir: g.termius_dir,
        snapshots_dir: g.snapshots_dir,
        password_file: g.password_file,
        password_env: g.password_env,
        secrets_file: g.service_secrets,
        yes: g.yes,
    };
    sync::offer_after_backup(&setup, &vault);
    Ok(())
}

/// Local restore: prompts for the input .tsb path, then password.
fn restore_local(g: &Flags) -> Result<()> {
    let file = prompt::ask_string("Path to the .tsb backup file:", None)?;
    let opts = restore::Options {
        backup_file: Path::new(&file),
        termius_dir: g.termius_dir,
        snapshots_dir: g.snapshots_dir,
        password_file: g.password_file,
        password_env: g.password_env,
        yes: g.yes,
        carry_key: g.carry_key,
    };
    let p = restore::run(opts)?;
    eprintln!("Done: restored into {}", p.display());
    Ok(())
}

/// Google Drive restore: login flow if not logged in, then pick + password.
fn restore_gdrive(g: &Flags) -> Result<()> {
    let creds = paths::resolve_gdrive_creds_path(g.creds_file)?;
    if !creds.exists() {
        gdrive::run_login(&creds)?;
    }
    let p = gdrive::run_restore(gdrive::RestoreOptions {
        termius_dir: g.termius_dir,
        snapshots_dir: g.snapshots_dir,
        password_file: g.password_file,
        password_env: g.password_env,
        creds_path: &creds,
        yes: g.yes,
        carry_key: g.carry_key,
    })?;
    eprintln!("Done: restored into {}", p.display());
    Ok(())
}
