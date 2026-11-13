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
//!
//! Navigation: every page after the first has a "← Back" row (Esc also
//! goes back), and so does the first menu of each flow — going back there
//! (or leaving the flow's first text question empty) returns to the page
//! the flow was started from. Page 1 has an "Exit" row (Esc also exits).

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
    // Every flow below is started from a page of this menu, so its first
    // menu or question can go back to that page.
    prompt::allow_back_out();

    let mut action = 0;
    let mut backend = 0;
    loop {
        // Page 1: action.
        action = match prompt::choose_or_leave(
            "What would you like to do?",
            &[
                "Backup".to_string(),
                "Restore".to_string(),
                "Sync settings".to_string(),
                "Add to PATH".to_string(),
            ],
            action,
            "Exit",
        )? {
            Some(a) => a,
            None => return Ok(()),
        };

        let outcome = match action {
            2 => sync_settings(g),
            3 => crate::install::run(g.yes),
            _ => loop {
                // Page 2: backend.
                backend = match prompt::choose_back(
                    match action {
                        0 => "Back up to where?",
                        _ => "Restore from where?",
                    },
                    &["Local file".to_string(), "Google Drive".to_string()],
                    backend,
                )? {
                    Some(b) => b,
                    None => break Err(Error::Back),
                };
                let flow = match (action, backend) {
                    (0, 0) => backup_local(g),
                    (0, _) => backup_gdrive(g),
                    (_, 0) => restore_local(g),
                    _ => restore_gdrive(g),
                };
                match flow {
                    // Went back from the flow: show page 2 again.
                    Err(Error::Back) => continue,
                    done => break done,
                }
            },
        };
        match outcome {
            // Went back to page 1.
            Err(Error::Back) => continue,
            done => return done,
        }
    }
}

/// The sync page: shows whether sync is on, then offers "Turn on" and
/// "Turn off" (and "← Back" to page 1). Turning on runs the Google Drive
/// flow — login when no credentials are stored yet, then the master
/// password, the vault to sync with (one your other devices already use,
/// or a new one), and its backup password — and starts two-way sync as a
/// background service.
fn sync_settings(g: &Flags) -> Result<()> {
    loop {
        let was_on = sync::is_on();
        eprintln!("Sync is currently {}.", sync::status_line());
        let choice = prompt::choose_back(
            "Sync",
            &["Turn on".to_string(), "Turn off".to_string()],
            usize::from(was_on),
        )?
        .ok_or(Error::Back)?;
        if choice == 1 {
            sync::turn_off()?;
            if was_on {
                eprintln!(
                    "Sync is off: the background sync service was stopped and \
                     removed. Your data on this machine and in the vault on \
                     Google Drive is untouched."
                );
            } else {
                eprintln!("Sync is already off.");
            }
            return Ok(());
        }
        match turn_sync_on(g) {
            // Went back from the Google Drive flow: show this page again.
            Err(Error::Back) => continue,
            done => return done,
        }
    }
}

/// "Turn on" on the sync page.
fn turn_sync_on(g: &Flags) -> Result<()> {
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

/// Local restore: prompts for the input .tsb path (empty goes back), then
/// password.
fn restore_local(g: &Flags) -> Result<()> {
    let file = prompt::ask_string_step("Path to the .tsb backup file:")?;
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
