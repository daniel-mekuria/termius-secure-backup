// SPDX-License-Identifier: Apache-2.0

//! Interactive wizard shown when `termius-backup` is run with no subcommand.
//!
//! Page 1 selects the action (backup / restore / sync settings / add to
//! PATH); page 2 selects the backend (local file / Google Drive). The
//! Google Drive branch runs the login flow when no credentials are stored
//! yet, and simply asks for the master password when already logged in
//! (both handled by the session open). "Sync settings" turns the
//! continuous sync on or off — per vault or for all vaults; turning a
//! vault on installs its background service (prompting for the two
//! passwords once, when they were never stored), turning it off removes
//! the service. "Add to PATH" is the interactive version of
//! `termius-backup install`.

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

/// Interactive toggle for continuous sync: shows the current state and
/// lets the user turn it off or back on, per vault or for all vaults.
/// Turning a vault on (or all vaults, per vault) installs its background
/// service; the two passwords are prompted once, when no secrets file
/// exists yet, and reused afterwards.
fn sync_settings(g: &Flags) -> Result<()> {
    let state = sync::sync_status();
    eprintln!("Continuous sync is currently {state}.");

    let choice = prompt::choose(
        "What would you like to change?",
        &[
            "Turn it off for all vaults".to_string(),
            "Turn it off for one vault".to_string(),
            "Turn it back on for all vaults".to_string(),
            "Turn it back on for one vault".to_string(),
        ],
        0,
    )?;
    let creds = paths::resolve_gdrive_creds_path(g.creds_file)?;
    let ctx = sync::ServiceCtx {
        creds_path: &creds,
        yes: g.yes,
        secrets_file: g.service_secrets,
    };
    match choice {
        0 => {
            sync::sync_off(None)?;
            eprintln!(
                "Continuous sync is now off for all vaults — every \
                 background sync service was stopped and removed."
            );
        }
        1 => {
            let name = prompt::ask_string("Vault name:", None)?;
            sync::sync_off(Some(&name))?;
            eprintln!(
                "Continuous sync is now off for vault '{name}' — its \
                 background service (if any) was stopped and removed."
            );
        }
        2 => {
            sync::sync_on(None, &ctx)?;
            eprintln!(
                "Continuous sync is now on for all vaults. (The background \
                 service is per-vault: use 'gdrive sync on --name N' — or \
                 this menu — to start one.)"
            );
        }
        _ => {
            let name = prompt::ask_string("Vault name:", None)?;
            let remaining = sync::sync_on(Some(&name), &ctx)?;
            if remaining.iter().any(|x| x == "*") {
                eprintln!(
                    "Vault '{name}' is now on; all other vaults remain off \
                     ('off for all vaults' is still set)."
                );
            }
            eprintln!(
                "Continuous sync for vault '{name}' is now running in the \
                 background ({id}) — it survives reboots.",
                id = crate::service::service_id(&name),
            );
        }
    }
    eprintln!("Done.");
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
    })?;
    eprintln!("Done: backup in vault '{vault}' (Drive file {file_id})");
    let ctx = sync::ServiceCtx {
        creds_path: &creds,
        yes: g.yes,
        secrets_file: g.service_secrets,
    };
    sync::offer_after_backup(g.termius_dir, &ctx, &vault);
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
    })?;
    eprintln!("Done: restored into {}", p.display());
    Ok(())
}
