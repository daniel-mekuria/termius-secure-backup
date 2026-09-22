// termius-secure-backup — encrypted backup/restore for the local Termius data directory.
// SPDX-License-Identifier: Apache-2.0

//! Binary entry point: a thin wrapper over the `termius_secure_backup` library.

use clap::Parser;
use std::process::ExitCode;

use termius_secure_backup::cli::{
    Cli, Command, GdriveAction, Globals, SnapshotsAction, SyncCommand,
};
use termius_secure_backup::error::ExitCode as AppExitCode;
use termius_secure_backup::util;
use termius_secure_backup::{
    backup, container, crypto, gdrive, install, paths, restore, rollback, snapshot, sync, wizard,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    util::init_logging(cli.verbose);
    let globals = Globals::from_cli(cli);
    // Destructure so the per-command arg can be moved out while the shared
    // flags remain borrowable as a group.
    let Globals {
        command,
        termius_dir,
        snapshots_dir,
        password_file,
        password_env,
        creds_file,
        yes,
    } = globals;
    let g = Refs {
        termius_dir,
        snapshots_dir,
        password_file,
        password_env,
        creds_file,
        yes,
    };
    let result = match command {
        Some(Command::Backup(a)) => run_backup(&g, a),
        Some(Command::Restore(a)) => run_restore(&g, a),
        Some(Command::Rollback(a)) => run_rollback(&g, a),
        Some(Command::Info(a)) => run_info(a),
        Some(Command::Snapshots(a)) => run_snapshots(&g, a.action),
        Some(Command::Gdrive(a)) => run_gdrive(&g, a.action),
        Some(Command::Install) => install::run(g.yes),
        None => run_wizard(&g),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(AppExitCode::from(e) as u8)
        }
    }
}

/// Borrowed view of the shared global flags.
struct Refs {
    termius_dir: Option<std::path::PathBuf>,
    snapshots_dir: Option<std::path::PathBuf>,
    password_file: Option<std::path::PathBuf>,
    password_env: Option<String>,
    creds_file: Option<std::path::PathBuf>,
    yes: bool,
}

impl Refs {
    fn termius_dir(&self) -> Option<&std::path::Path> {
        self.termius_dir.as_deref()
    }
    fn snapshots_dir(&self) -> Option<&std::path::Path> {
        self.snapshots_dir.as_deref()
    }
    fn password_file(&self) -> Option<&std::path::Path> {
        self.password_file.as_deref()
    }
    fn password_env(&self) -> Option<&str> {
        self.password_env.as_deref()
    }
    fn creds_file(&self) -> Option<&std::path::Path> {
        self.creds_file.as_deref()
    }
}

/// No subcommand: run the interactive menu (backup/restore × local/gdrive).
fn run_wizard(g: &Refs) -> termius_secure_backup::error::Result<()> {
    wizard::run(&wizard::Flags {
        termius_dir: g.termius_dir(),
        snapshots_dir: g.snapshots_dir(),
        password_file: g.password_file(),
        password_env: g.password_env(),
        creds_file: g.creds_file(),
        yes: g.yes,
    })
}

fn run_backup(
    g: &Refs,
    a: termius_secure_backup::cli::BackupArgs,
) -> termius_secure_backup::error::Result<()> {
    let opts = backup::Options {
        termius_dir: g.termius_dir(),
        out: a.out.as_deref(),
        password_file: g.password_file(),
        password_env: g.password_env(),
        yes: g.yes,
        kdf: crypto::KdfParams::default(),
    };
    let p = backup::run(opts)?;
    eprintln!("Done: {}", p.display());
    Ok(())
}

fn run_restore(
    g: &Refs,
    a: termius_secure_backup::cli::RestoreArgs,
) -> termius_secure_backup::error::Result<()> {
    let opts = restore::Options {
        backup_file: &a.file,
        termius_dir: g.termius_dir(),
        snapshots_dir: g.snapshots_dir(),
        password_file: g.password_file(),
        password_env: g.password_env(),
        yes: g.yes,
    };
    let p = restore::run(opts)?;
    eprintln!("Done: restored into {}", p.display());
    Ok(())
}

fn run_rollback(
    g: &Refs,
    a: termius_secure_backup::cli::RollbackArgs,
) -> termius_secure_backup::error::Result<()> {
    let opts = rollback::Options {
        termius_dir: g.termius_dir(),
        snapshots_dir: g.snapshots_dir(),
        yes: g.yes,
        snap_id: a.snap_id.clone(),
    };
    let id = rollback::run(opts)?;
    eprintln!("Done: rolled back to {id}");
    Ok(())
}

fn run_info(a: termius_secure_backup::cli::InfoArgs) -> termius_secure_backup::error::Result<()> {
    if !a.file.is_file() {
        return Err(termius_secure_backup::error::Error::NotFound(format!(
            "file not found: {}",
            a.file.display()
        )));
    }
    let h = container::read_header(&a.file)?;
    println!("{}", container::format_info(&h));
    Ok(())
}

fn run_snapshots(g: &Refs, action: SnapshotsAction) -> termius_secure_backup::error::Result<()> {
    let snaps = paths::resolve_snapshots_dir(g.snapshots_dir())?;
    match action {
        SnapshotsAction::List => {
            let entries = snapshot::list(&snaps)?;
            if entries.is_empty() {
                println!("No snapshots.");
                return Ok(());
            }
            println!("{:<34} {:<14} {:<10} SOURCE", "ID", "REASON", "ENTRIES");
            for m in entries {
                println!(
                    "{:<34} {:<14} {:<10} {}",
                    m.id, m.reason, m.entry_count, m.source_dir
                );
            }
            Ok(())
        }
        SnapshotsAction::Prune(p) => {
            let deleted = snapshot::prune(&snaps, p.keep)?;
            println!("Deleted {deleted} snapshot(s).");
            Ok(())
        }
    }
}

fn run_gdrive(g: &Refs, action: GdriveAction) -> termius_secure_backup::error::Result<()> {
    let creds = paths::resolve_gdrive_creds_path(g.creds_file())?;
    match action {
        GdriveAction::Login => gdrive::run_login(&creds)?,
        GdriveAction::Logout => gdrive::run_logout(&creds)?,
        GdriveAction::Status => gdrive::run_status(&creds)?,
        GdriveAction::Backup(a) => {
            let (vault, file_id) = gdrive::run_backup(gdrive::BackupOptions {
                termius_dir: g.termius_dir(),
                name: a.name.as_deref(),
                password_file: g.password_file(),
                password_env: g.password_env(),
                creds_path: &creds,
                yes: g.yes,
                keep: a.keep,
            })?;
            eprintln!("Done: backup in vault '{vault}' (Drive file {file_id})");
            sync::offer_after_backup(
                g.termius_dir(),
                g.password_file(),
                g.password_env(),
                &creds,
                g.yes,
                &vault,
            );
        }
        GdriveAction::Restore => {
            let p = gdrive::run_restore(gdrive::RestoreOptions {
                termius_dir: g.termius_dir(),
                snapshots_dir: g.snapshots_dir(),
                password_file: g.password_file(),
                password_env: g.password_env(),
                creds_path: &creds,
                yes: g.yes,
            })?;
            eprintln!("Done: restored into {}", p.display());
        }
        GdriveAction::Sync(a) => match a.command {
            Some(SyncCommand::Off(t)) => {
                sync::sync_off(t.name.as_deref())?;
                match t.name.as_deref() {
                    Some(n) => println!(
                        "Continuous sync turned off for vault '{n}' — I will \
                         stop suggesting it after backups. Re-enable with \
                         'gdrive sync on'."
                    ),
                    None => println!(
                        "Continuous sync turned off for all vaults — I will \
                         stop suggesting it after backups. Re-enable with \
                         'gdrive sync on'."
                    ),
                }
                eprintln!(
                    "Explicit 'gdrive sync' runs (and any systemd timer) are \
                     unaffected; a future sync of a turned-off vault starts \
                     from a fresh baseline."
                );
            }
            Some(SyncCommand::On(t)) => {
                sync::sync_on(t.name.as_deref())?;
                match t.name.as_deref() {
                    Some(n) => {
                        println!("Continuous sync turned back on for vault '{n}'.");
                        if sync::sync_globally_off() {
                            eprintln!(
                                "Note: '{n}' is on, but 'off for all vaults' \
                                 is still set, so every other vault remains \
                                 off."
                            );
                        }
                    }
                    None => {
                        println!("Continuous sync turned back on for all vaults.");
                    }
                }
            }
            None => {
                sync::run_sync(sync::SyncOptions {
                    termius_dir: g.termius_dir(),
                    name: a.name.as_deref(),
                    password_file: g.password_file(),
                    password_env: g.password_env(),
                    creds_path: &creds,
                    yes: g.yes,
                    interval: a.interval,
                    keep: a.keep,
                    once: a.once,
                    last_sig: None,
                    kdf: crypto::KdfParams::default(),
                })?;
            }
        },
    }
    Ok(())
}
