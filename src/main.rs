// termius-secure-backup — encrypted backup/restore for the local Termius data directory.
// SPDX-License-Identifier: Apache-2.0

#![deny(unsafe_op_in_unsafe_fn)]

mod archive;
mod backup;
mod cli;
mod container;
mod crypto;
mod error;
mod paths;
mod prompt;
mod restore;
mod rollback;
mod snapshot;
mod util;
mod weakpass;

use clap::Parser;
use std::process::ExitCode;

use crate::cli::{Cli, Command, SnapshotsAction};
use crate::error::ExitCode as AppExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    util::init_logging(cli.verbose);
    // Destructure so the per-command args can be moved out while the global
    // flags remain available as owned locals.
    let Cli {
        command,
        termius_dir,
        snapshots_dir,
        password_file,
        password_env,
        yes,
        verbose: _,
    } = cli;
    let globals = Globals {
        termius_dir,
        snapshots_dir,
        password_file,
        password_env,
        yes,
    };
    match run(command.unwrap_or_default(), &globals) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(AppExitCode::from(e) as u8)
        }
    }
}

struct Globals {
    termius_dir: Option<std::path::PathBuf>,
    snapshots_dir: Option<std::path::PathBuf>,
    password_file: Option<std::path::PathBuf>,
    password_env: Option<String>,
    yes: bool,
}

fn run(command: Command, g: &Globals) -> error::Result<()> {
    match command {
        Command::Backup(a) => run_backup(g, a),
        Command::Restore(a) => run_restore(g, a),
        Command::Rollback(a) => run_rollback(g, a),
        Command::Info(a) => run_info(a),
        Command::Snapshots(a) => run_snapshots(g, a.action),
    }
}

fn run_backup(g: &Globals, a: cli::BackupArgs) -> error::Result<()> {
    let opts = backup::Options {
        termius_dir: g.termius_dir.as_deref(),
        out: a.out.as_deref(),
        password_file: g.password_file.as_deref(),
        password_env: g.password_env.as_deref(),
        yes: g.yes,
        kdf: crypto::KdfParams::default(),
    };
    let p = backup::run(opts)?;
    eprintln!("Done: {}", p.display());
    Ok(())
}

fn run_restore(g: &Globals, a: cli::RestoreArgs) -> error::Result<()> {
    let opts = restore::Options {
        backup_file: &a.file,
        termius_dir: g.termius_dir.as_deref(),
        snapshots_dir: g.snapshots_dir.as_deref(),
        password_file: g.password_file.as_deref(),
        password_env: g.password_env.as_deref(),
        yes: g.yes,
    };
    let p = restore::run(opts)?;
    eprintln!("Done: restored into {}", p.display());
    Ok(())
}

fn run_rollback(g: &Globals, a: cli::RollbackArgs) -> error::Result<()> {
    let opts = rollback::Options {
        termius_dir: g.termius_dir.as_deref(),
        snapshots_dir: g.snapshots_dir.as_deref(),
        yes: g.yes,
        snap_id: a.snap_id.clone(),
    };
    let id = rollback::run(opts)?;
    eprintln!("Done: rolled back to {id}");
    Ok(())
}

fn run_info(a: cli::InfoArgs) -> error::Result<()> {
    if !a.file.is_file() {
        return Err(error::Error::NotFound(format!(
            "file not found: {}",
            a.file.display()
        )));
    }
    let h = container::read_header(&a.file)?;
    println!("{}", container::format_info(&h));
    Ok(())
}

fn run_snapshots(g: &Globals, action: SnapshotsAction) -> error::Result<()> {
    let snaps = paths::resolve_snapshots_dir(g.snapshots_dir.as_deref())?;
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
