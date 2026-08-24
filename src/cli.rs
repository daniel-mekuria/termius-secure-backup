// SPDX-License-Identifier: Apache-2.0

//! Command-line interface definitions (clap v4, derive).

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "termius-backup",
    version,
    about = "Encrypted backup and restore for the local Termius data directory"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Override the Termius data directory (auto-detected by default).
    #[arg(long, global = true)]
    pub termius_dir: Option<PathBuf>,

    /// Override the snapshots directory (auto-detected by default).
    #[arg(long, global = true)]
    pub snapshots_dir: Option<PathBuf>,

    /// Read the password from the first line of this file.
    #[arg(long, global = true)]
    pub password_file: Option<PathBuf>,

    /// Read the password from this environment variable.
    #[arg(long, global = true)]
    pub password_env: Option<String>,

    /// Skip confirmation prompts and the weak-password gate (non-interactive).
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Verbose logging.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Back up the Termius data directory into an encrypted .tsb file.
    Backup(BackupArgs),
    /// Restore the Termius data directory from an encrypted .tsb file.
    Restore(RestoreArgs),
    /// Roll the Termius directory back to a previous snapshot.
    Rollback(RollbackArgs),
    /// Inspect a .tsb file header without a password.
    Info(InfoArgs),
    /// Manage rollback snapshots.
    Snapshots(SnapshotsArgs),
}

impl Default for Command {
    fn default() -> Self {
        Command::Backup(BackupArgs::default())
    }
}

#[derive(Args, Debug, Default)]
pub struct BackupArgs {
    /// Output path for the encrypted backup file.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// Path to the .tsb backup file to restore.
    pub file: PathBuf,
}

#[derive(Args, Debug, Default)]
pub struct RollbackArgs {
    /// Specific snapshot id to roll back to (otherwise prompts interactively).
    #[arg(long)]
    pub snap_id: Option<String>,
}

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// Path to the .tsb file to inspect.
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct SnapshotsArgs {
    #[command(subcommand)]
    pub action: SnapshotsAction,
}

#[derive(Subcommand, Debug)]
pub enum SnapshotsAction {
    /// List tagged rollback snapshots.
    List,
    /// Delete old snapshots, keeping the newest N per source directory.
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Number of newest snapshots to keep per source directory.
    #[arg(long, default_value_t = 10)]
    pub keep: usize,
}
