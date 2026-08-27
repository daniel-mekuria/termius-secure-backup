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

    /// Override the stored Google Drive credential path (auto-detected by default).
    #[arg(long, global = true)]
    pub creds_file: Option<PathBuf>,

    /// Skip confirmation prompts and the weak-password gate (non-interactive).
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,

    /// Verbose logging.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

/// Owned global flags extracted from a parsed [`Cli`], plus the selected
/// subcommand (if any). `command: None` means the tool was run bare, which
/// triggers the interactive wizard on a TTY.
pub struct Globals {
    pub command: Option<Command>,
    pub termius_dir: Option<PathBuf>,
    pub snapshots_dir: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub password_env: Option<String>,
    pub creds_file: Option<PathBuf>,
    pub yes: bool,
}

impl Globals {
    /// Consume a parsed [`Cli`] and split it into globals + subcommand.
    pub fn from_cli(cli: Cli) -> Self {
        Globals {
            command: cli.command,
            termius_dir: cli.termius_dir,
            snapshots_dir: cli.snapshots_dir,
            password_file: cli.password_file,
            password_env: cli.password_env,
            creds_file: cli.creds_file,
            yes: cli.yes,
        }
    }
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
    /// Back up and restore over Google Drive.
    Gdrive(GdriveArgs),
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

#[derive(Args, Debug)]
pub struct GdriveArgs {
    #[command(subcommand)]
    pub action: GdriveAction,
}

#[derive(Subcommand, Debug)]
pub enum GdriveAction {
    /// Log in to Google Drive (OAuth device flow) and store encrypted credentials.
    Login,
    /// Remove stored Google Drive credentials.
    Logout,
    /// Show the linked Google Drive account.
    Status,
    /// Back up the Termius data directory to a vault on Google Drive.
    Backup(GdriveBackupArgs),
    /// Restore the Termius data directory from a backup on Google Drive.
    Restore,
}

#[derive(Args, Debug, Default)]
pub struct GdriveBackupArgs {
    /// Name for the backup (a `<name>.tsbak-vault` folder is created on Drive).
    #[arg(long)]
    pub name: Option<String>,
}
