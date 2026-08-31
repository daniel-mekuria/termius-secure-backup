// SPDX-License-Identifier: Apache-2.0

//! Rollback orchestration: pick a tagged snapshot, take a pre-rollback
//! snapshot of the current state, then restore the chosen snapshot.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::paths;
use crate::prompt;
use crate::snapshot::{self, Manifest, Reason};
use crate::util;

/// Options for a rollback run.
pub struct Options<'a> {
    pub termius_dir: Option<&'a Path>,
    pub snapshots_dir: Option<&'a Path>,
    pub yes: bool,
    pub snap_id: Option<String>,
}

/// Run an interactive rollback. Returns the restored snapshot id.
pub fn run(opts: Options<'_>) -> Result<String> {
    let snaps = paths::resolve_snapshots_dir(opts.snapshots_dir)?;
    let entries = snapshot::list(&snaps)?;
    if entries.is_empty() {
        return Err(Error::NotFound(
            "no snapshots available to roll back to".into(),
        ));
    }

    // Pick a snapshot.
    let chosen: Manifest = match &opts.snap_id {
        Some(id) => entries
            .iter()
            .find(|m| &m.id == id)
            .cloned()
            .ok_or_else(|| Error::SnapshotNotFound(id.clone()))?,
        None => {
            let labels: Vec<String> = entries
                .iter()
                .map(|m| format!("{}  ({})", m.id, m.reason))
                .collect();
            let idx = prompt::choose("Select a snapshot to roll back to", &labels, 0)?;
            entries[idx].clone()
        }
    };

    // Determine the target dir from the snapshot's recorded source, unless
    // overridden.
    let target: PathBuf = match opts.termius_dir {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(&chosen.source_dir),
    };

    if !opts.yes
        && !prompt::confirm(&format!(
            "Roll back {} to snapshot {} ({})?\nA snapshot of the current \
             state will be taken first so this is reversible.",
            target.display(),
            chosen.id,
            chosen.reason
        ))?
    {
        return Err(Error::Canceled("rollback canceled".into()));
    }

    // Take a pre-rollback snapshot of the current state.
    if target.is_dir() {
        let now = util::current_time();
        eprintln!("Snapshotting current state …");
        let m = snapshot::create(&snaps, &target, Reason::PreRollback, None, &now)?;
        eprintln!("Created pre-rollback snapshot: {}", m.id);
    }

    // Restore the chosen snapshot over the target.
    eprintln!("Restoring snapshot {} …", chosen.id);
    snapshot::restore(&snaps, &chosen.id, &target)?;
    eprintln!("Rollback complete: {}", target.display());
    Ok(chosen.id)
}
