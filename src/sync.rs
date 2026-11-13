// SPDX-License-Identifier: Apache-2.0

//! Two-way sync of Termius data between devices through a Google Drive
//! vault — the do-it-yourself equivalent of Termius's own cloud sync.
//!
//! Every machine that turns sync on for the same vault runs the same loop
//! (as a background service, see [`crate::service`]):
//!
//! - **Push.** When this machine's Termius data changes and the change has
//!   settled, an encrypted snapshot of the synced data
//!   ([`termius_data::SYNC_DIR`]) is uploaded to the vault. Changes are
//!   detected on the *logical* contents of the user-data databases (see
//!   [`termius_data::fingerprint`]), so LevelDB's file churn and Termius's
//!   own background writes never count as edits.
//! - **Pull.** When the vault's newest snapshot is one this machine has not
//!   seen (another device uploaded it), it is downloaded, decrypted, and
//!   verified, and swapped in as soon as Termius is closed on this machine
//!   — Termius caches its data while it runs, so it shows the new data on
//!   its next start.
//!
//! Each machine remembers the vault snapshot its data last matched (its
//! *head*) and the fingerprint of its data at that point
//! ([`VaultSync`]). Whole-state sync cannot merge edits made on two
//! devices at once, so when both changed since their last sync, the
//! vault's newer snapshot wins — the first device to upload wins — and
//! this machine's own changes are kept in a `pre-sync` rollback snapshot
//! (`termius-backup rollback`) instead of being lost.
//!
//! Upload policy ([`sync_tick`], a pure decision function):
//! - the data must differ from what was last synced (else nothing to do);
//! - it must be *stable* — unchanged for at least `debounce` — so a
//!   half-finished edit is never captured;
//! - at most one upload per `interval`;
//! - safety net: data that never settles is uploaded after `force_after`.
//!
//! `--once` runs a single check (no debounce) and exits, for cron and
//! systemd timers.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::archive;
use crate::backup;
use crate::crypto::KdfParams;
use crate::error::{Error, Result};
use crate::gdrive;
use crate::paths;
use crate::prompt;
use crate::restore;
use crate::service;
use crate::snapshot::{self, Reason};
use crate::termius_data;
use crate::util;

/// What this machine last synced with a vault.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSync {
    /// Drive file id of the vault snapshot this machine's data matched at
    /// its last sync (uploaded or applied here). `None`: never synced — the
    /// vault's newest snapshot counts as new.
    #[serde(default)]
    pub head: Option<String>,
    /// [`termius_data::fingerprint`] of this machine's data right after
    /// that sync. `None`: unknown — the local data counts as changed.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// On-disk sync state (`sync-state.json`, next to the credential store).
/// Holds ids and hashes only — no Termius data, no file names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SyncStateFile {
    /// Per vault: what this machine last synced with it.
    #[serde(default)]
    synced: HashMap<String, VaultSync>,
    /// The vault this machine syncs with (a machine syncs with one vault
    /// at a time: they would all write the same Termius data).
    #[serde(default)]
    active: Option<String>,
    /// Vault names whose post-backup sync offer has been turned off with
    /// `gdrive sync off`; [`SYNC_OFF_ALL`] means "all vaults".
    #[serde(default)]
    sync_off: Vec<String>,
    /// Vault names explicitly turned back on while a global
    /// [`SYNC_OFF_ALL`] off is in effect — they are on even though
    /// everything else is off.
    #[serde(default)]
    sync_on: Vec<String>,
    /// The Termius data directory the last sync run used, so later runs
    /// (the background service, cron `--once`) don't need `--termius-dir`.
    #[serde(default)]
    termius_dir: Option<String>,
}

/// Sentinel stored in `sync_off` for a global (all-vaults) off.
const SYNC_OFF_ALL: &str = "*";

impl SyncStateFile {
    /// Whether the post-backup offer is off for `vault`: either it was
    /// turned off individually, or a global off is set and `vault` has no
    /// per-vault exception.
    fn is_off(&self, vault: &str) -> bool {
        let individual = self.sync_off.iter().any(|x| x == vault);
        let global = self.sync_off.iter().any(|x| x == SYNC_OFF_ALL)
            && !self.sync_on.iter().any(|x| x == vault);
        individual || global
    }
}

fn load_state_file(path: &Path) -> SyncStateFile {
    match std::fs::read_to_string(path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
            eprintln!(
                "warning: sync state {} is unreadable ({e}) — treating it as empty.",
                path.display()
            );
            SyncStateFile::default()
        }),
        // Missing file = first run on this machine.
        Err(_) => SyncStateFile::default(),
    }
}

/// Persist the whole state file (atomic write).
fn save_state_file(path: &Path, file: &SyncStateFile) -> Result<()> {
    let json = serde_json::to_vec_pretty(file).expect("SyncStateFile serializes by construction");
    util::atomic_write(path, &json)
}

/// Load, modify, and save the state file.
fn update_state_file(path: &Path, f: impl FnOnce(&mut SyncStateFile)) -> Result<()> {
    let mut file = load_state_file(path);
    f(&mut file);
    save_state_file(path, &file)
}

/// Record that this machine's data (with fingerprint `fingerprint`) now
/// matches the vault snapshot `head` — called after `gdrive backup`, so a
/// sync of that vault does not re-upload or re-apply the same data.
/// Best-effort: a state-write failure never fails a successful backup.
pub fn record_synced(vault: &str, head: &str, fingerprint: String) {
    if let Ok(p) = paths::sync_state_path() {
        let synced = VaultSync {
            head: Some(head.to_string()),
            fingerprint: Some(fingerprint),
        };
        if let Err(e) = update_state_file(&p, |f| {
            f.synced.insert(vault.to_string(), synced);
        }) {
            eprintln!("warning: could not write sync state {}: {e}", p.display());
        }
    }
}

/// Turn the post-backup offer off (or back on) for `vault` — or for every
/// vault when `vault` is `None` — in the state file at `path`. Turning a
/// vault off also forgets what this machine last synced with it, so a
/// later sync starts fresh. Returns the updated list of off markers.
fn toggle_sync_off(path: &Path, vault: Option<&str>, off: bool) -> Result<Vec<String>> {
    let mut file = load_state_file(path);
    if off {
        match vault {
            Some(v) => {
                if !file.sync_off.iter().any(|x| x == v) {
                    file.sync_off.push(v.to_string());
                }
                // An explicit off overrides any per-vault exception.
                file.sync_on.retain(|x| x != v);
                file.synced.remove(v);
                if file.active.as_deref() == Some(v) {
                    file.active = None;
                }
            }
            None => {
                if !file.sync_off.iter().any(|x| x == SYNC_OFF_ALL) {
                    file.sync_off.push(SYNC_OFF_ALL.to_string());
                }
                // Exceptions are meaningless when everything is off.
                file.sync_on.clear();
                file.synced.clear();
                file.active = None;
            }
        }
    } else {
        match vault {
            Some(v) => {
                file.sync_off.retain(|x| x != v);
                // With a global off in effect, record this vault as an
                // exception so it is actually on.
                if file.sync_off.iter().any(|x| x == SYNC_OFF_ALL)
                    && !file.sync_on.iter().any(|x| x == v)
                {
                    file.sync_on.push(v.to_string());
                }
            }
            None => {
                file.sync_off.clear();
                file.sync_on.clear();
            }
        }
    }
    save_state_file(path, &file)?;
    Ok(file.sync_off)
}

/// Remember `dir` as the Termius data directory for future sync runs, so
/// the background service and `--once` runs don't need `--termius-dir`.
/// Best-effort: a state-write failure never fails an otherwise-successful
/// run.
pub fn remember_termius_dir(dir: &Path) {
    if let Ok(p) = paths::sync_state_path() {
        if let Err(e) = update_state_file(&p, |f| {
            f.termius_dir = dir.to_str().map(str::to_string);
        }) {
            eprintln!("warning: could not write sync state {}: {e}", p.display());
        }
    }
}

/// The Termius data directory a previous sync run used, if any.
pub fn saved_termius_dir() -> Option<PathBuf> {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p).termius_dir.map(PathBuf::from),
        Err(_) => None,
    }
}

/// Whether the post-backup offer is turned off for `vault` (either
/// globally without an exception, or for that vault specifically).
pub fn sync_is_off(vault: &str) -> bool {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p).is_off(vault),
        Err(_) => false,
    }
}

/// Whether the global (all-vaults) off marker is currently set.
pub fn sync_globally_off() -> bool {
    match paths::sync_state_path() {
        Ok(p) => load_state_file(&p)
            .sync_off
            .iter()
            .any(|x| x == SYNC_OFF_ALL),
        Err(_) => false,
    }
}

/// The vault this machine syncs with, if sync is on.
pub fn active_vault() -> Option<String> {
    paths::sync_state_path()
        .ok()
        .and_then(|p| load_state_file(&p).active)
}

/// Whether sync is on on this machine (a vault is set up, or a sync
/// service is installed).
pub fn is_on() -> bool {
    active_vault().is_some() || !service::installed_vaults().is_empty()
}

/// Human-readable sync state, for the interactive "Sync settings" page.
pub fn status_line() -> String {
    let installed = service::installed_vaults();
    match active_vault() {
        Some(v) if installed.contains(&service::service_slug(&v)) => {
            format!("on — this machine syncs with vault '{v}'")
        }
        Some(v) => format!(
            "set up for vault '{v}', but its background service is not \
             installed — turn sync on again to restart it"
        ),
        None if !installed.is_empty() => {
            format!("on (background sync service for: {})", installed.join(", "))
        }
        None => "off".to_string(),
    }
}

/// What turning sync on needs besides the vault name.
pub struct SyncSetup<'a> {
    /// The Google credential store (the master password unlocks it).
    pub creds_path: &'a Path,
    /// Explicit `--termius-dir` (else the saved/auto-detected one).
    pub termius_dir: Option<&'a Path>,
    /// Explicit `--snapshots-dir` for the pre-sync snapshot.
    pub snapshots_dir: Option<&'a Path>,
    /// Where the backup password comes from instead of a prompt.
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    /// A `--service-secrets` file for the background service: used as is
    /// when it exists, created with the verified passwords otherwise.
    pub secrets_file: Option<&'a Path>,
    /// Non-interactive: skip questions, take the safe defaults.
    pub yes: bool,
}

/// Turn two-way sync on for a vault (`name`, or chosen interactively from
/// the vaults on Drive): unlock Google Drive, check the backup password
/// against the vault's data, decide how this machine starts (when the
/// vault already has data), store the two passwords for the background
/// service, stop syncing any other vault, and install and start the
/// service. Returns the vault name.
pub fn turn_on(setup: &SyncSetup, name: Option<&str>) -> Result<String> {
    let state_path = paths::sync_state_path()?;

    // Unlock the stored Google credentials first, so a wrong master
    // password fails fast.
    let master = gdrive::master_password(setup.creds_path)?;
    let mut session = gdrive::Session::open(setup.creds_path, master.as_bytes())?;

    let (src, _) = resolve_sync_termius_dir(setup.termius_dir)?;
    remember_termius_dir(&src);

    let given = name
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_string);
    // Repeats when the user goes back from the start choice to the vault
    // list.
    let (name, backup_password, synced) = loop {
        let name = match &given {
            Some(n) => n.clone(),
            None => choose_vault(&mut session)?,
        };
        let folder_id = session.ensure_vault(&name)?;
        let newest = session.list_backups(&folder_id)?.into_iter().next();

        // The backup password must be the one the vault's data is
        // encrypted with — every syncing device shares it — so check it
        // right here.
        let backup_password = match &newest {
            Some(b) => {
                eprintln!(
                    "Vault '{name}' already has data — enter its backup password \
                     (the one your other devices use)."
                );
                let tsb = session.download_file(&b.id)?;
                let mut accepted = None;
                backup::acquire_and_decrypt(
                    setup.password_file,
                    setup.password_env,
                    false,
                    |pw| {
                        let mut plain = gdrive::decrypt_tsb(&tsb, pw.as_bytes())?;
                        zeroize(&mut plain);
                        accepted = Some(pw.to_string());
                        Ok(())
                    },
                )?;
                accepted.expect("set by a successful decrypt")
            }
            None => {
                backup::acquire_password(setup.password_file, setup.password_env, true, setup.yes)?
            }
        };

        // How this machine starts.
        let previous = load_state_file(&state_path)
            .synced
            .get(&name)
            .cloned()
            .unwrap_or_default();
        let synced = match &newest {
            // Empty vault: this machine's data goes up first.
            None => VaultSync::default(),
            // Already in step with the vault's newest data (e.g. right
            // after `gdrive backup`, or turning sync on again).
            Some(b) if previous.head.as_deref() == Some(b.id.as_str()) => previous,
            Some(b) => {
                let Some(take_vault) = use_vault_data(&name, b, setup.yes, given.is_none())? else {
                    continue; // back to the vault list
                };
                if take_vault {
                    if src.is_dir() {
                        let snaps = paths::resolve_snapshots_dir(setup.snapshots_dir)?;
                        let m = snapshot::create(
                            &snaps,
                            &src,
                            Reason::PreSync,
                            None,
                            &util::current_time(),
                        )?;
                        eprintln!(
                            "This machine's current Termius data was saved in \
                             rollback snapshot {} ('termius-backup rollback' \
                             restores it).",
                            m.id
                        );
                    }
                    // Nothing synced yet, local data as it is now: the
                    // vault's newest snapshot is applied on the first check.
                    VaultSync {
                        head: None,
                        fingerprint: Some(termius_data::fingerprint(&src)?),
                    }
                } else {
                    // In step with the vault's head, local data unknown: it
                    // is uploaded on the first check and becomes the new
                    // head.
                    VaultSync {
                        head: Some(b.id.clone()),
                        fingerprint: None,
                    }
                }
            }
        };
        break (name, backup_password, synced);
    };
    let mut file = load_state_file(&state_path);

    // The two passwords the unattended service needs.
    let secrets_path = match setup.secrets_file {
        Some(p) => p.to_path_buf(),
        None => paths::service_secrets_path(&name)?,
    };
    if setup.secrets_file.is_none() || !secrets_path.is_file() {
        service::write_secrets(
            &secrets_path,
            &service::ServiceSecrets {
                master_password: master,
                backup_password,
            },
        )?;
    }

    // One vault per machine: stop syncing any other vault.
    let slug = service::service_slug(&name);
    for other in service::installed_vaults() {
        if other != slug {
            let removed = service::remove_service(&other)?;
            drop_secrets(&other, removed);
            eprintln!(
                "Stopped syncing vault '{other}' — a machine syncs with one vault at a time."
            );
        }
    }

    let next = match (&synced.head, &synced.fingerprint) {
        (_, None) => {
            "This machine's Termius data will be uploaded to the vault within about a minute."
        }
        (None, Some(_)) => {
            "This machine switches to the vault's data as soon as Termius is closed here \
             (right away if it is not running)."
        }
        (Some(_), Some(_)) => "This machine's data is already in step with the vault.",
    };

    file.synced.retain(|k, _| k == &name);
    file.synced.insert(name.clone(), synced);
    file.active = Some(name.clone());
    save_state_file(&state_path, &file)?;
    toggle_sync_off(&state_path, Some(&name), false)?;

    service::install_service(&name, &secrets_path)?;
    eprintln!("{next}");
    Ok(name)
}

/// Pick the vault to sync with: one already on Drive (where the other
/// devices' data is), or a new one. An empty new-vault name goes back to
/// the list.
fn choose_vault(session: &mut gdrive::Session) -> Result<String> {
    const NEW_PROMPT: &str = "Name for the new sync vault (a <name>.tsbak-vault folder on Drive):";
    let vaults = session.list_vaults()?;
    if vaults.is_empty() {
        return prompt::ask_string_step(NEW_PROMPT);
    }
    let mut labels: Vec<String> = vaults
        .iter()
        .map(|v| {
            let last = v
                .last_backup
                .map(|t| util::local_timestamp_string(&t))
                .unwrap_or_else(|| "never".into());
            format!(
                "{}  (last saved: {last}, {} snapshot(s))",
                gdrive::vault_base_name(&v.name),
                v.backup_count
            )
        })
        .collect();
    labels.push("Create a new vault".to_string());
    let mut i = 0;
    loop {
        i = prompt::choose_step(
            "Which vault should this machine sync with? (to share data with \
             other devices, pick the vault they sync with)",
            &labels,
            i,
        )?;
        match vaults.get(i) {
            Some(v) => return Ok(gdrive::vault_base_name(&v.name).to_string()),
            None => {
                if let Some(name) = prompt::ask_string_back(NEW_PROMPT)? {
                    return Ok(name);
                }
            }
        }
    }
}

/// When the vault already has data this machine has not synced with:
/// should this machine take the vault's data (`Some(true)`) or upload its
/// own (`Some(false)`)? Non-interactive runs take the vault's data — this
/// machine's data is kept in a rollback snapshot, while uploading would
/// replace the data on every other device.
///
/// `None` means the user went back to the vault list (only offered when
/// `back_to_vaults`, i.e. the vault was picked from it).
fn use_vault_data(
    name: &str,
    newest: &gdrive::RemoteBackup,
    yes: bool,
    back_to_vaults: bool,
) -> Result<Option<bool>> {
    let when = newest
        .created
        .map(|t| util::local_timestamp_string(&t))
        .unwrap_or_else(|| "at an unknown time".into());
    if yes || !std::io::stdin().is_terminal() {
        eprintln!(
            "Vault '{name}' already has data (last saved {when}) — this machine \
             will switch to it."
        );
        return Ok(Some(true));
    }
    let label = format!(
        "Vault '{name}' already has data (last saved {when}). How should \
         this machine start syncing?"
    );
    let options = [
        "Use the vault's data on this machine (recommended when other \
         devices already sync with it — this machine's current data is \
         kept in a rollback snapshot)"
            .to_string(),
        "Upload this machine's data (the vault and every other syncing \
         device switch to it)"
            .to_string(),
    ];
    let i = if back_to_vaults {
        prompt::choose_back(&label, &options, 0)?
    } else {
        Some(prompt::choose_step(&label, &options, 0)?)
    };
    Ok(i.map(|i| i == 0))
}

/// Turn sync off on this machine: stop and remove every background sync
/// service, forget the sync state, and stop the post-backup offer. The
/// vaults and their data on Drive are left alone.
pub fn turn_off() -> Result<()> {
    sync_off(None).map(|_| ())
}

/// Turn sync off for `vault` (or every vault when `None`): stop and
/// remove the vault's background service, forget what this machine last
/// synced with it, and stop suggesting it after backups. Returns the list
/// of off markers now in effect ("*" = all).
pub fn sync_off(vault: Option<&str>) -> Result<Vec<String>> {
    match vault {
        Some(v) => {
            let removed = service::remove_service(v)?;
            drop_secrets(v, removed);
        }
        None => {
            for slug in service::installed_vaults() {
                let removed = service::remove_service(&slug)?;
                drop_secrets(&slug, removed);
            }
        }
    }
    toggle_sync_off(&paths::sync_state_path()?, vault, true)
}

/// `gdrive sync on`: with a vault name, turn two-way sync on for it (see
/// [`turn_on`]); without one, only re-enable the post-backup offer for
/// every vault. Returns the list of off markers still in effect.
pub fn sync_on(vault: Option<&str>, setup: &SyncSetup) -> Result<Vec<String>> {
    match vault {
        Some(v) => {
            turn_on(setup, Some(v))?;
            Ok(load_state_file(&paths::sync_state_path()?).sync_off)
        }
        None => toggle_sync_off(&paths::sync_state_path()?, None, false),
    }
}

/// Remove a vault's default secrets file. Best-effort — the service is
/// already gone, so a leftover file is not worth failing the run. Custom
/// `--service-secrets` files are never touched.
fn drop_secrets(vault: &str, removed: bool) {
    if !removed {
        return;
    }
    if let Ok(p) = paths::service_secrets_path(vault) {
        let _ = std::fs::remove_file(&p);
    }
}

/// Scheduling parameters for the sync loop.
#[derive(Debug, Clone, Copy)]
pub struct SyncPolicy {
    /// How often to check for changes (here and in the vault).
    pub interval: Duration,
    /// How long local data must stay unchanged before an upload (guards
    /// against capturing a half-finished edit).
    pub debounce: Duration,
    /// Force an upload after this much dirtiness even if the data never
    /// settles.
    pub force_after: Duration,
}

impl SyncPolicy {
    /// Derive the policy from a user-supplied interval (seconds). The
    /// interval is clamped to a 5-second minimum so a typo like `--interval
    /// 0` cannot busy-loop; the debounce is at most 10 seconds (and never
    /// longer than the interval itself).
    pub fn from_interval(secs: u64) -> Self {
        let interval = Duration::from_secs(secs.max(5));
        let debounce = Duration::from_secs(10.min(interval.as_secs()));
        SyncPolicy {
            interval,
            debounce,
            force_after: Duration::from_secs(15 * 60),
        }
    }
}

/// Upload bookkeeping carried across checks. Signatures are
/// [`termius_data::fingerprint`]s (an empty string = no data).
#[derive(Debug, Clone)]
pub struct SyncState {
    /// Fingerprint seen on the previous check (drives stability detection).
    pub prev_sig: String,
    /// Fingerprint of the last sync — the clean baseline.
    pub uploaded_sig: String,
    /// When the currently-observed fingerprint was first seen.
    pub stable_since: Option<time::OffsetDateTime>,
    /// When the data first diverged from `uploaded_sig`.
    pub dirty_since: Option<time::OffsetDateTime>,
    /// When the last successful upload happened.
    pub last_upload: Option<time::OffsetDateTime>,
}

impl SyncState {
    /// Start with `sig` as the clean baseline (nothing to upload until the
    /// data changes).
    pub fn with_baseline(sig: String) -> Self {
        SyncState {
            prev_sig: sig.clone(),
            uploaded_sig: sig,
            stable_since: None,
            dirty_since: None,
            last_upload: None,
        }
    }

    /// Record a successful upload of `sig`.
    pub fn mark_uploaded(&mut self, sig: String, now: time::OffsetDateTime) {
        self.uploaded_sig = sig;
        self.last_upload = Some(now);
        self.stable_since = None;
        self.dirty_since = None;
    }
}

/// Decide whether `now` is a good moment to upload. Pure with respect to the
/// world (no I/O, no clocks read): it mutates `state`'s bookkeeping fields
/// and returns true when an upload should happen.
///
/// A backwards clock step (NTP correction) never panics and never uploads
/// early — durations that would be negative are treated as zero.
pub fn sync_tick(
    state: &mut SyncState,
    sig: &str,
    now: time::OffsetDateTime,
    policy: SyncPolicy,
    once: bool,
) -> bool {
    // No data at all is not an upload target: it would replace the vault's
    // data with nothing if the real directory vanished mid-run.
    if sig.is_empty() {
        return false;
    }
    if sig == state.uploaded_sig {
        return false; // clean — nothing to do
    }
    if once {
        return true; // cron mode: changed means upload now
    }

    // Bookkeeping: when did this fingerprint appear, when did dirt start.
    if state.prev_sig != sig {
        state.stable_since = Some(now);
    }
    if state.dirty_since.is_none() {
        state.dirty_since = Some(now);
    }
    state.prev_sig = sig.to_string();

    // At most one upload per interval.
    if let Some(last) = state.last_upload {
        if since(last, now) < policy.interval {
            return false;
        }
    }
    // Debounce: the data must be unchanged long enough to be settled.
    let stable_for = state
        .stable_since
        .map(|t| since(t, now))
        .unwrap_or_default();
    if stable_for >= policy.debounce {
        return true;
    }
    // Safety net: continuously-changing data still gets uploaded.
    let dirty_for = state.dirty_since.map(|t| since(t, now)).unwrap_or_default();
    dirty_for >= policy.force_after
}

/// `now - t` as a std duration, or zero if the clock stepped backwards.
fn since(t: time::OffsetDateTime, now: time::OffsetDateTime) -> Duration {
    if now >= t {
        (now - t).unsigned_abs()
    } else {
        Duration::ZERO
    }
}

/// Choose the sync source directory. An explicit `--termius-dir` always
/// wins; otherwise a path saved by a previous run is reused — but only
/// while it still exists, so a moved/deleted directory falls back to the
/// usual resolution instead of sticking to a stale path. Returns
/// `(directory, from_saved)`, or `None` when the caller should fall back
/// to the auto-detected default (which may prompt on a TTY).
fn pick_sync_termius_dir(
    override_path: Option<&Path>,
    saved: Option<&Path>,
) -> Result<Option<(PathBuf, bool)>> {
    if let Some(p) = override_path {
        return Ok(Some((paths::resolve_termius_dir(Some(p))?, false)));
    }
    if let Some(s) = saved.filter(|p| p.is_dir()) {
        return Ok(Some((s.to_path_buf(), true)));
    }
    Ok(None)
}

/// Resolve the directory the sync works on, honoring the saved path from a
/// previous run when no `--termius-dir` was given.
fn resolve_sync_termius_dir(override_path: Option<&Path>) -> Result<(PathBuf, bool)> {
    match pick_sync_termius_dir(override_path, saved_termius_dir().as_deref())? {
        Some(d) => Ok(d),
        None => Ok((paths::resolve_termius_dir(None)?, false)),
    }
}

/// Options for `gdrive sync`.
#[derive(Debug, Clone)]
pub struct SyncOptions<'a> {
    /// Explicit `--termius-dir`. When absent, the directory saved by a
    /// previous sync run is reused (if it still exists) before the
    /// auto-detected default; whatever is resolved is remembered for the
    /// next run.
    pub termius_dir: Option<&'a Path>,
    /// Where `pre-sync` rollback snapshots go (`--snapshots-dir`).
    pub snapshots_dir: Option<&'a Path>,
    /// Vault name (prompts if absent).
    pub name: Option<&'a str>,
    pub password_file: Option<&'a Path>,
    pub password_env: Option<&'a str>,
    pub creds_path: &'a Path,
    pub yes: bool,
    /// Carry Termius's OS-keyring `localKey` into each upload, and install
    /// the one another device's snapshot carries.
    pub carry_key: bool,
    /// Check interval in seconds (clamped to a 5-second minimum).
    pub interval: u64,
    /// Keep only the newest N snapshots in the vault (0 = keep all).
    pub keep: u32,
    /// Check once (push or pull), then exit.
    pub once: bool,
    /// KDF parameters for the encrypted uploads (the CLI passes the
    /// production defaults; tests use fast ones).
    pub kdf: KdfParams,
}

/// Run the two-way sync loop. Continuous mode never stops on transient
/// failures (network, Drive, a Termius file caught mid-write) — it logs
/// and retries on the next check; only setup failures (no credentials, a
/// wrong master password, an unreadable Termius directory) are fatal. In
/// `once` mode any failure is returned.
pub fn run_sync(opts: SyncOptions<'_>) -> Result<()> {
    let (src, from_saved) = resolve_sync_termius_dir(opts.termius_dir)?;
    // Remember the directory so the next run (the background service, a
    // cron `--once`) doesn't need --termius-dir.
    remember_termius_dir(&src);
    let policy = SyncPolicy::from_interval(opts.interval);

    // Unlock the stored Google credentials first, so a wrong master
    // password fails fast before any vault naming or backup-password work.
    let master = gdrive::master_password(opts.creds_path)?;
    // At login the network may not be up yet: keep retrying the
    // connection in continuous mode instead of exiting.
    let mut session = retry_setup(opts.once, policy.interval, || {
        gdrive::Session::open(opts.creds_path, master.as_bytes())
    })?;

    let name = match opts.name {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => prompt::ask_string(
            "Name of the vault to sync with (a <name>.tsbak-vault folder on Drive):",
            None,
        )?,
    };
    let vault_name = gdrive::vault_folder_name(&name);

    // The backup password is asked once and reused for every upload.
    let password = backup::acquire_password(opts.password_file, opts.password_env, true, opts.yes)?;

    let folder_id = retry_setup(opts.once, policy.interval, || session.ensure_vault(&name))?;
    let running = termius_data::termius_running;
    let mut engine = Engine::new(
        EngineConfig {
            vault: name.clone(),
            folder_id,
            src: src.clone(),
            password,
            kdf: opts.kdf,
            carry_key: opts.carry_key,
            keep: opts.keep,
            snapshots_dir: paths::resolve_snapshots_dir(opts.snapshots_dir)?,
            state_path: paths::sync_state_path()?,
            policy,
        },
        &running,
    );

    if opts.once {
        eprintln!(
            "One-shot sync: checking {} against vault '{vault_name}' …",
            src.display()
        );
    } else {
        eprintln!(
            "Two-way sync: {} <-> vault '{vault_name}', checking every {}s (Ctrl-C to stop).",
            src.display(),
            policy.interval.as_secs()
        );
    }
    if from_saved {
        eprintln!("Using the Termius path saved by a previous sync run — pass --termius-dir to override it.");
    }
    if opts.keep > 0 {
        eprintln!("Keeping the newest {} snapshot(s) in the vault.", opts.keep);
    }

    let mut last_error: Option<String> = None;
    loop {
        // Access tokens live ~1 hour; a sync outlives them.
        if session.token_expired() {
            if let Err(e) = session.refresh_if_expired(opts.creds_path, master.as_bytes()) {
                if opts.once {
                    return Err(e);
                }
                eprintln!("warning: could not refresh Google token: {e} — retrying next check.");
            }
        }

        let result = match engine.step(&mut session, util::current_time(), opts.once) {
            Err(e) if is_auth_error(&e) => {
                eprintln!("Google token appears expired — refreshing and retrying once.");
                session
                    .refresh_if_expired(opts.creds_path, master.as_bytes())
                    .and_then(|_| engine.step(&mut session, util::current_time(), opts.once))
            }
            r => r,
        };
        match result {
            Ok(step) => {
                last_error = None;
                if opts.once && step == Step::Waiting {
                    eprintln!(
                        "Termius is running: the vault's newer data will be applied by \
                         a later sync run, once Termius is closed."
                    );
                }
            }
            Err(e) if opts.once => return Err(e),
            Err(e) => {
                // Report each distinct problem once, not on every check.
                let msg = e.to_string();
                if last_error.as_deref() != Some(msg.as_str()) {
                    eprintln!("warning: {msg} — retrying on the next check.");
                }
                last_error = Some(msg);
            }
        }

        if opts.once {
            break;
        }
        engine.idle(policy.interval);
    }

    eprintln!("One-shot sync complete.");
    Ok(())
}

/// Run a setup step; in continuous mode retry transient (network/Drive)
/// failures every `interval` instead of giving up — the background
/// service starts at login, possibly before the network is up.
fn retry_setup<T>(once: bool, interval: Duration, mut f: impl FnMut() -> Result<T>) -> Result<T> {
    let mut reported = false;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e @ (Error::Gdrive(_) | Error::Io(_))) if !once => {
                if !reported {
                    eprintln!("warning: {e} — retrying every {}s.", interval.as_secs());
                    reported = true;
                }
                thread::sleep(interval);
            }
            Err(e) => return Err(e),
        }
    }
}

/// A Drive error that looks like an expired/invalid access token.
fn is_auth_error(e: &Error) -> bool {
    matches!(e, Error::Gdrive(m) if m.contains("401") || m.contains("Unauthorized"))
}

fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// How often a downloaded update checks whether Termius has been closed.
const APPLY_POLL: Duration = Duration::from_secs(2);

/// Static parameters of one machine's sync with one vault.
pub(crate) struct EngineConfig {
    pub vault: String,
    pub folder_id: String,
    /// The Termius data directory.
    pub src: PathBuf,
    /// The backup password (encrypts uploads, decrypts other devices').
    pub password: String,
    pub kdf: KdfParams,
    pub carry_key: bool,
    pub keep: u32,
    pub snapshots_dir: PathBuf,
    /// The `sync-state.json` to keep [`VaultSync`] in.
    pub state_path: PathBuf,
    pub policy: SyncPolicy,
}

/// What one [`Engine::step`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Nothing to do (or local changes still settling).
    Idle,
    /// This machine's changes were uploaded.
    Pushed,
    /// An upload was abandoned (the data changed while packing, or another
    /// device saved first); the next check retries.
    Skipped,
    /// Newer data from another device is downloaded and waits for Termius
    /// to close.
    Waiting,
    /// Newer data from another device was applied.
    Applied,
}

/// A downloaded, decrypted snapshot from another device, waiting to be
/// applied.
struct Pending {
    id: String,
    name: String,
    /// The decrypted archive (zeroed on drop).
    payload: Vec<u8>,
    /// Whether the pre-sync snapshot for it was already taken (so a retried
    /// apply does not take another one).
    snapshotted: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        zeroize(&mut self.payload);
    }
}

/// One machine's side of the two-way sync with one vault.
pub(crate) struct Engine<'a> {
    cfg: EngineConfig,
    /// Whether Termius is running on this machine (injected for tests).
    running: &'a dyn Fn() -> bool,
    synced: VaultSync,
    tick: SyncState,
    pending: Option<Pending>,
    told_waiting: bool,
}

impl<'a> Engine<'a> {
    pub fn new(cfg: EngineConfig, running: &'a dyn Fn() -> bool) -> Self {
        let synced = load_state_file(&cfg.state_path)
            .synced
            .get(&cfg.vault)
            .cloned()
            .unwrap_or_default();
        let tick = SyncState::with_baseline(synced.fingerprint.clone().unwrap_or_default());
        Engine {
            cfg,
            running,
            synced,
            tick,
            pending: None,
            told_waiting: false,
        }
    }

    /// One check: if the vault has newer data from another device, fetch
    /// it and apply it (once Termius is closed) — it wins over local
    /// changes; otherwise upload local changes once they have settled.
    pub fn step(
        &mut self,
        session: &mut gdrive::Session,
        now: time::OffsetDateTime,
        once: bool,
    ) -> Result<Step> {
        let fp = termius_data::fingerprint(&self.cfg.src)?;
        let newest = session
            .list_backups(&self.cfg.folder_id)?
            .into_iter()
            .next();
        match newest {
            Some(b) if self.synced.head.as_deref() != Some(b.id.as_str()) => {
                if self.pending.as_ref().map(|p| p.id.as_str()) != Some(b.id.as_str()) {
                    eprintln!(
                        "Vault '{}' has newer data from another device ({}) — downloading …",
                        self.cfg.vault, b.name
                    );
                    let tsb = session.download_file(&b.id)?;
                    let payload =
                        gdrive::decrypt_tsb(&tsb, self.cfg.password.as_bytes()).map_err(|e| {
                            Error::Other(format!(
                                "cannot decrypt the vault's newest snapshot {}: {e} (every \
                                 device syncing with a vault must use the same backup password)",
                                b.name
                            ))
                        })?;
                    self.pending = Some(Pending {
                        id: b.id,
                        name: b.name,
                        payload,
                        snapshotted: false,
                    });
                    self.told_waiting = false;
                }
                return self.apply_pending(now);
            }
            // The vault's newest snapshot is ours: anything downloaded
            // earlier is stale.
            _ => self.pending = None,
        }

        self.tick.uploaded_sig = self.synced.fingerprint.clone().unwrap_or_default();
        if !sync_tick(&mut self.tick, &fp, now, self.cfg.policy, once) {
            return Ok(Step::Idle);
        }
        self.push(session, fp, now)
    }

    /// Upload this machine's synced data as the vault's new head.
    fn push(
        &mut self,
        session: &mut gdrive::Session,
        fp: String,
        now: time::OffsetDateTime,
    ) -> Result<Step> {
        eprintln!("Termius data changed on this machine — packing …");
        let carried = backup::carried_key_or_warn(self.cfg.carry_key);
        let mut payload = Vec::new();
        let meta = archive::pack_filtered(
            &self.cfg.src,
            &mut payload,
            &util::local_timestamp_string(&now),
            carried.as_ref(),
            &termius_data::in_sync_set,
        )?;

        // Torn-write guard: if the data changed while we packed, the
        // archive may straddle two states — skip; the next check retries.
        if termius_data::fingerprint(&self.cfg.src)? != fp {
            zeroize(&mut payload);
            eprintln!("Termius data changed while packing — retrying on the next check.");
            return Ok(Step::Skipped);
        }
        // Another device may have saved while we packed: its data wins.
        if let Some(b) = session
            .list_backups(&self.cfg.folder_id)?
            .into_iter()
            .next()
        {
            if self.synced.head.as_deref() != Some(b.id.as_str()) {
                zeroize(&mut payload);
                return Ok(Step::Skipped);
            }
        }

        let tsb = gdrive::encrypt_with(&self.cfg.kdf, self.cfg.password.as_bytes(), &payload)?;
        zeroize(&mut payload);
        let file_name = gdrive::tsb_file_name(&now);
        let id = session.upload_file(&self.cfg.folder_id, &file_name, &tsb)?;
        self.synced = VaultSync {
            head: Some(id),
            fingerprint: Some(fp.clone()),
        };
        self.save();
        self.tick.mark_uploaded(fp, now);

        if self.cfg.keep > 0 {
            let n = gdrive::prune_vault(session, &self.cfg.folder_id, self.cfg.keep)?;
            if n > 0 {
                eprintln!(
                    "Pruned {n} older snapshot(s); kept the newest {}.",
                    self.cfg.keep
                );
            }
        }
        eprintln!(
            "Synced this machine's changes to vault '{}' ({file_name}, {} entries).",
            self.cfg.vault, meta.entry_count
        );
        Ok(Step::Pushed)
    }

    /// Apply the downloaded snapshot if Termius is closed: keep a rollback
    /// snapshot when this machine has unsynced changes, verify, install the
    /// carried keyring key, and swap the data in.
    fn apply_pending(&mut self, now: time::OffsetDateTime) -> Result<Step> {
        let Some(p) = self.pending.as_mut() else {
            return Ok(Step::Idle);
        };
        if (self.running)() {
            if !self.told_waiting {
                eprintln!(
                    "Newer data from another device ({}) is ready and will be applied as \
                     soon as Termius is closed on this machine. Edits made here in the \
                     meantime will be replaced (they are kept in a rollback snapshot).",
                    p.name
                );
                self.told_waiting = true;
            }
            return Ok(Step::Waiting);
        }

        let src = &self.cfg.src;
        let fp = termius_data::fingerprint(src)?;
        if !p.snapshotted
            && !fp.is_empty()
            && self.synced.fingerprint.as_deref() != Some(fp.as_str())
        {
            let m = snapshot::create(&self.cfg.snapshots_dir, src, Reason::PreSync, None, &now)?;
            p.snapshotted = true;
            eprintln!(
                "This machine had changes that were not synced yet, and another device \
                 saved first, so its data wins. Your version was kept in rollback \
                 snapshot {} ('termius-backup rollback' restores it).",
                m.id
            );
        }

        let parent = src.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let staging = tempfile::tempdir_in(parent)?;
        let (meta, manifest) = archive::unpack(&p.payload, staging.path())?;
        archive::verify(staging.path(), &meta, &manifest).map_err(|e| {
            Error::Integrity(format!(
                "the vault's snapshot failed its integrity check: {e}"
            ))
        })?;
        restore::install_carried_key(&meta, self.cfg.carry_key)?;
        // Termius may have started while we unpacked.
        if (self.running)() {
            return Ok(Step::Waiting);
        }
        termius_data::apply(src, staging.path())?;

        let fp = termius_data::fingerprint(src)?;
        let p = self.pending.take().expect("checked above");
        self.synced = VaultSync {
            head: Some(p.id.clone()),
            fingerprint: Some(fp.clone()),
        };
        self.save();
        self.tick = SyncState::with_baseline(fp);
        self.told_waiting = false;
        eprintln!(
            "Applied {} from vault '{}' — Termius shows it the next time it starts.",
            p.name, self.cfg.vault
        );
        Ok(Step::Applied)
    }

    /// Wait for the next check. While a downloaded update is waiting for
    /// Termius to close, keep watching for that and apply it right away.
    pub fn idle(&mut self, interval: Duration) {
        if self.pending.is_none() {
            thread::sleep(interval);
            return;
        }
        let deadline = Instant::now() + interval;
        let mut failed = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            thread::sleep(APPLY_POLL.min(left));
            if failed || self.pending.is_none() || (self.running)() {
                continue;
            }
            if let Err(e) = self.apply_pending(util::current_time()) {
                eprintln!("warning: could not apply the vault's newer data: {e} — retrying on the next check.");
                failed = true;
            }
        }
    }

    /// Persist [`VaultSync`] (best-effort: the worst case after a failed
    /// write is one redundant upload or apply).
    fn save(&self) {
        let synced = self.synced.clone();
        let vault = self.cfg.vault.clone();
        if let Err(e) = update_state_file(&self.cfg.state_path, |f| {
            f.synced.insert(vault, synced);
        }) {
            eprintln!(
                "warning: could not write sync state {}: {e}",
                self.cfg.state_path.display()
            );
        }
    }
}

/// After a successful `gdrive backup`, offer to turn two-way sync on for
/// the vault. The offer is an interactive three-way choice: turn it on
/// now, decline, or decline *and stop being asked about this vault*
/// (which records a `gdrive sync off` for it). The offer no-ops when
/// `--yes` was passed, stdin is not a TTY (CI / pipes), or the offer was
/// turned off with `gdrive sync off`; and it swallows setup errors with a
/// message — the backup itself already succeeded.
pub fn offer_after_backup(setup: &SyncSetup, vault_name: &str) {
    if setup.yes || !std::io::stdin().is_terminal() {
        return;
    }
    let base = gdrive::vault_base_name(vault_name);
    // The user turned the offer off with `gdrive sync off` — honor it.
    if sync_is_off(base) {
        return;
    }
    // Already syncing with this vault — nothing to offer.
    if active_vault().as_deref() == Some(base) {
        return;
    }
    loop {
        // A bare Enter keeps the old behavior (decline, ask again next time).
        let choice = match prompt::choose(
            &format!(
                "Keep this machine in sync with vault '{base}'? (two-way: \
                 changes made here are uploaded, changes from your other \
                 devices are applied; it runs as a background service that \
                 survives reboots)"
            ),
            &[
                "Yes — turn sync on now".to_string(),
                format!("No — and don't ask me again for '{base}'"),
                "No — ask me again next time".to_string(),
            ],
            2,
        ) {
            Ok(c) => c,
            Err(_) => return, // e.g. Ctrl-C at the prompt — the backup is done
        };
        if choice == 1 {
            match sync_off(Some(base)) {
                Ok(_) => eprintln!(
                    "OK — I won't ask about vault '{base}' again \
                     ('gdrive sync on' turns it back on)."
                ),
                Err(e) => eprintln!("could not remember that choice: {e}"),
            }
            return;
        }
        if choice != 0 {
            return;
        }
        match turn_on(setup, Some(base)) {
            Ok(v) => eprintln!(
                "Sync is on for vault '{v}' ({id}). It survives reboots — turn \
                 it off with 'gdrive sync off' or the Sync settings menu.",
                id = service::service_id(&v),
            ),
            // Went back from the sync setup: ask again.
            Err(Error::Back) => continue,
            Err(e) => eprintln!("Sync not turned on: {e}"),
        }
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gdrive::{GdriveClient, MockGdriveClient, RemoteBackup, VaultFolder};
    use crate::termius_data::testutil::{record_key, seed, write_ops};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    fn at(secs: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(secs)
    }

    fn fp(s: &str) -> String {
        s.to_string()
    }

    #[test]
    fn policy_clamps_interval_and_derives_debounce() {
        assert_eq!(
            SyncPolicy::from_interval(0).interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            SyncPolicy::from_interval(3).interval,
            Duration::from_secs(5)
        );
        assert_eq!(
            SyncPolicy::from_interval(60).interval,
            Duration::from_secs(60)
        );
        // Debounce is at most 10 s, and never longer than the interval.
        assert_eq!(
            SyncPolicy::from_interval(60).debounce,
            Duration::from_secs(10)
        );
        assert_eq!(
            SyncPolicy::from_interval(5).debounce,
            Duration::from_secs(5)
        );
        assert_eq!(
            SyncPolicy::from_interval(60).force_after,
            Duration::from_secs(900)
        );
    }

    #[test]
    fn tick_uploads_after_debounce_when_stable() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(String::new());
        let s = fp("a");
        // Change appears at t=0: dirty, but the debounce hasn't elapsed.
        assert!(!sync_tick(&mut state, &s, at(0), policy, false));
        assert!(!sync_tick(&mut state, &s, at(9), policy, false));
        assert!(sync_tick(&mut state, &s, at(10), policy, false));
    }

    #[test]
    fn tick_waits_for_data_to_settle() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(String::new());
        let (a, b) = (fp("a"), fp("b"));
        // Changing every 5 s: the debounce keeps resetting.
        assert!(!sync_tick(&mut state, &a, at(0), policy, false));
        assert!(!sync_tick(&mut state, &b, at(5), policy, false));
        assert!(!sync_tick(&mut state, &a, at(10), policy, false));
        assert!(!sync_tick(&mut state, &b, at(15), policy, false));
        // Still at b at t=20 (5 s of stability — not enough)…
        assert!(!sync_tick(&mut state, &b, at(20), policy, false));
        // …but 10 s of stability at t=25 uploads.
        assert!(sync_tick(&mut state, &b, at(25), policy, false));
    }

    #[test]
    fn tick_respects_interval_between_uploads() {
        let policy = SyncPolicy::from_interval(60);
        let (a, b) = (fp("a"), fp("b"));
        let mut state = SyncState::with_baseline(String::new());
        assert!(!sync_tick(&mut state, &a, at(10), policy, false));
        assert!(sync_tick(&mut state, &a, at(20), policy, false));
        state.mark_uploaded(a, at(20));

        // New change at t=22: the interval (60 s) has not elapsed, so even
        // after the debounce the tick stays quiet until t=80.
        assert!(!sync_tick(&mut state, &b, at(22), policy, false));
        assert!(!sync_tick(&mut state, &b, at(79), policy, false));
        assert!(sync_tick(&mut state, &b, at(80), policy, false));
    }

    #[test]
    fn tick_force_after_uploads_never_settling_data() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(String::new());
        // A different fingerprint every second.
        for t in 0..=905i64 {
            if sync_tick(&mut state, &format!("fp-{t}"), at(t), policy, false) {
                assert!(t >= 900, "fired too early at t={t}");
                return;
            }
        }
        panic!("never uploaded continuously-changing data");
    }

    #[test]
    fn tick_clock_step_back_is_safe() {
        let policy = SyncPolicy::from_interval(60);
        let s = fp("a");
        let mut state = SyncState::with_baseline(String::new());
        sync_tick(&mut state, &s, at(100), policy, false); // stable_since = 100
        assert!(!sync_tick(&mut state, &s, at(50), policy, false));
    }

    #[test]
    fn tick_clean_and_empty_data_are_never_uploaded() {
        let policy = SyncPolicy::from_interval(60);
        let s = fp("a");
        let mut state = SyncState::with_baseline(s.clone());
        for t in 0..300i64 {
            assert!(!sync_tick(&mut state, &s, at(t), policy, false));
            assert!(!sync_tick(&mut state, "", at(t), policy, false));
            assert!(!sync_tick(&mut state, "", at(t), policy, true));
        }
    }

    #[test]
    fn tick_once_uploads_immediately_when_dirty() {
        let policy = SyncPolicy::from_interval(60);
        let mut state = SyncState::with_baseline(fp("clean"));
        assert!(sync_tick(&mut state, "dirty", at(0), policy, true));
        assert!(!sync_tick(&mut state, "clean", at(0), policy, true));
    }

    #[test]
    fn state_file_round_trip_and_legacy_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        let a = VaultSync {
            head: Some("id-1".into()),
            fingerprint: Some("fp-1".into()),
        };
        update_state_file(&path, |f| {
            f.synced.insert("laptop".into(), a.clone());
            f.active = Some("laptop".into());
        })
        .unwrap();
        let file = load_state_file(&path);
        assert_eq!(file.synced.get("laptop"), Some(&a));
        assert_eq!(file.active.as_deref(), Some("laptop"));

        // A state file written by the upload-only sync of older versions
        // (per-vault directory signatures under "vaults") still loads.
        std::fs::write(
            &path,
            r#"{"vaults":{"laptop":{"file_count":1,"total_size":2,"max_mtime_secs":3}},"sync_off":["x"],"termius_dir":"/t"}"#,
        )
        .unwrap();
        let file = load_state_file(&path);
        assert!(file.synced.is_empty());
        assert_eq!(file.sync_off, vec!["x".to_string()]);
        assert_eq!(file.termius_dir.as_deref(), Some("/t"));
    }

    #[test]
    fn state_file_missing_or_corrupt_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load_state_file(&tmp.path().join("absent.json"))
            .synced
            .is_empty());
        let path = tmp.path().join("sync-state.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(load_state_file(&path).synced.is_empty());
    }

    #[test]
    fn pick_termius_dir_override_wins_over_saved() {
        let tmp = tempfile::tempdir().unwrap();
        let custom = tmp.path().join("custom");
        let saved = tmp.path().join("saved");
        std::fs::create_dir_all(&custom).unwrap();
        std::fs::create_dir_all(&saved).unwrap();
        let (d, from_saved) = pick_sync_termius_dir(Some(&custom), Some(&saved))
            .unwrap()
            .unwrap();
        assert_eq!(d, custom);
        assert!(!from_saved);
    }

    #[test]
    fn pick_termius_dir_uses_saved_when_no_override() {
        let tmp = tempfile::tempdir().unwrap();
        let saved = tmp.path().join("saved");
        std::fs::create_dir_all(&saved).unwrap();
        let (d, from_saved) = pick_sync_termius_dir(None, Some(&saved)).unwrap().unwrap();
        assert_eq!(d, saved);
        assert!(from_saved);
    }

    #[test]
    fn pick_termius_dir_stale_saved_falls_back() {
        let tmp = tempfile::tempdir().unwrap();
        let gone = tmp.path().join("never-created");
        assert!(pick_sync_termius_dir(None, Some(&gone)).unwrap().is_none());
        assert!(pick_sync_termius_dir(None, None).unwrap().is_none());
    }

    #[test]
    fn pick_termius_dir_missing_override_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let bogus = tmp.path().join("nope");
        assert!(pick_sync_termius_dir(Some(&bogus), None).is_err());
    }

    #[test]
    fn sync_off_on_toggle_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        let a = VaultSync {
            head: Some("a".into()),
            fingerprint: Some("fa".into()),
        };
        let b = VaultSync {
            head: Some("b".into()),
            fingerprint: Some("fb".into()),
        };
        update_state_file(&path, |f| {
            f.synced.insert("laptop".into(), a.clone());
            f.synced.insert("server".into(), b.clone());
            f.active = Some("laptop".into());
        })
        .unwrap();

        // Off for one vault: marker added, its sync state forgotten, the
        // other vault's untouched.
        let off = toggle_sync_off(&path, Some("laptop"), true).unwrap();
        assert_eq!(off, vec!["laptop".to_string()]);
        let file = load_state_file(&path);
        assert!(!file.synced.contains_key("laptop"));
        assert_eq!(file.synced.get("server"), Some(&b));
        assert_eq!(file.active, None);

        // Idempotent — no duplicate marker.
        let off = toggle_sync_off(&path, Some("laptop"), true).unwrap();
        assert_eq!(off, vec!["laptop".to_string()]);

        // Back on removes only that marker.
        let off = toggle_sync_off(&path, Some("laptop"), false).unwrap();
        assert!(off.is_empty());
    }

    #[test]
    fn sync_off_global_off_specific_on() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sync-state.json");
        update_state_file(&path, |f| {
            f.synced.insert("laptop".into(), VaultSync::default());
            f.active = Some("laptop".into());
        })
        .unwrap();

        // Global off: every vault is off, all sync state forgotten.
        let off = toggle_sync_off(&path, None, true).unwrap();
        assert_eq!(off, vec![SYNC_OFF_ALL.to_string()]);
        let file = load_state_file(&path);
        assert!(file.is_off("laptop"));
        assert!(file.is_off("server"));
        assert!(file.synced.is_empty());
        assert_eq!(file.active, None);

        // Turning one vault back on records it as an exception.
        let off = toggle_sync_off(&path, Some("laptop"), false).unwrap();
        assert_eq!(off, vec![SYNC_OFF_ALL.to_string()]);
        let file = load_state_file(&path);
        assert!(!file.is_off("laptop"), "exception vault must be on");
        assert!(file.is_off("server"), "other vaults must stay off");

        // Explicitly turning the exception off again removes it.
        let off = toggle_sync_off(&path, Some("laptop"), true).unwrap();
        assert!(off.iter().any(|x| x == SYNC_OFF_ALL));
        assert!(load_state_file(&path).is_off("laptop"));

        // Global on clears everything, exceptions included.
        let off = toggle_sync_off(&path, None, false).unwrap();
        assert!(off.is_empty());
        let file = load_state_file(&path);
        assert!(!file.is_off("laptop"));
        assert!(file.sync_on.is_empty());
    }

    // ---- two devices against one (mock) vault -------------------------

    /// One in-memory Drive shared by several sessions ("devices").
    #[derive(Clone, Default)]
    struct SharedDrive(Rc<RefCell<MockGdriveClient>>);

    impl GdriveClient for SharedDrive {
        fn list_vaults(&mut self) -> Result<Vec<VaultFolder>> {
            self.0.borrow_mut().list_vaults()
        }
        fn list_backups(&mut self, folder_id: &str) -> Result<Vec<RemoteBackup>> {
            self.0.borrow_mut().list_backups(folder_id)
        }
        fn ensure_vault(&mut self, name: &str) -> Result<String> {
            self.0.borrow_mut().ensure_vault(name)
        }
        fn upload_file(&mut self, folder_id: &str, name: &str, data: &[u8]) -> Result<String> {
            self.0.borrow_mut().upload_file(folder_id, name, data)
        }
        fn download_file(&mut self, file_id: &str) -> Result<Vec<u8>> {
            self.0.borrow_mut().download_file(file_id)
        }
        fn delete_file(&mut self, file_id: &str) -> Result<()> {
            self.0.borrow_mut().delete_file(file_id)
        }
    }

    fn session(drive: &SharedDrive) -> gdrive::Session {
        let creds = gdrive::Creds {
            email: "test@example.com".into(),
            client_id: "client".into(),
            client_secret: None,
            refresh_token: "rt".into(),
            access_token: "at".into(),
            expires_at: i64::MAX,
        };
        gdrive::Session::new_with_client(creds, Box::new(drive.clone()))
    }

    /// A test device: its own Termius dir, state file, and snapshots.
    struct Device {
        dir: tempfile::TempDir,
        home: tempfile::TempDir,
    }

    impl Device {
        fn new() -> Self {
            Device {
                dir: tempfile::tempdir().unwrap(),
                home: tempfile::tempdir().unwrap(),
            }
        }
        fn state_path(&self) -> PathBuf {
            self.home.path().join("sync-state.json")
        }
        fn snapshots(&self) -> PathBuf {
            self.home.path().join("snapshots")
        }
        fn fingerprint(&self) -> String {
            termius_data::fingerprint(self.dir.path()).unwrap()
        }
        fn set_synced(&self, s: VaultSync) {
            update_state_file(&self.state_path(), |f| {
                f.synced.insert("team".into(), s);
            })
            .unwrap();
        }
        fn engine<'a>(&self, folder_id: &str, running: &'a dyn Fn() -> bool) -> Engine<'a> {
            Engine::new(
                EngineConfig {
                    vault: "team".into(),
                    folder_id: folder_id.into(),
                    src: self.dir.path().to_path_buf(),
                    password: "sync-password-1".into(),
                    kdf: KdfParams {
                        m_kib: 1024,
                        t: 1,
                        p: 1,
                    },
                    carry_key: false,
                    keep: 0,
                    snapshots_dir: self.snapshots(),
                    state_path: self.state_path(),
                    policy: SyncPolicy::from_interval(60),
                },
                running,
            )
        }
    }

    fn host(name: &str, value: &str) -> (Vec<u8>, Option<Vec<u8>>) {
        (
            record_key(2, name.as_bytes()),
            Some(value.as_bytes().to_vec()),
        )
    }

    #[test]
    fn two_devices_sync_both_ways_and_resolve_conflicts() {
        let drive = SharedDrive::default();
        let folder = drive.0.borrow_mut().ensure_vault("team").unwrap();
        let (mut sa, mut sb) = (session(&drive), session(&drive));

        // Device A has hosts; device B has different data of its own and
        // joins with "use the vault's data".
        let a = Device::new();
        seed(a.dir.path());
        let b = Device::new();
        seed(b.dir.path());
        write_ops(b.dir.path(), 9, 50, &[host("host-1", "bravo's version")]);
        b.set_synced(VaultSync {
            head: None,
            fingerprint: Some(b.fingerprint()),
        });
        assert_ne!(a.fingerprint(), b.fingerprint());

        let a_running = Cell::new(false);
        let b_running = Cell::new(true);
        let ra = || a_running.get();
        let rb = || b_running.get();
        let mut ea = a.engine(&folder, &ra);
        let mut eb = b.engine(&folder, &rb);

        // 1. A uploads its data into the empty vault.
        assert_eq!(ea.step(&mut sa, at(0), true).unwrap(), Step::Pushed);
        assert_eq!(ea.step(&mut sa, at(1), true).unwrap(), Step::Idle);

        // 2. B sees it, but Termius is open there: it waits, untouched.
        let b_before = b.fingerprint();
        assert_eq!(eb.step(&mut sb, at(2), true).unwrap(), Step::Waiting);
        assert_eq!(b.fingerprint(), b_before);

        // 3. Termius closes on B: A's data is applied. B had no unsynced
        // edits, so no rollback snapshot is needed.
        b_running.set(false);
        assert_eq!(eb.step(&mut sb, at(3), true).unwrap(), Step::Applied);
        assert_eq!(b.fingerprint(), a.fingerprint());
        assert!(snapshot::list(&b.snapshots()).unwrap().is_empty());
        assert_eq!(eb.step(&mut sb, at(4), true).unwrap(), Step::Idle);

        // 4. A host added on B reaches A.
        write_ops(b.dir.path(), 20, 100, &[host("host-2", "beta")]);
        assert_eq!(eb.step(&mut sb, at(5), true).unwrap(), Step::Pushed);
        assert_eq!(ea.step(&mut sa, at(6), true).unwrap(), Step::Applied);
        assert_eq!(a.fingerprint(), b.fingerprint());
        let a_entries =
            crate::leveldb::live_entries(&crate::termius_data::testutil::idb_dir(a.dir.path()))
                .unwrap();
        assert!(a_entries
            .iter()
            .any(|(k, v)| k == &record_key(2, b"host-2") && v == b"beta"));

        // 5. Background writes (activity log) are not an edit: no upload.
        write_ops(
            a.dir.path(),
            30,
            200,
            &[(record_key(3, b"log-9"), Some(b"noise".to_vec()))],
        );
        assert_eq!(ea.step(&mut sa, at(7), true).unwrap(), Step::Idle);

        // 6. Conflict: both edit, B uploads first. B's data wins on A, and
        // A's own edit is kept in a pre-sync rollback snapshot.
        write_ops(a.dir.path(), 31, 300, &[host("host-a", "from A")]);
        write_ops(b.dir.path(), 32, 301, &[host("host-b", "from B")]);
        assert_eq!(eb.step(&mut sb, at(8), true).unwrap(), Step::Pushed);
        assert_eq!(ea.step(&mut sa, at(9), true).unwrap(), Step::Applied);
        assert_eq!(a.fingerprint(), b.fingerprint());
        let snaps = snapshot::list(&a.snapshots()).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].reason, "pre-sync");

        // 7. Both are in step now; nothing moves.
        assert_eq!(ea.step(&mut sa, at(10), true).unwrap(), Step::Idle);
        assert_eq!(eb.step(&mut sb, at(11), true).unwrap(), Step::Idle);

        // The state survives a restart of the service.
        let ea2 = a.engine(&folder, &ra);
        assert_eq!(ea2.synced, ea.synced);
    }

    #[test]
    fn push_into_vault_with_existing_head_uploads_local_data() {
        // "Upload this machine's data" when joining: head = the vault's
        // newest, fingerprint unknown → the first check uploads.
        let drive = SharedDrive::default();
        let folder = drive.0.borrow_mut().ensure_vault("team").unwrap();
        let other = drive
            .0
            .borrow_mut()
            .upload_file(&folder, "old.tsb", b"not-ours")
            .unwrap();
        let dev = Device::new();
        seed(dev.dir.path());
        dev.set_synced(VaultSync {
            head: Some(other),
            fingerprint: None,
        });
        let never = || false;
        let mut e = dev.engine(&folder, &never);
        let mut s = session(&drive);
        assert_eq!(e.step(&mut s, at(0), true).unwrap(), Step::Pushed);
        assert_eq!(s.list_backups(&folder).unwrap().len(), 2);
    }

    #[test]
    fn wrong_backup_password_on_pull_is_reported() {
        let drive = SharedDrive::default();
        let folder = drive.0.borrow_mut().ensure_vault("team").unwrap();
        let tsb = gdrive::encrypt_with(
            &KdfParams {
                m_kib: 1024,
                t: 1,
                p: 1,
            },
            b"another-password",
            b"payload",
        )
        .unwrap();
        drive
            .0
            .borrow_mut()
            .upload_file(&folder, "x.tsb", &tsb)
            .unwrap();
        let dev = Device::new();
        seed(dev.dir.path());
        let never = || false;
        let mut e = dev.engine(&folder, &never);
        let err = e.step(&mut session(&drive), at(0), true).unwrap_err();
        assert!(err.to_string().contains("same backup password"), "{err}");
    }
}
