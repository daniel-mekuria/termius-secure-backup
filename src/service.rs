// SPDX-License-Identifier: Apache-2.0

//! The background service that keeps a vault's continuous sync running with
//! the terminal closed, across reboots, until the user turns it off.
//!
//! - Linux: a systemd *user* unit at
//!   `~/.config/systemd/user/termius-backup-sync-<vault>.service`
//! - macOS: a launchd LaunchAgent at
//!   `~/Library/LaunchAgents/com.termius-secure-backup.sync-<vault>.plist`
//! - Windows: a Task Scheduler logon task (`schtasks /SC ONLOGON`)
//!
//! On every platform the service runs, unattended:
//!
//! ```sh
//! termius-backup gdrive sync --name <vault> --service-secrets <file> --yes
//! ```
//!
//! where `<file>` (0600, written by this module) holds the two passwords
//! the sync needs: the Google Drive master password (unlocks the stored
//! credentials) and the backup password (encrypts the uploads).

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::paths;

/// Unit/label/task names only accept a limited character set, so anything
/// else in the vault name becomes `-`, and everything is lowercased (unit
/// files are case-sensitive on disk; conventional names are lowercase).
pub fn service_slug(vault: &str) -> String {
    vault
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

/// The two passwords an unattended sync run needs.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ServiceSecrets {
    /// Unlocks the stored Google credentials (the "master password").
    pub master_password: String,
    /// Encrypts the uploaded `.tsb` files.
    pub backup_password: String,
}

/// Read and parse a secrets file.
pub fn read_secrets(path: &Path) -> Result<ServiceSecrets> {
    let bytes = std::fs::read(path).map_err(|e| {
        Error::NotFound(format!(
            "service secrets file not found: {} ({e})",
            path.display()
        ))
    })?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Write the secrets file so that only the owner can read it (0600 on
/// Unix). Written via a temp file + rename so a crash never leaves a
/// truncated secrets file behind.
pub fn write_secrets(path: &Path, secrets: &ServiceSecrets) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_vec_pretty(secrets)?;
    json.push(b'\n');
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The arguments (after the binary path) the service runs.
pub fn service_args(vault: &str, secrets: &Path) -> Vec<String> {
    vec![
        "gdrive".into(),
        "sync".into(),
        "--name".into(),
        vault.to_string(),
        "--service-secrets".into(),
        secrets.to_string_lossy().into_owned(),
        "--yes".into(),
    ]
}

/// The constant part of a service id (everything before the vault slug).
#[cfg(target_os = "macos")]
const ID_PREFIX: &str = "com.termius-secure-backup.sync-";
#[cfg(not(target_os = "macos"))]
const ID_PREFIX: &str = "termius-backup-sync-";

/// The human-facing name of the service for a vault (the unit name on
/// Linux, the label on macOS, the task name on Windows).
pub fn service_id(vault: &str) -> String {
    format!("{ID_PREFIX}{}", service_slug(vault))
}

/// The service file location for `vault` on this platform, if any.
fn service_file(vault: &str) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // `$XDG_CONFIG_HOME/systemd/user` (usually `~/.config/systemd/user`).
        let cfg = paths::config_dir()?;
        Some(
            cfg.join("systemd")
                .join("user")
                .join(format!("{}.service", service_id(vault))),
        )
    }
    #[cfg(target_os = "macos")]
    {
        let home = paths::home_dir()?;
        Some(
            home.join("Library")
                .join("LaunchAgents")
                .join(format!("{}.plist", service_id(vault))),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let _ = vault;
        None // Task Scheduler keeps the task in the registry.
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = vault;
        None
    }
}

/// Whether a service file/registration for `vault` exists.
pub fn service_installed(vault: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        return std::process::Command::new("schtasks")
            .args(["/Query", "/TN", &service_id(vault)])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    }
    #[cfg(not(target_os = "windows"))]
    service_file(vault).is_some_and(|p| p.symlink_metadata().is_ok())
}

/// Install (or re-install) and start the background service for `vault`.
/// The binary path is taken from the currently running executable.
pub fn install_service(vault: &str, secrets: &Path) -> Result<()> {
    let exe = std::env::current_exe().map_err(|e| {
        Error::Other(format!(
            "could not determine the running binary's path: {e}"
        ))
    })?;
    #[cfg(target_os = "linux")]
    return install_linux(&exe, vault, secrets);
    #[cfg(target_os = "macos")]
    return install_macos(&exe, vault, secrets);
    #[cfg(target_os = "windows")]
    return install_windows(&exe, vault, secrets);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (exe, vault, secrets);
        Err(Error::Other(
            "the background service is only supported on Linux (systemd), \
             macOS (launchd), and Windows (Task Scheduler)"
                .into(),
        ))
    }
}

/// Stop and remove the background service for `vault`. Returns whether
/// there was a service to remove.
pub fn remove_service(vault: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    return remove_linux(vault);
    #[cfg(target_os = "macos")]
    return remove_macos(vault);
    #[cfg(target_os = "windows")]
    return remove_windows(vault);
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = vault;
        Ok(false)
    }
}

/// All vaults with an installed service (from the service files on this
/// machine), for "turn everything off". Returns slugs, which are
/// idempotent inputs to [`remove_service`].
pub fn installed_vaults() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        // Task Scheduler: enumerate and filter by our task-name prefix.
        let out = std::process::Command::new("schtasks")
            .args(["/Query", "/FO", "CSV", "/NH"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let prefix = "termius-backup-sync-";
        let mut found = Vec::new();
        for line in text.lines() {
            // CSV rows look like:  "task name", "next run", "status"
            let name = line
                .trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split('"').next())
                .unwrap_or("");
            if let Some(slug) = name.strip_prefix(prefix) {
                if !found.contains(&slug.to_string()) {
                    found.push(slug.to_string());
                }
            }
        }
        return found;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let dir = match service_dir() {
            Some(d) => d,
            None => return Vec::new(),
        };
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let stem = name
                    .strip_suffix(".service")
                    .or_else(|| name.strip_suffix(".plist"))?;
                let rest = stem.strip_prefix(ID_PREFIX)?;
                Some(rest.to_string())
            })
            .collect()
    }
}

/// The directory holding this platform's service files.
#[cfg(not(target_os = "windows"))]
fn service_dir() -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        paths::config_dir().map(|c| c.join("systemd").join("user"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = paths::home_dir()?;
        Some(home.join("Library").join("LaunchAgents"))
    }
}

// ---------------------------------------------------------------- Linux

#[cfg(target_os = "linux")]
fn run_systemctl(args: &[&str]) -> Result<std::process::Output> {
    let out = std::process::Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|e| {
            Error::Other(format!(
                "could not run 'systemctl --user' — is a systemd user session available? ({e})"
            ))
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Other(format!(
            "'systemctl --user {}' failed: {}",
            args.join(" "),
            err.trim()
        )));
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn install_linux(exe: &Path, vault: &str, secrets: &Path) -> Result<()> {
    let id = service_id(vault);
    let unit_path = service_file(vault)
        .ok_or_else(|| Error::NotFound("could not determine your home directory".to_string()))?;
    if let Some(parent) = unit_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&unit_path, unit_file_content(exe, vault, secrets))?;
    run_systemctl(&["daemon-reload"])?;
    run_systemctl(&["enable", "--now", &id])?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_linux(vault: &str) -> Result<bool> {
    let path = service_file(vault)
        .ok_or_else(|| Error::NotFound("could not determine your home directory".to_string()))?;
    let existed = path.symlink_metadata().is_ok();
    let id = service_id(vault);
    // Only talk to systemd when there was something to remove — `sync off`
    // must work on machines without a systemd user session. A unit that was
    // never enabled fails to stop/disable — ignore that.
    if existed {
        let _ = run_systemctl(&["disable", "--now", &id]);
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if existed {
        let _ = run_systemctl(&["daemon-reload"]);
    }
    Ok(existed)
}

#[cfg(target_os = "linux")]
fn unit_file_content(exe: &Path, vault: &str, secrets: &Path) -> String {
    let mut cmd = systemd_quote(exe.to_string_lossy().as_ref());
    for a in service_args(vault, secrets) {
        cmd.push(' ');
        cmd.push_str(&systemd_quote(&a));
    }
    format!(
        "[Unit]\n\
         Description=termius-backup continuous Google Drive sync (vault '{vault}')\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={cmd}\n\
         Restart=always\n\
         RestartSec=15\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// systemd ExecStart quoting: quote when the argument contains whitespace
/// (or a quote), escaping backslashes and double quotes inside.
#[cfg(target_os = "linux")]
fn systemd_quote(arg: &str) -> String {
    if arg.chars().any(|c| c.is_whitespace() || c == '"') {
        format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        arg.to_string()
    }
}

// ----------------------------------------------------------------- macOS

#[cfg(target_os = "macos")]
fn uid() -> String {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "0".into())
}

#[cfg(target_os = "macos")]
fn run_launchctl(args: &[&str]) -> Result<std::process::Output> {
    let out = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|e| {
            Error::Other(format!(
                "could not run 'launchctl' — is a macOS GUI session available? ({e})"
            ))
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Other(format!(
            "'launchctl {}' failed: {}",
            args.join(" "),
            err.trim()
        )));
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(target_os = "macos")]
fn plist_content(exe: &Path, vault: &str, secrets: &Path, log: &Path) -> String {
    let label = service_id(vault);
    let mut args: Vec<&std::ffi::OsStr> = vec![exe.as_os_str()];
    for a in service_args(vault, secrets) {
        args.push(Path::new(&a).as_os_str());
    }
    let items: Vec<String> = args
        .iter()
        .map(|a| format!("\t\t<string>{}</string>", xml_escape(&a.to_string_lossy())))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n{items}\n\t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<true/>\n\
         \t<key>StandardOutPath</key>\n\
         \t<string>{log}</string>\n\
         \t<key>StandardErrorPath</key>\n\
         \t<string>{log}</string>\n\
         </dict>\n\
         </plist>\n",
        label = xml_escape(&label),
        items = items.join("\n"),
        log = xml_escape(&log.to_string_lossy()),
    )
}

#[cfg(target_os = "macos")]
fn install_macos(exe: &Path, vault: &str, secrets: &Path) -> Result<()> {
    let home = paths::home_dir()
        .ok_or_else(|| Error::NotFound("could not determine your home directory".to_string()))?;
    let slug = service_slug(vault);
    let log = home
        .join("Library")
        .join("Logs")
        .join(format!("termius-backup-sync-{slug}.log"));
    let plist = service_file(vault)
        .ok_or_else(|| Error::NotFound("could not determine your home directory".to_string()))?;
    if let Some(parent) = plist.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&plist, plist_content(exe, vault, secrets, &log))?;
    let label = service_id(vault);
    let domain = format!("gui/{}", uid());
    let target = format!("{domain}/{label}");
    // Replacing a previously installed service: unload the old one first.
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .output();
    run_launchctl(&["bootstrap", &domain, &plist.to_string_lossy()])?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_macos(vault: &str) -> Result<bool> {
    let label = service_id(vault);
    let target = format!("gui/{}/{}", uid(), label);
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .output();
    let path = service_file(vault)
        .ok_or_else(|| Error::NotFound("could not determine your home directory".to_string()))?;
    let existed = path.symlink_metadata().is_ok();
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(existed)
}

// ---------------------------------------------------------------- Windows

#[cfg(target_os = "windows")]
fn run_schtasks(args: &[&str]) -> Result<std::process::Output> {
    let out = std::process::Command::new("schtasks")
        .args(args)
        .output()
        .map_err(|e| Error::Other(format!("could not run 'schtasks' (Task Scheduler): {e}")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let msg = if !stderr.trim().is_empty() {
            stderr.trim().to_string()
        } else {
            stdout.trim().to_string()
        };
        return Err(Error::Other(format!(
            "'schtasks {}' failed: {}",
            args.join(" "),
            if msg.is_empty() {
                "unknown error".into()
            } else {
                msg
            }
        )));
    }
    Ok(out)
}

#[cfg(target_os = "windows")]
fn task_command_line(exe: &Path, vault: &str, secrets: &Path) -> String {
    let mut cmd = format!("\"{}\"", exe.display());
    for a in service_args(vault, secrets) {
        cmd.push(' ');
        if a.contains(' ') {
            cmd.push_str(&format!("\"{a}\""));
        } else {
            cmd.push_str(&a);
        }
    }
    cmd
}

#[cfg(target_os = "windows")]
fn install_windows(exe: &Path, vault: &str, secrets: &Path) -> Result<()> {
    let name = service_id(vault);
    let tr = task_command_line(exe, vault, secrets);
    run_schtasks(&[
        "/Create", "/F", "/SC", "ONLOGON", "/TN", &name, "/IT", "/TR", &tr,
    ])?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_windows(vault: &str) -> Result<bool> {
    let name = service_id(vault);
    let existed = std::process::Command::new("schtasks")
        .args(["/Query", "/TN", &name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !existed {
        return Ok(false);
    }
    let out = std::process::Command::new("schtasks")
        .args(["/Delete", "/F", "/TN", &name])
        .output()
        .map_err(|e| Error::Other(format!("could not run 'schtasks': {e}")))?;
    if !out.status.success() {
        // "Task does not exist" is fine — nothing to remove.
        let err = String::from_utf8_lossy(&out.stderr);
        let out2 = String::from_utf8_lossy(&out.stdout);
        let msg = format!("{err}{out2}").to_lowercase();
        if !msg.contains("does not exist") && !msg.contains("not found") {
            return Err(Error::Other(format!(
                "'schtasks /Delete' failed: {}",
                format!("{err}{out2}").trim()
            )));
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_sanitizes_vault_names() {
        assert_eq!(service_slug("main-backup"), "main-backup");
        assert_eq!(service_slug("my vault.v2"), "my-vault-v2");
        assert_eq!(service_slug("a_b-c"), "a_b-c");
    }

    #[test]
    fn secrets_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("secrets.json");
        let s = ServiceSecrets {
            master_password: "m/pw \"quoted\"".into(),
            backup_password: "b pw\n".into(),
        };
        write_secrets(&p, &s).unwrap();
        let back = read_secrets(&p).unwrap();
        assert_eq!(back.master_password, s.master_password);
        assert_eq!(back.backup_password, s.backup_password);
    }

    #[test]
    fn secrets_file_missing_is_not_found() {
        let e = read_secrets(Path::new("/nonexistent/secrets.json")).unwrap_err();
        assert!(matches!(e, Error::NotFound(_)), "error: {e}");
    }

    #[test]
    fn service_args_shape() {
        let secrets = PathBuf::from("/home/u/.config/tsb/sync-service-main-backup.json");
        let args = service_args("main-backup", &secrets);
        assert_eq!(
            args,
            vec![
                "gdrive",
                "sync",
                "--name",
                "main-backup",
                "--service-secrets",
                "/home/u/.config/tsb/sync-service-main-backup.json",
                "--yes",
            ]
        );
    }

    #[test]
    fn service_id_is_stable_per_slug() {
        assert_eq!(service_id("My Vault"), service_id("my-vault"));
        assert_ne!(service_id("a"), service_id("b"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unit_file_content_quotes_and_lists_args() {
        let content = unit_file_content(
            Path::new("/home/u/.cargo/bin/termius-backup"),
            "main backup",
            Path::new("/home/u/.config/tsb/s.json"),
        );
        assert!(
            content.contains("ExecStart=/home/u/.cargo/bin/termius-backup gdrive sync"),
            "{content}"
        );
        assert!(
            content.contains(r#""main backup""#),
            "vault arg not quoted: {content}"
        );
        assert!(content.contains("Restart=always"), "{content}");
        assert!(content.contains("WantedBy=default.target"), "{content}");
    }
}
