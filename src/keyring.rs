// SPDX-License-Identifier: Apache-2.0

//! Termius's `localKey` — the 32-byte NaCl secretbox key Termius uses to
//! encrypt every host / key field in its IndexedDB.
//!
//! Termius stores that key in the **OS keyring**, a shared system-wide
//! secret store (Windows Credential Manager, the freedesktop Secret Service
//! on Linux, the macOS Keychain). It is not part of the Termius data
//! directory; it sits under one namespaced entry:
//!
//!   service `Termius` (or `termius-app` for a snap install) / account `localKey`
//!
//! On Windows that is the Credential Manager generic credential whose target
//! is `Termius/localKey`.
//!
//! Because the key lives *outside* the data directory, a backup of the data
//! directory alone cannot restore on another machine: the target's Termius
//! uses its own `localKey`, so the source's fields fail to decrypt (they show
//! up as empty rows). Carrying the key — reading it from the source keyring at
//! pack time, shipping it inside the encrypted archive, and installing it into
//! the target keyring at restore time — is what makes cross-machine restore
//! work.
//!
//! We only ever touch the Termius-namespaced entry. Other applications'
//! keyring items (git, browsers, …) are never read or written.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The keyring account (attribute) name Termius uses for the key.
pub const ACCOUNT: &str = "localKey";

/// Candidate service names, tried in order. The name depends on how Termius
/// was installed (it uses the executable name as the keyring service), so a
/// snap install lives under `termius-app` while macOS uses `Termius`.
const CANDIDATE_SERVICES: &[&str] = &[
    "Termius",
    "termius-app",
    "Termius (MAS)",
    "termius",
    "com.termius-dmg.mac",
];

/// The service we install under when the target has no existing Termius
/// entry (a fresh machine). This is the standard (non-snap) service name.
const DEFAULT_SERVICE: &str = "Termius";

/// A captured `localKey`, carried inside an archive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarriedKey {
    /// base64 of the 32-byte NaCl secretbox key.
    pub key_b64: String,
    /// The keyring service it was read from (provenance, for logging).
    pub service: String,
}

impl CarriedKey {
    /// A short human description for log lines.
    pub fn describe(&self) -> String {
        format!("service={} account={}", self.service, ACCOUNT)
    }
}

/// True if `b64` base64-decodes to exactly 32 bytes — the shape of a
/// `localKey`. Used to reject garbage before it is stored or installed.
pub fn looks_like_local_key(b64: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map(|b| b.len() == 32)
        .unwrap_or(false)
}

/// Read Termius's `localKey` from the OS keyring.
///
/// Returns `Ok(Some(key))` when a candidate service holds a shape-valid key,
/// `Ok(None)` when none does (Termius has never run on this machine, the
/// keyring is locked, or the entry uses a service name we don't know). This
/// is a read of one namespaced item; it never mutates the keyring.
pub fn read_local_key() -> Result<Option<CarriedKey>> {
    for service in CANDIDATE_SERVICES {
        if let Some(raw) = backend::read(service) {
            let raw = raw.trim().to_string();
            if looks_like_local_key(&raw) {
                return Ok(Some(CarriedKey {
                    key_b64: raw,
                    service: service.to_string(),
                }));
            }
        }
    }
    Ok(None)
}

/// Install `key_b64` into the OS keyring so the local Termius can use it.
///
/// Overwrites every candidate service that already holds an entry (so the
/// local Termius finds the carried key whichever service it reads) and also
/// ensures the default service has it. Returns a description of what was
/// written, for the caller to print.
pub fn install_local_key(key_b64: &str) -> Result<String> {
    let key = key_b64.trim();
    if !looks_like_local_key(key) {
        return Err(Error::BadFormat {
            detail: format!(
                "the carried Termius key is not a 32-byte key (it base64-decodes to {} bytes)",
                base64::engine::general_purpose::STANDARD
                    .decode(key)
                    .map(|b| b.len())
                    .unwrap_or(0)
            ),
            offset: 0,
        });
    }

    let mut written: Vec<String> = Vec::new();
    // Overwrite any existing Termius entry, whichever candidate service
    // holds one, so the local Termius always finds the carried key.
    for service in CANDIDATE_SERVICES {
        if backend::read(service).is_some() {
            backend::write(service, key)?;
            written.push(format!("{service} (overwritten)"));
        }
    }
    // Ensure the default service has the key (a fresh target has no entry).
    if !written.iter().any(|w| w.starts_with(DEFAULT_SERVICE)) {
        backend::write(DEFAULT_SERVICE, key)?;
        written.push(format!("{DEFAULT_SERVICE} (created)"));
    }

    Ok(format!(
        "Termius localKey (account {ACCOUNT}) installed under: {}",
        written.join(", ")
    ))
}

// --------------------------------------------------------------------------
// Platform backends. Each provides `read(service) -> Option<String>` (the
// key's base64 value, or None) and `write(service, key_b64) -> io::Result`.
// Only one compiles per target.
// --------------------------------------------------------------------------

#[cfg(windows)]
mod backend {
    //! Windows: the Credential Manager, via `advapi32` FFI. `cmdkey` cannot
    //! print a credential's blob, so reading needs `CredReadW` regardless.

    use std::io;

    use super::ACCOUNT;

    #[repr(C)]
    struct Filetime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct Credential {
        flags: u32,
        typ: u32,
        target: *mut u16,
        comment: *mut u16,
        last_written: Filetime,
        blob_size: u32,
        blob: *mut u8,
        persist: u32,
        attr_count: u32,
        attrs: *mut u8,
        alias: *mut u16,
        user: *mut u16,
    }

    const CRED_TYPE_GENERIC: u32 = 1;
    const CRED_PERSIST_LOCAL: u32 = 2;

    extern "system" {
        fn CredReadW(
            target: *const u16,
            typ: u32,
            flags: u32,
            credential: *mut *mut Credential,
        ) -> i32;
        fn CredWriteW(credential: *const Credential, flags: u32) -> i32;
        fn CredDeleteW(target: *const u16, typ: u32, flags: u32) -> i32;
        fn CredFree(credential: *const Credential);
    }

    /// Encode `s` as a NUL-terminated UTF-16 (wide) string.
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The Credential Manager declares no blob encoding. keytar writes UTF-8;
    /// also try UTF-16-LE and keep the first that yields a non-empty string.
    fn decode_blob(blob: &[u8]) -> Option<String> {
        if let Ok(s) = std::str::from_utf8(blob) {
            let t = s.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
        if blob.len() >= 2 {
            let u: Vec<u16> = (0..blob.len() / 2)
                .map(|i| u16::from_le_bytes([blob[2 * i], blob[2 * i + 1]]))
                .collect();
            let t = String::from_utf16_lossy(&u).trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }
        None
    }

    pub fn read(service: &str) -> Option<String> {
        let target = wide(&format!("{service}/{ACCOUNT}"));
        let mut cred: *mut Credential = std::ptr::null_mut();
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
        if ok == 0 || cred.is_null() {
            return None;
        }
        let c = unsafe { &*cred };
        let blob = unsafe { std::slice::from_raw_parts(c.blob, c.blob_size as usize) };
        let val = decode_blob(blob);
        unsafe { CredFree(c as *const Credential) };
        val
    }

    pub fn write(service: &str, key_b64: &str) -> io::Result<()> {
        let mut target = wide(&format!("{service}/{ACCOUNT}"));
        let mut user = wide(ACCOUNT);
        let blob: &[u8] = key_b64.as_bytes(); // stored as UTF-8, like keytar

        // Overwrite semantics: delete first (ignore "not found"), then write.
        unsafe {
            let _ = CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0);
        }
        let cred = Credential {
            flags: 0,
            typ: CRED_TYPE_GENERIC,
            target: target.as_mut_ptr(),
            comment: std::ptr::null_mut(),
            last_written: Filetime { low: 0, high: 0 },
            blob_size: blob.len() as u32,
            blob: blob.as_ptr() as *mut u8,
            persist: CRED_PERSIST_LOCAL,
            attr_count: 0,
            attrs: std::ptr::null_mut(),
            alias: std::ptr::null_mut(),
            user: user.as_mut_ptr(),
        };
        let r = unsafe { CredWriteW(&cred, 0) };
        if r != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "macos")]
mod backend {
    //! macOS: the Keychain, via the `security` CLI.

    use std::io;
    use std::process::Command;

    use super::ACCOUNT;

    pub fn read(service: &str) -> Option<String> {
        let out = Command::new("security")
            .args(["find-generic-password", "-s", service, "-a", ACCOUNT, "-w"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    pub fn write(service: &str, key_b64: &str) -> io::Result<()> {
        // `-U` updates the item if the (service, account) pair already exists.
        let st = Command::new("security")
            .args([
                "add-generic-password",
                "-U",
                "-s",
                service,
                "-a",
                ACCOUNT,
                "-w",
                key_b64,
            ])
            .status()?;
        if st.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "security add-generic-password exited with {st}"
            )))
        }
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod backend {
    //! Linux / other Unix: the freedesktop Secret Service, via `secret-tool`
    //! (shipped with libsecret-tools; the same backend keytar uses).

    use std::io;
    use std::io::Write;
    use std::process::Command;

    use super::ACCOUNT;

    pub fn read(service: &str) -> Option<String> {
        let out = Command::new("secret-tool")
            .args(["lookup", "service", service, "account", ACCOUNT])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    pub fn write(service: &str, key_b64: &str) -> io::Result<()> {
        // The secret value itself is read from stdin; the rest are attributes.
        // `--replace` overwrites an existing item with the same attributes.
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                "--replace",
                "--service",
                service,
                "--account",
                ACCOUNT,
            ])
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or_else(|| io::Error::other("could not open secret-tool stdin"))?;
            stdin.write_all(key_b64.as_bytes())?;
        }
        let st = child.wait()?;
        if st.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "secret-tool store exited with {st}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_check_accepts_32_bytes() {
        let k = base64::engine::general_purpose::STANDARD.encode(vec![7u8; 32]);
        assert!(looks_like_local_key(&k));
        // Tolerates surrounding whitespace.
        assert!(looks_like_local_key(&format!("  {k}\n")));
    }

    #[test]
    fn shape_check_rejects_wrong_length() {
        assert!(!looks_like_local_key(
            &base64::engine::general_purpose::STANDARD.encode(vec![7u8; 31])
        ));
        assert!(!looks_like_local_key(
            &base64::engine::general_purpose::STANDARD.encode(vec![7u8; 33])
        ));
    }

    #[test]
    fn shape_check_rejects_non_base64() {
        assert!(!looks_like_local_key("not base64 !!"));
        assert!(!looks_like_local_key(""));
    }

    #[test]
    fn install_rejects_bad_shape() {
        assert!(install_local_key("too-short").is_err());
    }

    #[test]
    fn read_is_available_and_never_fatals() {
        // Whatever the environment (CI, no keyring, locked), read must
        // return a value rather than panic; we only assert it runs.
        let _ = read_local_key();
    }
}
