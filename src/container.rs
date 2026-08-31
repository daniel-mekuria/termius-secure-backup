// SPDX-License-Identifier: Apache-2.0

//! The `.tsb` (Termius Secure Backup) container format.
//!
//! Layout (all integers little-endian):
//! ```text
//! magic        : 6 bytes  b"TSBAK\x01"
//! kdf_algo     : 1 byte   (1 = argon2id)
//! kdf_m_kib    : u32 LE
//! kdf_t        : u32 LE
//! kdf_p        : u32 LE
//! salt_len     : u16 LE   (16)
//! salt         : 16 bytes
//! cipher       : 1 byte   (1 = xchacha20-poly1305)
//! nonce_len    : u16 LE   (24)
//! nonce        : 24 bytes
//! ct_len       : u64 LE
//! ciphertext   : ct_len bytes
//! ```
//! The cleartext header (magic .. nonce) is bound to the ciphertext as AEAD
//! associated data, so any tampering with the header causes decryption to
//! fail.

use std::io::Write;
use std::path::Path;

use crate::crypto::{
    derive_key, open, random_nonce, random_salt, seal, KdfParams, SecretKey, NONCE_LEN, SALT_LEN,
    TAG_LEN,
};
use crate::error::{Error, Result};

/// Container magic + version byte: "TSBAK" + version 1.
pub const MAGIC: &[u8; 6] = b"TSBAK\x01";
/// Supported container version.
pub const VERSION: u8 = 1;
/// Total cleartext header length in bytes (magic through ct_len).
pub const HEADER_LEN: usize = 73;
const KDF_ARGON2ID: u8 = 1;
const CIPHER_XCHACHA: u8 = 1;

/// Cleartext header, parsed from a `.tsb` file. Reading it requires no
/// password — it is what `info` prints.
#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ct_len: u64,
}

/// Write an encrypted container to `dest`. `plaintext` is the already-
/// compressed+archived payload; `aad` is captured from the header bytes.
/// Parent directories of `dest` are created as needed (e.g. a fresh
/// `~/.config/termius-secure-backup/` on first `gdrive login`).
pub fn write(dest: &Path, password: &[u8], params: &KdfParams, plaintext: &[u8]) -> Result<()> {
    params.validate()?;
    let salt = random_salt();
    let nonce = random_nonce();
    let header = encode_header(params, &salt, &nonce, (plaintext.len() + TAG_LEN) as u64);

    let key = SecretKey::new(derive_key(password, &salt, params)?);
    let ciphertext = seal(&key, &nonce, plaintext, &header)?;

    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Io(std::io::Error::new(
                    e.kind(),
                    format!("creating the directory for {}: {e}", dest.display()),
                ))
            })?;
        }
    }
    let mut file = std::fs::File::create(dest).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("writing {}: {e}", dest.display()),
        ))
    })?;
    file.write_all(&header).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("writing {}: {e}", dest.display()),
        ))
    })?;
    file.write_all(&ciphertext).map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("writing {}: {e}", dest.display()),
        ))
    })?;
    file.sync_all().map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("writing {}: {e}", dest.display()),
        ))
    })?;
    Ok(())
}

/// Read a `.tsb` file, naming it in any "not found" error.
fn read_backup_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::NotFound(format!("backup file not found: {}", path.display()))
        } else {
            Error::Io(std::io::Error::new(
                e.kind(),
                format!("reading {}: {e}", path.display()),
            ))
        }
    })
}

/// Read and parse only the cleartext header. No password required.
pub fn read_header(path: &Path) -> Result<Header> {
    let raw = read_backup_file(path)?;
    parse_header(&raw)
}

/// Read the full container and decrypt it with `password`. Returns the
/// plaintext payload (compressed archive).
pub fn read_and_decrypt(path: &Path, password: &[u8]) -> Result<Vec<u8>> {
    let raw = read_backup_file(path)?;
    let header_len = HEADER_LEN;
    if raw.len() < header_len {
        return Err(Error::BadFormat {
            detail: "file shorter than header".into(),
            offset: raw.len() as u64,
        });
    }
    let header_bytes = &raw[..header_len];
    let header = parse_header(header_bytes)?;
    header.kdf_params.validate()?;
    let ct_len = header.ct_len as usize;
    if raw.len() != header_len + ct_len {
        return Err(Error::BadFormat {
            detail: format!(
                "ciphertext length mismatch: header says {ct_len}, file has {}",
                raw.len() - header_len
            ),
            offset: header_len as u64,
        });
    }
    let ciphertext = &raw[header_len..];
    let key = SecretKey::new(derive_key(password, &header.salt, &header.kdf_params)?);
    let plaintext = open(&key, &header.nonce, ciphertext, header_bytes)?;
    Ok(plaintext)
}

/// The exact, canonical header byte layout for given fields.
fn encode_header(
    params: &KdfParams,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ct_len: u64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_LEN);
    buf.extend_from_slice(MAGIC);
    buf.push(VERSION);
    buf.push(KDF_ARGON2ID);
    buf.extend_from_slice(&params.m_kib.to_le_bytes());
    buf.extend_from_slice(&params.t.to_le_bytes());
    buf.extend_from_slice(&params.p.to_le_bytes());
    buf.extend_from_slice(&(SALT_LEN as u16).to_le_bytes());
    buf.extend_from_slice(salt);
    buf.push(CIPHER_XCHACHA);
    buf.extend_from_slice(&(NONCE_LEN as u16).to_le_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&ct_len.to_le_bytes());
    buf
}

/// Parse the canonical header bytes (inverse of `encode_header`).
fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < HEADER_LEN {
        return Err(Error::BadFormat {
            detail: "header too short".into(),
            offset: 0,
        });
    }
    if &buf[0..6] != MAGIC {
        return Err(Error::BadFormat {
            detail: "bad magic".into(),
            offset: 0,
        });
    }
    let version = buf[6];
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    if buf[7] != KDF_ARGON2ID {
        return Err(Error::UnsupportedKdf(buf[7]));
    }
    let m_kib = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    let t = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let p = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let salt_len = u16::from_le_bytes(buf[20..22].try_into().unwrap());
    if salt_len != SALT_LEN as u16 {
        return Err(Error::BadFormat {
            detail: format!("bad salt length {salt_len}"),
            offset: 20,
        });
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buf[22..38]);
    let cipher = buf[38];
    if cipher != CIPHER_XCHACHA {
        return Err(Error::UnsupportedCipher(cipher));
    }
    let nonce_len = u16::from_le_bytes(buf[39..41].try_into().unwrap());
    if nonce_len != NONCE_LEN as u16 {
        return Err(Error::BadFormat {
            detail: format!("bad nonce length {nonce_len}"),
            offset: 39,
        });
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&buf[41..65]);
    let ct_len = u64::from_le_bytes(buf[65..73].try_into().unwrap());
    Ok(Header {
        version,
        kdf_params: KdfParams { m_kib, t, p },
        salt,
        nonce,
        ct_len,
    })
}

/// `info` formatting helper (returns a human-readable summary string).
pub fn format_info(h: &Header) -> String {
    format!(
        "Termius Secure Backup (.tsb)\n  format version : {}\n  KDF            : Argon2id\n  KDF memory     : {} KiB ({} MiB)\n  KDF time       : {}\n  KDF parallelism: {}\n  cipher         : XChaCha20-Poly1305\n  ciphertext len : {} bytes\n  (password required to read contents)",
        h.version,
        h.kdf_params.m_kib,
        h.kdf_params.m_kib / 1024,
        h.kdf_params.t,
        h.kdf_params.p,
        h.ct_len,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> KdfParams {
        KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        }
    }

    #[test]
    fn write_then_read_header_no_password() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let pt = b"hello payload";
        write(tmp.path(), b"strong-pw-123", &fast(), pt).unwrap();
        let h = read_header(tmp.path()).unwrap();
        assert_eq!(h.version, VERSION);
        assert_eq!(h.kdf_params, fast());
        assert_eq!(h.ct_len, (pt.len() + TAG_LEN) as u64);
    }

    #[test]
    fn write_then_decrypt_round_trip() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let pt = b"the payload bytes";
        write(tmp.path(), b"strong-pw-123", &fast(), pt).unwrap();
        let got = read_and_decrypt(tmp.path(), b"strong-pw-123").unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn wrong_password_fails_cleanly() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write(tmp.path(), b"strong-pw-123", &fast(), b"payload").unwrap();
        let r = read_and_decrypt(tmp.path(), b"wrong-password-x");
        assert!(matches!(r, Err(Error::PasswordRejected)));
    }

    #[test]
    fn magic_header_is_only_cleartext() {
        // The payload is encrypted; reading the raw file should not leak pt.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let pt = b"UNIQUEPLAINTEXTTOKEN";
        write(tmp.path(), b"strong-pw-123", &fast(), pt).unwrap();
        let raw = std::fs::read(tmp.path()).unwrap();
        assert!(!raw.windows(pt.len()).any(|w| w == pt));
        // but the magic IS present in the clear
        assert!(raw.starts_with(MAGIC));
    }

    #[test]
    fn truncated_file_errors() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write(tmp.path(), b"strong-pw-123", &fast(), b"payload").unwrap();
        let raw = std::fs::read(tmp.path()).unwrap();
        std::fs::write(tmp.path(), &raw[..30]).unwrap();
        let r = read_header(tmp.path());
        assert!(matches!(r, Err(Error::BadFormat { .. })));
    }

    #[test]
    fn bad_magic_errors() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"NOTTSBAK\x01restofheader").unwrap();
        let r = read_header(tmp.path());
        assert!(matches!(r, Err(Error::BadFormat { .. })));
    }

    #[test]
    fn tampered_ct_len_in_header_fails_decrypt() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write(tmp.path(), b"strong-pw-123", &fast(), b"payload").unwrap();
        let mut raw = std::fs::read(tmp.path()).unwrap();
        // Flip a bit in the ct_len field (bytes 65..73).
        raw[65] ^= 0x01;
        std::fs::write(tmp.path(), &raw).unwrap();
        let r = read_and_decrypt(tmp.path(), b"strong-pw-123");
        // ct_len mismatch causes a short read / tag failure.
        assert!(r.is_err());
    }

    #[test]
    fn tampered_kdf_param_fails_decrypt() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write(tmp.path(), b"strong-pw-123", &fast(), b"payload").unwrap();
        let mut raw = std::fs::read(tmp.path()).unwrap();
        // Flip a bit in m_kib (bytes 8..12). This changes the AAD-bound header
        // but the on-disk ciphertext remains the same -> tag fails.
        raw[8] ^= 0x01;
        std::fs::write(tmp.path(), &raw).unwrap();
        let r = read_and_decrypt(tmp.path(), b"strong-pw-123");
        assert!(matches!(r, Err(Error::PasswordRejected)));
    }

    #[test]
    fn info_summary_includes_params() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write(tmp.path(), b"strong-pw-123", &fast(), b"payload").unwrap();
        let h = read_header(tmp.path()).unwrap();
        let s = format_info(&h);
        assert!(s.contains("Argon2id"));
        assert!(s.contains("XChaCha20-Poly1305"));
    }
}
