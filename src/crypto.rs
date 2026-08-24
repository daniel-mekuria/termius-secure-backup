// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives: Argon2id key derivation and
//! XChaCha20-Poly1305 authenticated encryption.
//!
//! The KDF parameters mirror Termius's own libsodium INTERACTIVE profile
//! (Argon2id, 64 MiB / t=3 / p=4) for parity; the AEAD is XChaCha20-Poly1305
//! whose 192-bit nonce permits uniformly-random nonce selection per file.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

use crate::error::{Error, Result};

/// Salt length in bytes.
pub const SALT_LEN: usize = 16;
/// XChaCha20 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Derived key length in bytes (XChaCha20-256).
pub const KEY_LEN: usize = 32;
/// Poly1305 authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Argon2id parameters. Stored in the container header so they are tunable
/// and verifiable per-file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB (e.g. 65536 = 64 MiB).
    pub m_kib: u32,
    /// Time cost (iterations).
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // libsodium crypto_pwhash INTERACTIVE parity.
        KdfParams {
            m_kib: 65_536, // 64 MiB
            t: 3,
            p: 4,
        }
    }
}

impl KdfParams {
    /// Validate that the parameters are within sane bounds.
    pub fn validate(&self) -> Result<()> {
        if self.m_kib < 1024 || self.m_kib > 4 * 1024 * 1024 {
            return Err(Error::BadFormat {
                detail: "KDF memory cost out of range".into(),
                offset: 0,
            });
        }
        if self.t == 0 || self.t > 100 {
            return Err(Error::BadFormat {
                detail: "KDF time cost out of range".into(),
                offset: 0,
            });
        }
        if self.p == 0 || self.p > 64 {
            return Err(Error::BadFormat {
                detail: "KDF parallelism out of range".into(),
                offset: 0,
            });
        }
        Ok(())
    }
}

/// A randomly-generated salt.
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// A random XChaCha20 nonce.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Derive a 32-byte key from a password and salt using Argon2id.
pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<[u8; KEY_LEN]> {
    params.validate()?;
    let argon_params = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN))
        .map_err(|e| Error::Other(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::Auth(format!("argon2 derivation failed: {e}")))?;
    Ok(out)
}

/// A zeroizing wrapper for key material.
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Construct a key from derived bytes.
    pub fn new(key: [u8; KEY_LEN]) -> Self {
        SecretKey(key)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Best-effort zeroize without a dependency.
        for b in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

/// Seal `plaintext` with `aad` as associated data. Returns ciphertext+tag.
pub fn seal(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| Error::Other(format!("cipher init: {e}")))?;
    let n = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            n,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::PasswordRejected)
}

/// Open (decrypt+verify) `ciphertext` with `aad`. Returns the plaintext or
/// an error if the tag does not verify (wrong password or tampered data).
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| Error::Other(format!("cipher init: {e}")))?;
    let n = XNonce::from_slice(nonce);
    cipher
        .decrypt(
            n,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::PasswordRejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_params() -> KdfParams {
        // Fast enough for tests (still Argon2id).
        KdfParams {
            m_kib: 1024,
            t: 1,
            p: 1,
        }
    }

    #[test]
    fn round_trip() {
        let params = fast_params();
        let salt = random_salt();
        let nonce = random_nonce();
        let key = derive_key(b"correct horse battery staple", &salt, &params).unwrap();
        let key = SecretKey::new(key);
        let aad = b"header-bytes";
        let pt = b"the quick brown fox jumps over the lazy dog";
        let ct = seal(&key, &nonce, pt, aad).unwrap();
        assert_ne!(&ct[..], pt);
        let got = open(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn wrong_password_fails() {
        let params = fast_params();
        let salt = random_salt();
        let nonce = random_nonce();
        let k1 = SecretKey::new(derive_key(b"password-one", &salt, &params).unwrap());
        let k2 = SecretKey::new(derive_key(b"password-two", &salt, &params).unwrap());
        let ct = seal(&k1, &nonce, b"secret", b"aad").unwrap();
        let r = open(&k2, &nonce, &ct, b"aad");
        assert!(matches!(r, Err(Error::PasswordRejected)));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let params = fast_params();
        let salt = random_salt();
        let nonce = random_nonce();
        let key = SecretKey::new(derive_key(b"pw", &salt, &params).unwrap());
        let mut ct = seal(&key, &nonce, b"secret", b"aad").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        let r = open(&key, &nonce, &ct, b"aad");
        assert!(matches!(r, Err(Error::PasswordRejected)));
    }

    #[test]
    fn tampered_aad_fails() {
        let params = fast_params();
        let salt = random_salt();
        let nonce = random_nonce();
        let key = SecretKey::new(derive_key(b"pw", &salt, &params).unwrap());
        let ct = seal(&key, &nonce, b"secret", b"aad-original").unwrap();
        let r = open(&key, &nonce, &ct, b"aad-tampered");
        assert!(matches!(r, Err(Error::PasswordRejected)));
    }

    #[test]
    fn wrong_nonce_fails() {
        let params = fast_params();
        let salt = random_salt();
        let n1 = random_nonce();
        let n2 = random_nonce();
        let key = SecretKey::new(derive_key(b"pw", &salt, &params).unwrap());
        let ct = seal(&key, &n1, b"secret", b"aad").unwrap();
        let r = open(&key, &n2, &ct, b"aad");
        assert!(matches!(r, Err(Error::PasswordRejected)));
    }

    #[test]
    fn nonce_uniqueness_many_seals() {
        // Random 192-bit nonces must not collide across many seals.
        let params = fast_params();
        let salt = random_salt();
        let key = SecretKey::new(derive_key(b"pw", &salt, &params).unwrap());
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1024 {
            let n = random_nonce();
            assert!(seen.insert(n), "nonce collision detected");
            let _ = seal(&key, &n, b"x", b"a").unwrap();
        }
    }

    #[test]
    fn params_validation_rejects_extremes() {
        assert!(KdfParams {
            m_kib: 0,
            t: 3,
            p: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m_kib: 64,
            t: 3,
            p: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m_kib: 65536,
            t: 0,
            p: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m_kib: 65536,
            t: 3,
            p: 0
        }
        .validate()
        .is_err());
        assert!(KdfParams::default().validate().is_ok());
    }
}
