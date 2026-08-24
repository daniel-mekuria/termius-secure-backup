// SPDX-License-Identifier: Apache-2.0

//! Property-based tests for the crypto AEAD and archive round-trips.

use proptest::prelude::*;
use termius_secure_backup::archive;
use termius_secure_backup::container;
use termius_secure_backup::crypto::{self, KdfParams};

prop_compose! {
    /// Generate a random-ish byte vector of bounded length.
    fn arb_bytes(max: usize)(len in 0..max, bytes in proptest::collection::vec(any::<u8>(), 0..max)) -> Vec<u8> {
        let _ = len;
        bytes
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Sealing then opening with the correct key/nonce/AAD recovers the
    /// plaintext for arbitrary inputs.
    #[test]
    fn aead_round_trip(pt in arb_bytes(4096), aad in arb_bytes(256)) {
        // Use fast KDF params for test speed.
        let params = KdfParams { m_kib: 1024, t: 1, p: 1 };
        let salt = crypto::random_salt();
        let nonce = crypto::random_nonce();
        let key = crypto::SecretKey::new(
            crypto::derive_key(b"prop-pw", &salt, &params).unwrap()
        );
        let pt_len = pt.len();
        let ct = crypto::seal(&key, &nonce, &pt, &aad).unwrap();
        let recovered = crypto::open(&key, &nonce, &ct, &aad).unwrap();
        prop_assert_eq!(recovered, pt);
        // Ciphertext is plaintext + 16-byte tag.
        prop_assert_eq!(ct.len(), pt_len + 16);
    }

    /// A wrong AAD must always fail to open.
    #[test]
    fn aead_wrong_aad_fails(pt in arb_bytes(1024), aad1 in arb_bytes(64), aad2 in arb_bytes(64)) {
        prop_assume!(aad1 != aad2);
        let params = KdfParams { m_kib: 1024, t: 1, p: 1 };
        let salt = crypto::random_salt();
        let nonce = crypto::random_nonce();
        let key = crypto::SecretKey::new(
            crypto::derive_key(b"prop-pw", &salt, &params).unwrap()
        );
        let ct = crypto::seal(&key, &nonce, &pt, &aad1).unwrap();
        let r = crypto::open(&key, &nonce, &ct, &aad2);
        prop_assert!(r.is_err());
    }

    /// The container round-trips an arbitrary plaintext and the cleartext
    /// header never leaks the plaintext.
    #[test]
    fn container_round_trip_hides_plaintext(pt in arb_bytes(8192)) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("p.tsb");
        let params = KdfParams { m_kib: 1024, t: 1, p: 1 };
        container::write(&path, b"prop-pw-123", &params, &pt).unwrap();
        let raw = std::fs::read(&path).unwrap();
        // The plaintext must not appear verbatim in the file.
        if !pt.is_empty() {
            prop_assert!(!raw.windows(pt.len()).any(|w| w == pt));
        }
        let got = container::read_and_decrypt(&path, b"prop-pw-123").unwrap();
        prop_assert_eq!(got, pt);
    }
}

// A simple archive round-trip property: pack a small tree, unpack, and
// verify the recorded root hash matches.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn archive_round_trip_tree(
        n_files in 1..8usize,
        content_seed in any::<u32>(),
    ) {
        let src = tempfile::tempdir().unwrap();
        // Build a deterministic-ish tree from the seed.
        let mut seed = content_seed;
        for i in 0..n_files {
            let name = format!("file_{i}.txt");
            let mut data = Vec::new();
            for _ in 0..(i * 7 + 1) {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                data.push((seed >> 16) as u8);
            }
            std::fs::write(src.path().join(&name), &data).unwrap();
        }
        let mut buf = Vec::new();
        let meta = archive::pack(
            src.path(),
            &mut buf,
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        let dest = tempfile::tempdir().unwrap();
        let got = archive::unpack(&buf, dest.path()).unwrap();
        archive::verify(dest.path(), &got).unwrap();
        prop_assert_eq!(got.sha256_root, meta.sha256_root);
    }
}
