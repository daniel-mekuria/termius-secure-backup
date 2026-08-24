// SPDX-License-Identifier: Apache-2.0

//! Password strength assessment and the weak-password re-confirmation gate.

/// Minimum acceptable length before a password is even considered "strong".
pub const MIN_LENGTH: usize = 12;

/// A small blocklist of trivially weak passwords.
const COMMON: &[&str] = &[
    "password",
    "password1",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "abc123",
    "letmein",
    "welcome",
    "admin",
    "admin123",
    "iloveyou",
    "monkey",
    "dragon",
    "termius",
    "termius123",
    "passw0rd",
    "p@ssw0rd",
    "changeme",
    "secret",
    "root",
    "toor",
    "111111",
    "000000",
    "asdfasdf",
    "guest",
];

/// The result of a strength assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Strength {
    /// Acceptable; no extra confirmation needed.
    Strong,
    /// Weak; the caller should ask the user to re-confirm before proceeding.
    Weak { reason: WeakReason },
}

/// Why a password was judged weak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeakReason {
    TooShort,
    Common,
    LowEntropy,
    Repeating,
}

impl std::fmt::Display for WeakReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WeakReason::TooShort => write!(f, "password is shorter than {MIN_LENGTH} characters"),
            WeakReason::Common => write!(f, "password is a commonly-used weak password"),
            WeakReason::LowEntropy => {
                write!(f, "password has low character diversity / entropy")
            }
            WeakReason::Repeating => {
                write!(
                    f,
                    "password is mostly a single repeated character or pattern"
                )
            }
        }
    }
}

/// Assess a password's strength. Checks run from most specific to most
/// coarse, so a structural weakness (common word, repetition) is reported
/// before a generic low-entropy verdict.
pub fn assess(pw: &[u8]) -> Strength {
    if pw.len() < MIN_LENGTH {
        return Strength::Weak {
            reason: WeakReason::TooShort,
        };
    }
    let lower = String::from_utf8_lossy(pw).to_lowercase();
    if is_common(&lower) {
        return Strength::Weak {
            reason: WeakReason::Common,
        };
    }
    if is_repeating(&lower) {
        return Strength::Weak {
            reason: WeakReason::Repeating,
        };
    }
    // Character-class diversity as a rough entropy proxy.
    let mut classes = 0u32;
    if lower.chars().any(|c| c.is_ascii_lowercase()) {
        classes += 1;
    }
    if pw.iter().any(|b| b.is_ascii_digit()) {
        classes += 1;
    }
    if pw.iter().any(|b| b.is_ascii_punctuation()) {
        classes += 1;
    }
    if pw.iter().any(|b| b.is_ascii_uppercase()) {
        classes += 1;
    }
    if classes < 2 {
        return Strength::Weak {
            reason: WeakReason::LowEntropy,
        };
    }
    // A rough Shannon-entropy floor (bits per char × length).
    if shannon_bits(pw) < 40.0 {
        return Strength::Weak {
            reason: WeakReason::LowEntropy,
        };
    }
    Strength::Strong
}

/// True if the password is a known weak password, or a known weak base with
/// a trivial numeric suffix (e.g. "password12345"). A common base with any
/// number of trailing digits, or a trailing run of digits/symbols on a
/// common base, is still trivially weak.
fn is_common(lower: &str) -> bool {
    if COMMON.contains(&lower) {
        return true;
    }
    // Strip a trailing run of digits and re-check the base.
    let trimmed = lower.trim_end_matches(|c: char| c.is_ascii_digit());
    if trimmed.len() >= 4 && trimmed != lower {
        let stripped = trimmed.trim_end_matches(|c: char| c.is_ascii_punctuation());
        for c in COMMON {
            if *c == stripped || *c == trimmed {
                return true;
            }
        }
    }
    false
}

/// True if the password is a single repeated character, a short-period
/// pattern, or overwhelmingly dominated by one character.
fn is_repeating(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.is_empty() {
        return false;
    }
    // All same character.
    if chars.iter().all(|c| *c == chars[0]) {
        return true;
    }
    // Overwhelmingly one character (>= 80%).
    let mut counts: std::collections::HashMap<char, u32> = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0) += 1;
    }
    let max = *counts.values().max().unwrap_or(&0) as f64;
    if max / chars.len() as f64 >= 0.8 {
        return true;
    }
    // Short period repetition like "abcabcabc".
    for period in 1..=(chars.len() / 2) {
        if chars.len() % period != 0 {
            continue;
        }
        let pattern = &chars[..period];
        if chars.chunks(period).all(|chunk| chunk == pattern) {
            return true;
        }
    }
    false
}

fn shannon_bits(pw: &[u8]) -> f64 {
    use std::collections::HashMap;
    let mut counts: HashMap<u8, u64> = HashMap::new();
    for b in pw {
        *counts.entry(*b).or_insert(0) += 1;
    }
    let total = pw.len() as f64;
    let mut entropy_per_char = 0.0f64;
    for &c in counts.values() {
        let p = c as f64 / total;
        entropy_per_char -= p * p.log2();
    }
    entropy_per_char * total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_short_is_weak() {
        assert_eq!(
            assess(b"short"),
            Strength::Weak {
                reason: WeakReason::TooShort
            }
        );
    }

    #[test]
    fn common_password_is_weak() {
        assert_eq!(
            assess(b"password12345"),
            Strength::Weak {
                reason: WeakReason::Common
            }
        );
    }

    #[test]
    fn single_char_class_is_weak() {
        // only lowercase, no digits/symbols -> low diversity
        assert_eq!(
            assess(b"abcdefghijkm"),
            Strength::Weak {
                reason: WeakReason::LowEntropy
            }
        );
    }

    #[test]
    fn repeating_is_weak() {
        assert_eq!(
            assess(b"aaaaaaaaaaaa1"),
            Strength::Weak {
                reason: WeakReason::Repeating
            }
        );
    }

    #[test]
    fn pattern_repeat_is_weak() {
        assert_eq!(
            assess(b"abcabcabcabc"),
            Strength::Weak {
                reason: WeakReason::Repeating
            }
        );
    }

    #[test]
    fn strong_password_ok() {
        assert_eq!(assess(b"correct-horse-battery-9"), Strength::Strong);
        assert_eq!(assess(b"Tr0ub4dor&3-is-OK"), Strength::Strong);
    }
}
