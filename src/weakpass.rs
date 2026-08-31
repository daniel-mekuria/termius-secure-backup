// SPDX-License-Identifier: Apache-2.0

//! Password strength assessment and the weak-password re-confirmation gate.
//!
//! Uses [zxcvbn], the standard password-strength estimator: it matches
//! dictionary words, keyboard patterns, sequences, dates, and leetspeak
//! substitutions, and reports the order of magnitude of guesses an offline
//! attacker would need (`guesses_log10`). Backups are protected by
//! Argon2id, so an attacker with a stolen `.tsb` file brute-forces the
//! password offline — the bar is therefore "at least 10^8 guesses"
//! (zxcvbn score ≥ 3, which zxcvbn itself documents as the floor:
//! "any score less than 3 should be considered too weak").

use zxcvbn::Score;

/// Minimum acceptable length before a password is even considered "strong".
/// A hard floor on top of the zxcvbn score: 12 characters rules out
/// short-but-random passwords that score well but are a typing-error away
/// from being forgotten.
pub const MIN_LENGTH: usize = 12;

/// The password must require at least 10^MIN_GUESSES_LOG10 guesses
/// (zxcvbn score ≥ 3).
const MIN_GUESSES_LOG10: f64 = 8.0;

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
    /// Fewer than [`MIN_LENGTH`] characters.
    TooShort,
    /// zxcvbn estimates it can be cracked in fewer than
    /// 10^`MIN_GUESSES_LOG10` guesses; `detail` is zxcvbn's own
    /// plain-language explanation (warning + first suggestion).
    Guessable { detail: String },
}

impl std::fmt::Display for WeakReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WeakReason::TooShort => {
                write!(f, "password is shorter than {MIN_LENGTH} characters.")
            }
            WeakReason::Guessable { detail } => write!(f, "{detail}"),
        }
    }
}

/// Assess a password's strength. The length floor runs first, then zxcvbn:
/// a weak verdict carries zxcvbn's explanation so the prompt can tell the
/// user exactly what is wrong (e.g. "This is a top-10 common password.").
pub fn assess(pw: &[u8]) -> Strength {
    if pw.len() < MIN_LENGTH {
        return Strength::Weak {
            reason: WeakReason::TooShort,
        };
    }
    let text = String::from_utf8_lossy(pw);
    let result = zxcvbn::zxcvbn(&text, &[]);
    if result.guesses_log10() >= MIN_GUESSES_LOG10 && result.score() >= Score::Three {
        Strength::Strong
    } else {
        Strength::Weak {
            reason: WeakReason::Guessable {
                detail: explain_weak(&result),
            },
        }
    }
}

/// Build the user-facing explanation for a weak password from zxcvbn's
/// feedback (e.g. `This is a top-10 common password. Add another word or
/// two.`). Falls back to a generic message when zxcvbn gives none.
fn explain_weak(result: &zxcvbn::Entropy) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(fb) = result.feedback() {
        if let Some(w) = fb.warning() {
            parts.push(w.to_string());
        }
        if let Some(s) = fb.suggestions().first() {
            parts.push(s.to_string());
        }
    }
    if parts.is_empty() {
        parts.push(format!(
            "password is too easy to guess (estimated strength 10^{:.1} guesses; at least 10^{MIN_GUESSES_LOG10:.0} needed).",
            result.guesses_log10()
        ));
    }
    parts.join(" ")
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
        // The 11-char password used in the non-interactive CLI test:
        // too short, so it warns and proceeds via --yes.
        assert_eq!(
            assess(b"weakpass123"),
            Strength::Weak {
                reason: WeakReason::TooShort
            }
        );
    }

    #[test]
    fn common_password_is_weak() {
        let r = assess(b"password12345");
        assert!(
            matches!(
                r,
                Strength::Weak {
                    reason: WeakReason::Guessable { .. }
                }
            ),
            "password12345 should be guessable, got {r:?}"
        );
    }

    #[test]
    fn sequence_is_weak() {
        assert!(matches!(
            assess(b"abcdefghijkm"),
            Strength::Weak {
                reason: WeakReason::Guessable { .. }
            }
        ));
    }

    #[test]
    fn repeating_is_weak() {
        assert!(matches!(
            assess(b"aaaaaaaaaaaa1"),
            Strength::Weak {
                reason: WeakReason::Guessable { .. }
            }
        ));
    }

    #[test]
    fn pattern_repeat_is_weak() {
        assert!(matches!(
            assess(b"abcabcabcabc"),
            Strength::Weak {
                reason: WeakReason::Guessable { .. }
            }
        ));
    }

    #[test]
    fn keyboard_pattern_is_weak() {
        assert!(matches!(
            assess(b"qweqweqweqwe12"),
            Strength::Weak {
                reason: WeakReason::Guessable { .. }
            }
        ));
    }

    #[test]
    fn weak_reason_message_is_actionable() {
        // The user should see zxcvbn's plain-language explanation, not a
        // bare "weak" verdict.
        let Strength::Weak { reason } = assess(b"password12345") else {
            panic!("expected weak");
        };
        let s = reason.to_string();
        assert!(!s.is_empty());
        assert!(
            s.to_lowercase().contains("common") || s.to_lowercase().contains("password"),
            "message should explain why: {s}"
        );
    }

    #[test]
    fn strong_password_ok() {
        assert_eq!(assess(b"correct-horse-battery-9"), Strength::Strong);
        assert_eq!(assess(b"Tr0ub4dor&3-is-OK"), Strength::Strong);
        assert_eq!(assess(b"xK9#mQ2$vL7@wP4z"), Strength::Strong);
    }

    #[test]
    fn score_three_boundary_is_strong() {
        // 10^8 guesses (zxcvbn score 3) is the floor — it passes.
        assert_eq!(assess(b"P@ssw0rd!2026x"), Strength::Strong);
    }
}
