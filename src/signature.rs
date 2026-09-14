//! A signature as text, once the HMAC is done: written as lowercase hex,
//! and compared without the comparison saying how far the two agreed.
//!
//! Every scheme that signs a request over HTTP — Signature Version 4,
//! Azure's Shared Key and Shared Access Signature — ends the same way, and
//! each carried these two functions until 2026-09-14 (ADR-0044). What a
//! scheme signs, and how, stays with the scheme.

use std::fmt::Write as _;

/// `bytes` as lowercase hex, which is how Signature Version 4 writes a
/// digest.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        out
    })
}

/// Equal, without the comparison's timing saying how far the two agreed.
#[must_use]
pub fn same(expected: &str, given: &str) -> bool {
    expected.len() == given.len()
        && expected
            .bytes()
            .zip(given.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_two_digits_a_byte() {
        assert_eq!(hex(&[0, 1, 0xab, 0xff]), "0001abff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn same_compares_whole_strings_only() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "ab"));
        assert!(!same("", "a"));
        assert!(same("", ""));
    }
}
