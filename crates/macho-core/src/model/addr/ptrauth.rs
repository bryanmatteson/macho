//! Pointer-authentication (arm64e) helpers.
//!
//! arm64e encodes a signature in the top 16 bits of a pointer. When dyld
//! applies fixups it replaces the signature with the authenticated target,
//! so pointers read from memory in a live process are plain VAs. Static
//! analysis, though, often sees the raw on-disk form and must strip the
//! signature bits before dereferencing the pointer or comparing it against
//! a VA.
//!
//! This module exposes the stripping operation as a single, testable helper
//! rather than scattering bit-masking through metadata readers. Call
//! [`strip_ptrauth`] on any `u64` that was read directly from the binary on
//! an arm64e image and is meant to be interpreted as a VA.

/// Mask covering the 48 virtual-address bits used by iOS / macOS arm64e.
///
/// The ARM architecture allows up to 52 bits of virtual address, but Apple
/// silicon currently caps usable VAs at 48 bits and reserves bits 48..=63
/// for pointer-auth metadata. We mask conservatively here: if a future
/// Apple system widens the VA range we'll need to narrow this mask, but
/// today any pointer with high bits set on arm64e has been signed.
const PTRAUTH_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Strip the pointer-authentication signature from an arm64e pointer.
///
/// Returns the raw VA with all pointer-auth metadata cleared. On non-arm64e
/// architectures callers should avoid this helper — a plain pointer value
/// on x86_64 or arm64 may legitimately occupy the top bits and stripping
/// would corrupt it.
#[inline]
pub fn strip_ptrauth(raw: u64) -> u64 {
    raw & PTRAUTH_MASK
}

/// Whether a `u64` has any bits set that arm64e would interpret as
/// pointer-auth metadata. A `false` return means [`strip_ptrauth`] is a no-op.
#[inline]
pub fn has_ptrauth_bits(raw: u64) -> bool {
    raw & !PTRAUTH_MASK != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_high_bits() {
        let signed = 0x8012_3456_dead_beefu64;
        assert_eq!(strip_ptrauth(signed), 0x0000_3456_dead_beef);
    }

    #[test]
    fn noop_when_unsigned() {
        let plain = 0x0000_0001_dead_beefu64;
        assert_eq!(strip_ptrauth(plain), plain);
        assert!(!has_ptrauth_bits(plain));
    }

    #[test]
    fn detects_signed_pointer() {
        assert!(has_ptrauth_bits(0x8012_0000_0000_0000));
        assert!(!has_ptrauth_bits(0));
    }
}
