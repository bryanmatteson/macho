use std::fmt;
use std::ops::{Add, Sub};

use serde::Serialize;

macro_rules! addr_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize)]
        pub struct $name(pub u64);

        impl $name {
            pub fn as_usize(self) -> usize {
                self.0 as usize
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:#x})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        impl Add<u64> for $name {
            type Output = Self;
            fn add(self, rhs: u64) -> Self {
                Self(self.0 + rhs)
            }
        }

        impl Sub for $name {
            type Output = u64;
            fn sub(self, rhs: Self) -> u64 {
                self.0 - rhs.0
            }
        }
    };
}

addr_type!(
    FatFileOffset,
    "Absolute byte offset within a fat container."
);
addr_type!(
    ThinFileOffset,
    "Byte offset within a thin Mach-O image slice."
);
addr_type!(Rva, "Relative virtual address (offset from image base).");
addr_type!(Va, "Virtual address as encoded in the Mach-O file.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_hex() {
        assert_eq!(format!("{}", Va(0x1000)), "0x1000");
    }

    #[test]
    fn debug_named() {
        assert_eq!(format!("{:?}", ThinFileOffset(16)), "ThinFileOffset(0x10)");
    }

    #[test]
    fn add_offset() {
        assert_eq!(ThinFileOffset(10) + 5, ThinFileOffset(15));
    }

    #[test]
    fn sub_same_type() {
        let diff: u64 = Va(0x2000) - Va(0x1000);
        assert_eq!(diff, 0x1000);
    }

    #[test]
    fn ordering() {
        assert!(ThinFileOffset(1) < ThinFileOffset(2));
    }
}
