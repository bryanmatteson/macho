use std::borrow::Cow;
use std::fmt;

macro_rules! name_type {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub fn from_bytes(raw: [u8; 16]) -> Self {
                Self(raw)
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            /// Returns bytes up to the first null byte.
            pub fn trimmed_bytes(&self) -> &[u8] {
                match self.0.iter().position(|&b| b == 0) {
                    Some(pos) => &self.0[..pos],
                    None => &self.0,
                }
            }

            pub fn as_str_lossy(&self) -> Cow<'_, str> {
                String::from_utf8_lossy(self.trimmed_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "\"{}\"", self.as_str_lossy())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.as_str_lossy())
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.trimmed_bytes() == other.as_bytes()
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.trimmed_bytes() == other.as_bytes()
            }
        }
    };
}

name_type!(SegmentName);
name_type!(SectionName);

impl SegmentName {
    pub const TEXT: Self = Self::from_static(b"__TEXT");
    pub const DATA: Self = Self::from_static(b"__DATA");
    pub const DATA_CONST: Self = Self::from_static(b"__DATA_CONST");
    pub const LINKEDIT: Self = Self::from_static(b"__LINKEDIT");
    pub const PAGEZERO: Self = Self::from_static(b"__PAGEZERO");

    const fn from_static(s: &[u8]) -> Self {
        let mut buf = [0u8; 16];
        let mut i = 0;
        while i < s.len() && i < 16 {
            buf[i] = s[i];
            i += 1;
        }
        Self(buf)
    }
}

impl SectionName {
    pub const TEXT: Self = Self::from_static(b"__text");
    pub const DATA: Self = Self::from_static(b"__data");
    pub const BSS: Self = Self::from_static(b"__bss");
    pub const COMMON: Self = Self::from_static(b"__common");
    pub const OBJC_CLASSLIST: Self = Self::from_static(b"__objc_classlist");
    pub const OBJC_CATLIST: Self = Self::from_static(b"__objc_catlist");
    pub const OBJC_PROTOLIST: Self = Self::from_static(b"__objc_protolist");
    pub const OBJC_DATA: Self = Self::from_static(b"__objc_data");
    pub const OBJC_CONST: Self = Self::from_static(b"__objc_const");
    pub const OBJC_SELREFS: Self = Self::from_static(b"__objc_selrefs");
    pub const OBJC_METHNAMES: Self = Self::from_static(b"__objc_methname");
    pub const OBJC_CLASSNAME: Self = Self::from_static(b"__objc_classname");
    pub const OBJC_METHTYPE: Self = Self::from_static(b"__objc_methtype");

    const fn from_static(s: &[u8]) -> Self {
        let mut buf = [0u8; 16];
        let mut i = 0;
        while i < s.len() && i < 16 {
            buf[i] = s[i];
            i += 1;
        }
        Self(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trimmed_bytes_stops_at_null() {
        let name = SegmentName::TEXT;
        assert_eq!(name.trimmed_bytes(), b"__TEXT");
    }

    #[test]
    fn full_16_bytes_no_null() {
        let name = SegmentName([b'A'; 16]);
        assert_eq!(name.trimmed_bytes().len(), 16);
    }

    #[test]
    fn eq_str() {
        assert_eq!(SegmentName::TEXT, "__TEXT");
        assert_ne!(SegmentName::TEXT, "__DATA");
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", SegmentName::LINKEDIT), "__LINKEDIT");
    }

    #[test]
    fn lossy_non_utf8() {
        let mut raw = [0u8; 16];
        raw[0] = 0xFF;
        raw[1] = 0xFE;
        let name = SegmentName(raw);
        // Should not panic, returns replacement chars
        let s = name.as_str_lossy();
        assert!(!s.is_empty());
    }
}
