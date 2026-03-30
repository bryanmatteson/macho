#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn read_u16(self, bytes: [u8; 2]) -> u16 {
        match self {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        }
    }

    pub fn read_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        }
    }

    pub fn read_u64(self, bytes: [u8; 8]) -> u64 {
        match self {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        }
    }

    pub fn read_i32(self, bytes: [u8; 4]) -> i32 {
        match self {
            Endian::Little => i32::from_le_bytes(bytes),
            Endian::Big => i32::from_be_bytes(bytes),
        }
    }

    /// Interpret a u32 whose bytes are in the given endianness as a native u32.
    ///
    /// When zerocopy reads a `u32` field from a byte slice, the resulting value
    /// has its bytes in file order. On a LE host reading a BE file, the value
    /// needs byte-swapping. This function handles that.
    pub fn interpret_u32(self, raw: u32) -> u32 {
        match self {
            Endian::Little => u32::from_le(raw),
            Endian::Big => u32::from_be(raw),
        }
    }

    pub fn interpret_u64(self, raw: u64) -> u64 {
        match self {
            Endian::Little => u64::from_le(raw),
            Endian::Big => u64::from_be(raw),
        }
    }

    pub fn interpret_i32(self, raw: i32) -> i32 {
        match self {
            Endian::Little => i32::from_le(raw),
            Endian::Big => i32::from_be(raw),
        }
    }

    pub fn interpret_u16(self, raw: u16) -> u16 {
        match self {
            Endian::Little => u16::from_le(raw),
            Endian::Big => u16::from_be(raw),
        }
    }

    // Encode helpers — inverse of interpret_*. Convert a native value to
    // the byte order used in the file, so it can be stored in a POD struct
    // field before writing.

    pub fn encode_u16(self, val: u16) -> u16 {
        match self {
            Endian::Little => val.to_le(),
            Endian::Big => val.to_be(),
        }
    }

    pub fn encode_u32(self, val: u32) -> u32 {
        match self {
            Endian::Little => val.to_le(),
            Endian::Big => val.to_be(),
        }
    }

    pub fn encode_u64(self, val: u64) -> u64 {
        match self {
            Endian::Little => val.to_le(),
            Endian::Big => val.to_be(),
        }
    }

    pub fn encode_i32(self, val: i32) -> i32 {
        match self {
            Endian::Little => val.to_le(),
            Endian::Big => val.to_be(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_le() {
        let val: u32 = 0xDEADBEEF;
        let bytes = val.to_le_bytes();
        assert_eq!(Endian::Little.read_u32(bytes), val);
    }

    #[test]
    fn round_trip_be() {
        let val: u32 = 0xDEADBEEF;
        let bytes = val.to_be_bytes();
        assert_eq!(Endian::Big.read_u32(bytes), val);
    }

    #[test]
    fn interpret_le_on_le_host() {
        let val: u32 = 0x12345678;
        let le_raw = u32::to_le(val);
        assert_eq!(Endian::Little.interpret_u32(le_raw), val);
    }

    #[test]
    fn interpret_be_on_le_host() {
        let val: u32 = 0x12345678;
        let be_raw = u32::to_be(val);
        assert_eq!(Endian::Big.interpret_u32(be_raw), val);
    }

    #[test]
    fn encode_interpret_round_trip() {
        let val: u32 = 0xDEADBEEF;
        for endian in [Endian::Little, Endian::Big] {
            let encoded = endian.encode_u32(val);
            assert_eq!(endian.interpret_u32(encoded), val);
        }
    }
}
