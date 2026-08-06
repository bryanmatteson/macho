use crate::metadata::dyld::error::{Error, Result};

/// A cursor for reading ULEB128 and SLEB128 values from a byte slice.
pub struct LebReader<'data> {
    data: &'data [u8],
    pos: usize,
}

impl<'data> LebReader<'data> {
    /// Performs new.
    pub fn new(data: &'data [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Performs at.
    pub fn at(data: &'data [u8], pos: usize) -> Self {
        Self { data, pos }
    }

    /// Performs pos.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Performs remaining.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Performs read_u8.
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::format("unexpected end of data reading byte"));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Performs peek_u8.
    pub fn peek_u8(&self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(Error::format("unexpected end of data peeking byte"));
        }
        Ok(self.data[self.pos])
    }

    /// Performs read_uleb128.
    pub fn read_uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if self.pos >= self.data.len() {
                return Err(Error::format("unexpected end of data in ULEB128"));
            }
            let byte = self.data[self.pos];
            self.pos += 1;

            let val = (byte & 0x7F) as u64;
            if shift >= 64 || (shift == 63 && val > 1) {
                return Err(Error::format("ULEB128 exceeds u64"));
            }
            result |= val << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Performs read_sleb128.
    pub fn read_sleb128(&mut self) -> Result<i64> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut byte;
        loop {
            if self.pos >= self.data.len() {
                return Err(Error::format("unexpected end of data in SLEB128"));
            }
            byte = self.data[self.pos];
            self.pos += 1;

            result |= ((byte & 0x7F) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift > 70 {
                return Err(Error::format("SLEB128 too large"));
            }
        }
        // Sign extend
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }
        Ok(result)
    }

    /// Read a null-terminated string, advancing past the null byte.
    pub fn read_string(&mut self) -> Result<&'data str> {
        let start = self.pos;
        while self.pos < self.data.len() {
            if self.data[self.pos] == 0 {
                let s = std::str::from_utf8(&self.data[start..self.pos]).map_err(|e| {
                    Error::format(format!("invalid UTF-8 in string at offset {start}: {e}"))
                })?;
                self.pos += 1; // skip null
                return Ok(s);
            }
            self.pos += 1;
        }
        Err(Error::format("unterminated string"))
    }

    /// Performs skip.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        let new = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::format("skip overflow"))?;
        if new > self.data.len() {
            return Err(Error::format("skip past end of data"));
        }
        self.pos = new;
        Ok(())
    }

    /// Performs slice_from.
    pub fn slice_from(&self, start: usize) -> &'data [u8] {
        &self.data[start..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb128_single_byte() {
        let mut r = LebReader::new(&[0x05]);
        assert_eq!(r.read_uleb128().unwrap(), 5);
    }

    #[test]
    fn uleb128_multi_byte() {
        // 624485 = 0x98765 -> [0xE5, 0x8E, 0x26]
        let mut r = LebReader::new(&[0xE5, 0x8E, 0x26]);
        assert_eq!(r.read_uleb128().unwrap(), 624485);
    }

    #[test]
    fn uleb128_zero() {
        let mut r = LebReader::new(&[0x00]);
        assert_eq!(r.read_uleb128().unwrap(), 0);
    }

    #[test]
    fn sleb128_positive() {
        let mut r = LebReader::new(&[0x05]);
        assert_eq!(r.read_sleb128().unwrap(), 5);
    }

    #[test]
    fn sleb128_negative() {
        // -5 in SLEB128: [0x7B]
        let mut r = LebReader::new(&[0x7B]);
        assert_eq!(r.read_sleb128().unwrap(), -5);
    }

    #[test]
    fn sleb128_negative_multi() {
        // -123456 in SLEB128: [0xC0, 0xBB, 0x78]
        let mut r = LebReader::new(&[0xC0, 0xBB, 0x78]);
        assert_eq!(r.read_sleb128().unwrap(), -123456);
    }

    #[test]
    fn string_reading() {
        let data = b"hello\0world\0";
        let mut r = LebReader::new(data);
        assert_eq!(r.read_string().unwrap(), "hello");
        assert_eq!(r.read_string().unwrap(), "world");
    }

    #[test]
    fn truncated_uleb128() {
        let mut r = LebReader::new(&[0x80]); // continuation bit set, no more bytes
        assert!(r.read_uleb128().is_err());
    }

    #[test]
    fn overflowing_uleb128_rejects() {
        let mut r = LebReader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02]);
        assert!(r.read_uleb128().is_err());
    }
}
