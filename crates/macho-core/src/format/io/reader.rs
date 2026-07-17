use crate::error::{Error, Result};
use crate::format::io::endian::Endian;

/// The BinaryReader type.
pub struct BinaryReader<'data> {
    data: &'data [u8],
    endian: Endian,
    offset: usize,
}

impl<'data> BinaryReader<'data> {
    /// Performs new.
    pub fn new(data: &'data [u8], endian: Endian) -> Self {
        Self {
            data,
            endian,
            offset: 0,
        }
    }

    /// Performs at_offset.
    pub fn at_offset(data: &'data [u8], endian: Endian, offset: usize) -> Self {
        Self {
            data,
            endian,
            offset,
        }
    }

    /// Performs offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Performs remaining.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Performs endian.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Performs seek.
    pub fn seek(&mut self, offset: usize) {
        self.offset = offset;
    }

    /// Performs skip.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        let new_offset = self
            .offset
            .checked_add(n)
            .ok_or_else(|| self.bounds_err(n))?;
        if new_offset > self.data.len() {
            return Err(self.bounds_err(n));
        }
        self.offset = new_offset;
        Ok(())
    }

    /// Performs read_u8.
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            return Err(self.bounds_err(1));
        }
        let val = self.data[self.offset];
        self.offset += 1;
        Ok(val)
    }

    /// Performs read_u16.
    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_array::<2>()?;
        Ok(self.endian.read_u16(bytes))
    }

    /// Performs read_u32.
    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_array::<4>()?;
        Ok(self.endian.read_u32(bytes))
    }

    /// Performs read_u64.
    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read_array::<8>()?;
        Ok(self.endian.read_u64(bytes))
    }

    /// Performs read_i32.
    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_array::<4>()?;
        Ok(self.endian.read_i32(bytes))
    }

    /// Performs read_bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'data [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| self.bounds_err(n))?;
        if end > self.data.len() {
            return Err(self.bounds_err(n));
        }
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    /// Performs read_fixed_array.
    pub fn read_fixed_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.read_bytes(N)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        Ok(arr)
    }

    /// Read a null-terminated C string starting at `abs_offset`.
    /// Does not advance the cursor.
    pub fn read_c_string_at(&self, abs_offset: usize, max_len: usize) -> Result<&'data [u8]> {
        if abs_offset >= self.data.len() {
            return Err(Error::bounds(abs_offset as u64, 1, self.data.len() as u64));
        }
        let limit = (abs_offset + max_len).min(self.data.len());
        let slice = &self.data[abs_offset..limit];
        match slice.iter().position(|&b| b == 0) {
            Some(pos) => Ok(&slice[..pos]),
            None => Ok(slice),
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| self.bounds_err(N))?;
        if end > self.data.len() {
            return Err(self.bounds_err(N));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.data[self.offset..end]);
        self.offset = end;
        Ok(arr)
    }

    fn bounds_err(&self, needed: usize) -> Error {
        Error::bounds(self.offset as u64, needed as u64, self.data.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_reads() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut r = BinaryReader::new(&data, Endian::Little);
        assert_eq!(r.read_u32().unwrap(), 0x04030201);
        assert_eq!(r.read_u32().unwrap(), 0x08070605);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn bounds_error() {
        let data = [0u8; 2];
        let mut r = BinaryReader::new(&data, Endian::Little);
        assert!(r.read_u32().is_err());
    }

    #[test]
    fn c_string() {
        let data = b"hello\0world\0";
        let r = BinaryReader::new(data, Endian::Little);
        assert_eq!(r.read_c_string_at(0, 20).unwrap(), b"hello");
        assert_eq!(r.read_c_string_at(6, 20).unwrap(), b"world");
    }

    #[test]
    fn big_endian() {
        let data = 0xDEADBEEFu32.to_be_bytes();
        let mut r = BinaryReader::new(&data, Endian::Big);
        assert_eq!(r.read_u32().unwrap(), 0xDEADBEEF);
    }
}
