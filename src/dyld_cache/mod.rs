use serde::Serialize;

use crate::error::{Error, Result};

const DYLD_CACHE_MAGIC_PREFIX: &[u8] = b"dyld_v1";
const HEADER_MIN_SIZE: usize = 32;
const MAPPING_INFO_SIZE: usize = 32;
const IMAGE_INFO_SIZE: usize = 32;
const IMAGE_TEXT_INFO_SIZE: usize = 32;

// Header offsets for the modern imagesText fields (dyld_cache_format.h)
const IMAGES_TEXT_OFFSET_OFF: usize = 0x88;
const IMAGES_TEXT_COUNT_OFF: usize = 0x90;
// Minimum header size to contain the imagesText fields
const MODERN_HEADER_MIN: usize = IMAGES_TEXT_COUNT_OFF + 8;

/// Read-only index of a dyld shared cache file.
///
/// Supports enumeration and extraction of embedded Mach-O images without
/// modifying the cache. Extracted image slices can be fed directly into
/// [`crate::parse::parse`] for normal inspection.
#[derive(Debug, Clone, Serialize)]
pub struct DyldCache {
    pub header: DyldCacheHeader,
    pub mappings: Vec<CacheMapping>,
    pub images: Vec<CacheImage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DyldCacheHeader {
    pub magic: String,
    pub arch: String,
    pub mapping_offset: u32,
    pub mapping_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheImage {
    pub address: u64,
    pub path: String,
    pub text_size: u32,
}

/// Parse a dyld shared cache from a memory-mapped buffer.
pub fn parse_dyld_cache(data: &[u8]) -> Result<DyldCache> {
    if data.len() < HEADER_MIN_SIZE {
        return Err(Error::Format("file too small for dyld cache header".into()));
    }

    // Validate magic: first 7 bytes must be "dyld_v1"
    if &data[..7] != DYLD_CACHE_MAGIC_PREFIX {
        return Err(Error::Format("not a dyld shared cache (bad magic)".into()));
    }

    // The full 16-byte magic encodes the architecture, e.g. "dyld_v1  x86_64\0"
    let magic_bytes = &data[..16];
    let magic = std::str::from_utf8(magic_bytes)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();

    let arch = magic
        .strip_prefix("dyld_v1")
        .unwrap_or("")
        .trim()
        .to_string();

    let mapping_offset = read_u32_le(data, 16);
    let mapping_count = read_u32_le(data, 20);
    let images_offset_old = read_u32_le(data, 24);
    let images_count_old = read_u32_le(data, 28);

    let header = DyldCacheHeader {
        magic,
        arch,
        mapping_offset,
        mapping_count,
    };

    // Parse mappings
    let mappings = parse_mappings(data, mapping_offset as usize, mapping_count as usize)?;

    // Parse images: try old format first, fall back to modern imagesText format
    let images = if images_count_old > 0 && images_offset_old > 0 {
        parse_images_old(data, images_offset_old as usize, images_count_old as usize)?
    } else if data.len() >= MODERN_HEADER_MIN {
        let images_text_offset = read_u64_le(data, IMAGES_TEXT_OFFSET_OFF);
        let images_text_count = read_u64_le(data, IMAGES_TEXT_COUNT_OFF);
        if images_text_count > 0 && images_text_offset > 0 {
            parse_images_text(data, images_text_offset as usize, images_text_count as usize)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    Ok(DyldCache {
        header,
        mappings,
        images,
    })
}

fn parse_mappings(data: &[u8], offset: usize, count: usize) -> Result<Vec<CacheMapping>> {
    let mut mappings = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset + i * MAPPING_INFO_SIZE;
        if off + MAPPING_INFO_SIZE > data.len() {
            return Err(Error::Bounds {
                offset: off as u64,
                needed: MAPPING_INFO_SIZE as u64,
                available: data.len() as u64,
            });
        }
        mappings.push(CacheMapping {
            address: read_u64_le(data, off),
            size: read_u64_le(data, off + 8),
            file_offset: read_u64_le(data, off + 16),
            max_prot: read_u32_le(data, off + 24),
            init_prot: read_u32_le(data, off + 28),
        });
    }
    Ok(mappings)
}

/// Parse the old-style dyld_cache_image_info entries.
/// Layout: address(u64) + modTime(u64) + inode(u64) + pathFileOffset(u32) + pad(u32)
fn parse_images_old(data: &[u8], offset: usize, count: usize) -> Result<Vec<CacheImage>> {
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset + i * IMAGE_INFO_SIZE;
        if off + IMAGE_INFO_SIZE > data.len() {
            return Err(Error::Bounds {
                offset: off as u64,
                needed: IMAGE_INFO_SIZE as u64,
                available: data.len() as u64,
            });
        }
        let address = read_u64_le(data, off);
        let path_offset = read_u32_le(data, off + 24);
        let path = read_c_string(data, path_offset as usize);

        images.push(CacheImage {
            address,
            path,
            text_size: 0,
        });
    }
    Ok(images)
}

/// Parse the modern dyld_cache_image_text_info entries.
/// Layout: uuid(16) + loadAddress(u64) + textSegmentSize(u32) + pathOffset(u32)
fn parse_images_text(data: &[u8], offset: usize, count: usize) -> Result<Vec<CacheImage>> {
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset + i * IMAGE_TEXT_INFO_SIZE;
        if off + IMAGE_TEXT_INFO_SIZE > data.len() {
            return Err(Error::Bounds {
                offset: off as u64,
                needed: IMAGE_TEXT_INFO_SIZE as u64,
                available: data.len() as u64,
            });
        }
        // Skip uuid (16 bytes)
        let address = read_u64_le(data, off + 16);
        let text_size = read_u32_le(data, off + 24);
        let path_offset = read_u32_le(data, off + 28);
        let path = read_c_string(data, path_offset as usize);

        images.push(CacheImage {
            address,
            path,
            text_size,
        });
    }
    Ok(images)
}

impl DyldCache {
    /// List all embedded images.
    pub fn images(&self) -> &[CacheImage] {
        &self.images
    }

    /// List cache memory mappings.
    pub fn mappings(&self) -> &[CacheMapping] {
        &self.mappings
    }

    /// Architecture string extracted from the magic field.
    pub fn arch(&self) -> &str {
        &self.header.arch
    }

    /// Convert a virtual address to a file offset using the mapping table.
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        for m in &self.mappings {
            if va >= m.address && va < m.address + m.size {
                return Some(m.file_offset + (va - m.address));
            }
        }
        None
    }

    /// Extract the Mach-O bytes for the image at the given index.
    ///
    /// Returns a slice into the original cache data that starts at the image's
    /// mapped location. When the image has a known `text_size`, that is used
    /// as the slice length. Otherwise the slice extends to the next image
    /// boundary or mapping end. The returned slice can be passed to
    /// [`crate::parse::parse`].
    pub fn extract_image<'data>(&self, index: usize, data: &'data [u8]) -> Result<&'data [u8]> {
        let image = self
            .images
            .get(index)
            .ok_or_else(|| Error::Format(format!("image index {index} out of range")))?;

        let file_offset = self.va_to_file_offset(image.address).ok_or_else(|| {
            Error::Address(format!(
                "image VA {:#x} not in any mapping",
                image.address
            ))
        })?;

        let start = file_offset as usize;
        if start >= data.len() {
            return Err(Error::Bounds {
                offset: file_offset,
                needed: 1,
                available: data.len() as u64,
            });
        }

        // If we know the text segment size, use it as the extraction length
        if image.text_size > 0 {
            let end = (start + image.text_size as usize).min(data.len());
            return Ok(&data[start..end]);
        }

        // Fallback: find the next image boundary or mapping end
        let mapping_end = self
            .mappings
            .iter()
            .find(|m| file_offset >= m.file_offset && file_offset < m.file_offset + m.size)
            .map(|m| (m.file_offset + m.size) as usize)
            .unwrap_or(data.len());

        let mut next_offset = mapping_end;
        for other in &self.images {
            if let Some(other_fo) = self.va_to_file_offset(other.address) {
                let other_start = other_fo as usize;
                if other_start > start && other_start < next_offset {
                    next_offset = other_start;
                }
            }
        }

        let end = next_offset.min(data.len());
        Ok(&data[start..end])
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

fn read_c_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_cache(arch: &str) -> Vec<u8> {
        // Build a minimal old-format dyld cache with 1 mapping and 1 image
        let mut magic = [0u8; 16];
        let prefix = format!("dyld_v1  {arch}");
        let bytes = prefix.as_bytes();
        let len = bytes.len().min(15);
        magic[..len].copy_from_slice(&bytes[..len]);

        let mapping_offset: u32 = 32; // right after header
        let mapping_count: u32 = 1;
        let images_offset: u32 = mapping_offset + MAPPING_INFO_SIZE as u32;
        let images_count: u32 = 1;

        let image_va: u64 = 0x1_0000_0000;
        let image_file_offset: u64 = 4096;

        // Path will be placed after the image info
        let path_offset: u32 = images_offset + IMAGE_INFO_SIZE as u32;
        let path = b"/usr/lib/libSystem.B.dylib\0";

        let total_size = path_offset as usize + path.len() + image_file_offset as usize + 4096;
        let mut data = vec![0u8; total_size];

        // Header
        data[..16].copy_from_slice(&magic);
        data[16..20].copy_from_slice(&mapping_offset.to_le_bytes());
        data[20..24].copy_from_slice(&mapping_count.to_le_bytes());
        data[24..28].copy_from_slice(&images_offset.to_le_bytes());
        data[28..32].copy_from_slice(&images_count.to_le_bytes());

        // Mapping: covers the image region
        let m_off = mapping_offset as usize;
        data[m_off..m_off + 8].copy_from_slice(&image_va.to_le_bytes());
        data[m_off + 8..m_off + 16].copy_from_slice(&4096u64.to_le_bytes());
        data[m_off + 16..m_off + 24].copy_from_slice(&image_file_offset.to_le_bytes());
        data[m_off + 24..m_off + 28].copy_from_slice(&5u32.to_le_bytes());
        data[m_off + 28..m_off + 32].copy_from_slice(&5u32.to_le_bytes());

        // Image info (old format: address + modTime + inode + pathOffset + pad)
        let i_off = images_offset as usize;
        data[i_off..i_off + 8].copy_from_slice(&image_va.to_le_bytes());
        data[i_off + 8..i_off + 16].copy_from_slice(&0u64.to_le_bytes());
        data[i_off + 16..i_off + 24].copy_from_slice(&0u64.to_le_bytes());
        data[i_off + 24..i_off + 28].copy_from_slice(&path_offset.to_le_bytes());

        // Path string
        let p_off = path_offset as usize;
        data[p_off..p_off + path.len()].copy_from_slice(path);

        data
    }

    fn make_modern_cache(arch: &str) -> Vec<u8> {
        // Build a minimal modern-format cache (old image fields zeroed, uses imagesText)
        let mut magic = [0u8; 16];
        let prefix = format!("dyld_v1  {arch}");
        let bytes = prefix.as_bytes();
        let len = bytes.len().min(15);
        magic[..len].copy_from_slice(&bytes[..len]);

        let mapping_offset: u32 = 0x98; // after header (needs room for imagesText fields)
        let mapping_count: u32 = 1;

        let image_va: u64 = 0x1_8000_0000;
        let image_file_offset: u64 = 4096;

        // imagesText entries start after the mapping
        let images_text_offset: u64 = (mapping_offset as u64) + MAPPING_INFO_SIZE as u64;
        let images_text_count: u64 = 1;

        // Path after the image text info
        let path_offset: u32 = (images_text_offset as u32) + IMAGE_TEXT_INFO_SIZE as u32;
        let path = b"/usr/lib/libSystem.B.dylib\0";

        let total_size = path_offset as usize + path.len() + image_file_offset as usize + 4096;
        let mut data = vec![0u8; total_size];

        // Header
        data[..16].copy_from_slice(&magic);
        data[16..20].copy_from_slice(&mapping_offset.to_le_bytes());
        data[20..24].copy_from_slice(&mapping_count.to_le_bytes());
        // Old image fields: zero
        data[24..28].copy_from_slice(&0u32.to_le_bytes());
        data[28..32].copy_from_slice(&0u32.to_le_bytes());

        // imagesText fields at offsets 0x88/0x90
        data[0x88..0x90].copy_from_slice(&images_text_offset.to_le_bytes());
        data[0x90..0x98].copy_from_slice(&images_text_count.to_le_bytes());

        // Mapping
        let m_off = mapping_offset as usize;
        data[m_off..m_off + 8].copy_from_slice(&image_va.to_le_bytes());
        data[m_off + 8..m_off + 16].copy_from_slice(&0x100000u64.to_le_bytes());
        data[m_off + 16..m_off + 24].copy_from_slice(&image_file_offset.to_le_bytes());
        data[m_off + 24..m_off + 28].copy_from_slice(&5u32.to_le_bytes());
        data[m_off + 28..m_off + 32].copy_from_slice(&5u32.to_le_bytes());

        // Image text info: uuid(16) + loadAddress(8) + textSegmentSize(4) + pathOffset(4)
        let i_off = images_text_offset as usize;
        // uuid: leave as zeros
        data[i_off + 16..i_off + 24].copy_from_slice(&image_va.to_le_bytes());
        data[i_off + 24..i_off + 28].copy_from_slice(&0x50000u32.to_le_bytes()); // text_size
        data[i_off + 28..i_off + 32].copy_from_slice(&path_offset.to_le_bytes());

        // Path string
        let p_off = path_offset as usize;
        data[p_off..p_off + path.len()].copy_from_slice(path);

        data
    }

    #[test]
    fn parse_old_format_cache() {
        let data = make_minimal_cache("arm64e");
        let cache = parse_dyld_cache(&data).expect("failed to parse");
        assert_eq!(cache.arch(), "arm64e");
        assert_eq!(cache.mappings().len(), 1);
        assert_eq!(cache.images().len(), 1);
        assert_eq!(cache.images()[0].path, "/usr/lib/libSystem.B.dylib");
    }

    #[test]
    fn parse_modern_format_cache() {
        let data = make_modern_cache("arm64e");
        let cache = parse_dyld_cache(&data).expect("failed to parse");
        assert_eq!(cache.arch(), "arm64e");
        assert_eq!(cache.mappings().len(), 1);
        assert_eq!(cache.images().len(), 1);
        assert_eq!(cache.images()[0].path, "/usr/lib/libSystem.B.dylib");
        assert_eq!(cache.images()[0].text_size, 0x50000);
        assert_eq!(cache.images()[0].address, 0x1_8000_0000);
    }

    #[test]
    fn va_to_file_offset_works() {
        let data = make_minimal_cache("x86_64");
        let cache = parse_dyld_cache(&data).expect("failed to parse");
        let fo = cache.va_to_file_offset(0x1_0000_0000);
        assert_eq!(fo, Some(4096));
        assert_eq!(cache.va_to_file_offset(0x1_0000_0100), Some(4096 + 0x100));
        assert_eq!(cache.va_to_file_offset(0xDEAD), None);
    }

    #[test]
    fn extract_image_returns_slice() {
        let data = make_minimal_cache("arm64e");
        let cache = parse_dyld_cache(&data).expect("failed to parse");
        let slice = cache.extract_image(0, &data).expect("failed to extract");
        assert!(!slice.is_empty());
    }

    #[test]
    fn extract_modern_image_uses_text_size() {
        let data = make_modern_cache("arm64e");
        let cache = parse_dyld_cache(&data).expect("failed to parse");
        let slice = cache.extract_image(0, &data).expect("failed to extract");
        // text_size is 0x50000, but data may be smaller — should be clamped
        assert!(!slice.is_empty());
    }

    #[test]
    fn bad_magic_rejected() {
        let data = b"not a dyld cache file at all!!";
        assert!(parse_dyld_cache(data).is_err());
    }

    #[test]
    fn too_small_rejected() {
        let data = b"dyld_v1";
        assert!(parse_dyld_cache(data).is_err());
    }
}
