use super::*;

const DYLD_CACHE_MAGIC_PREFIX: &[u8] = b"dyld_v1";
const HEADER_MIN_SIZE: usize = 32;
pub(super) const MAPPING_INFO_SIZE: usize = 32;
pub(super) const IMAGE_INFO_SIZE: usize = 32;
pub(super) const IMAGE_TEXT_INFO_SIZE: usize = 32;

// Header offsets for the modern imagesText fields (dyld_cache_format.h)
const IMAGES_TEXT_OFFSET_OFF: usize = 0x88;
const IMAGES_TEXT_COUNT_OFF: usize = 0x90;
// Minimum header size to contain the imagesText fields
const MODERN_HEADER_MIN: usize = IMAGES_TEXT_COUNT_OFF + 8;
const UUID_OFF: usize = 0x58;
const LOCAL_SYMBOLS_OFFSET_OFF: usize = 0x48;
const LOCAL_SYMBOLS_SIZE_OFF: usize = 0x50;
const SUBCACHE_ARRAY_OFFSET_OFF: usize = 0x188;
const SUBCACHE_ARRAY_COUNT_OFF: usize = 0x18c;
const SYMBOL_FILE_UUID_OFF: usize = 0x190;
const CACHE_SUBTYPE_OFF: usize = 0x1c8;
const IMAGES_OFFSET_OFF: usize = 0x1c0;
const IMAGES_COUNT_OFF: usize = 0x1c4;
const SUBCACHE_ENTRY_V1_SIZE: usize = 24;
const SUBCACHE_ENTRY_V2_SIZE: usize = 56;

/// Read-only index of a dyld shared cache file.
///
/// Supports enumeration and extraction of embedded Mach-O images without
/// modifying the cache. Extracted image slices can be fed directly into
/// [`crate::format::parse`] for normal inspection.
#[derive(Debug, Clone, Serialize)]
pub struct DyldCache {
    /// The header field.
    pub header: DyldCacheHeader,
    /// The mappings field.
    pub mappings: Vec<CacheMapping>,
    /// The images field.
    pub images: Vec<CacheImage>,
    /// Subcache files required by this cache, in header order.
    pub subcaches: Vec<SubCacheEntry>,
}

#[derive(Debug, Clone, Serialize)]
/// The DyldCacheHeader type.
pub struct DyldCacheHeader {
    /// The magic field.
    pub magic: String,
    /// The arch field.
    pub arch: String,
    /// The mapping_offset field.
    pub mapping_offset: u32,
    /// The mapping_count field.
    pub mapping_count: u32,
    /// Unique identifier of this cache family member.
    pub uuid: [u8; 16],
    /// File offset of the cache-level local-symbol store, when present.
    pub local_symbols_offset: u64,
    /// Size of the cache-level local-symbol store, when present.
    pub local_symbols_size: u64,
    /// UUID of a separate local-symbol cache, or all zeroes when absent.
    pub symbol_file_uuid: [u8; 16],
}

#[derive(Debug, Clone, Serialize)]
/// The CacheMapping type.
pub struct CacheMapping {
    /// The address field.
    pub address: u64,
    /// The size field.
    pub size: u64,
    /// The file_offset field.
    pub file_offset: u64,
    /// The max_prot field.
    pub max_prot: u32,
    /// The init_prot field.
    pub init_prot: u32,
}

#[derive(Debug, Clone, Serialize)]
/// The CacheImage type.
pub struct CacheImage {
    /// The address field.
    pub address: u64,
    /// The path field.
    pub path: String,
    /// The text_size field.
    pub text_size: u32,
}

/// One required dyld cache family member declared by the primary header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubCacheEntry {
    /// Expected UUID of the sibling cache file.
    pub uuid: [u8; 16],
    /// VM offset of the sibling from the primary cache base.
    pub cache_vm_offset: u64,
    /// Exact filename suffix, including the leading dot.
    pub file_suffix: String,
}

/// Parse a dyld shared cache from a memory-mapped buffer.
pub fn parse_dyld_cache(data: &[u8]) -> Result<DyldCache> {
    if data.len() < HEADER_MIN_SIZE {
        return Err(Error::format("file too small for dyld cache header"));
    }

    // Validate magic: first 7 bytes must be "dyld_v1"
    if &data[..7] != DYLD_CACHE_MAGIC_PREFIX {
        return Err(Error::format("not a dyld shared cache (bad magic)"));
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

    let mapping_offset = read_u32_le(data, 16)?;
    let mapping_count = read_u32_le(data, 20)?;
    let images_offset_old = read_u32_le(data, 24)?;
    let images_count_old = read_u32_le(data, 28)?;

    let uuid = if mapping_offset as usize > UUID_OFF {
        read_uuid(data, UUID_OFF)?
    } else {
        [0; 16]
    };
    let (local_symbols_offset, local_symbols_size) =
        if mapping_offset as usize > LOCAL_SYMBOLS_SIZE_OFF {
            (
                read_u64_le(data, LOCAL_SYMBOLS_OFFSET_OFF)?,
                read_u64_le(data, LOCAL_SYMBOLS_SIZE_OFF)?,
            )
        } else {
            (0, 0)
        };
    let symbol_file_uuid = if mapping_offset as usize > SYMBOL_FILE_UUID_OFF {
        read_uuid(data, SYMBOL_FILE_UUID_OFF)?
    } else {
        [0; 16]
    };

    let header = DyldCacheHeader {
        magic,
        arch,
        mapping_offset,
        mapping_count,
        uuid,
        local_symbols_offset,
        local_symbols_size,
        symbol_file_uuid,
    };

    // Parse mappings
    let mappings = parse_mappings(data, mapping_offset as usize, mapping_count as usize)?;

    // Parse images: current caches use the later images array, intermediate
    // caches use imagesText, and legacy caches use the original fields.
    let images = if images_count_old > 0 && images_offset_old > 0 {
        parse_images_old(data, images_offset_old as usize, images_count_old as usize)?
    } else if mapping_offset as usize > IMAGES_COUNT_OFF {
        let images_offset = read_u32_le(data, IMAGES_OFFSET_OFF)?;
        let images_count = read_u32_le(data, IMAGES_COUNT_OFF)?;
        if images_count > 0 && images_offset > 0 {
            parse_images_old(data, images_offset as usize, images_count as usize)?
        } else {
            parse_images_text_if_present(data)?
        }
    } else if data.len() >= MODERN_HEADER_MIN {
        parse_images_text_if_present(data)?
    } else {
        Vec::new()
    };

    let subcaches = parse_subcaches(data, mapping_offset as usize)?;

    Ok(DyldCache {
        header,
        mappings,
        images,
        subcaches,
    })
}

fn parse_images_text_if_present(data: &[u8]) -> Result<Vec<CacheImage>> {
    if data.len() < MODERN_HEADER_MIN {
        return Ok(Vec::new());
    }
    let images_text_offset = read_u64_le(data, IMAGES_TEXT_OFFSET_OFF)?;
    let images_text_count = read_u64_le(data, IMAGES_TEXT_COUNT_OFF)?;
    if images_text_count == 0 || images_text_offset == 0 {
        return Ok(Vec::new());
    }
    let off = usize::try_from(images_text_offset).map_err(|_| {
        Error::format(format!(
            "dyld cache imagesText offset {images_text_offset:#x} exceeds addressable memory"
        ))
    })?;
    let cnt = usize::try_from(images_text_count).map_err(|_| {
        Error::format(format!(
            "dyld cache imagesText count {images_text_count} exceeds addressable memory"
        ))
    })?;
    parse_images_text(data, off, cnt)
}

fn parse_subcaches(data: &[u8], header_size: usize) -> Result<Vec<SubCacheEntry>> {
    if header_size <= SUBCACHE_ARRAY_COUNT_OFF {
        return Ok(Vec::new());
    }
    let offset = read_u32_le(data, SUBCACHE_ARRAY_OFFSET_OFF)? as usize;
    let count = read_u32_le(data, SUBCACHE_ARRAY_COUNT_OFF)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    if offset == 0 {
        return Err(Error::format(
            "dyld cache declares subcaches with a zero table offset",
        ));
    }
    let has_suffix = header_size > CACHE_SUBTYPE_OFF;
    let stride = if has_suffix {
        SUBCACHE_ENTRY_V2_SIZE
    } else {
        SUBCACHE_ENTRY_V1_SIZE
    };
    validate_table_extent(data, offset, count, stride, "subcache")?;
    let mut result = Vec::with_capacity(count);
    let mut suffixes = BTreeSet::new();
    let mut uuids = BTreeSet::new();
    for index in 0..count {
        let entry_offset = offset
            .checked_add(
                index
                    .checked_mul(stride)
                    .ok_or_else(|| Error::format(format!("subcache[{index}] stride overflows")))?,
            )
            .ok_or_else(|| Error::format(format!("subcache[{index}] offset overflows")))?;
        let uuid = read_uuid(data, entry_offset)?;
        let cache_vm_offset = read_u64_le(data, entry_offset + 16)?;
        let file_suffix = if has_suffix {
            read_fixed_c_string(data, entry_offset + 24, 32, "subcache suffix")?
        } else {
            format!(".{}", index + 1)
        };
        if !file_suffix.starts_with('.') || file_suffix.len() < 2 {
            return Err(Error::format(format!(
                "subcache[{index}] has invalid suffix {file_suffix:?}"
            )));
        }
        if !suffixes.insert(file_suffix.clone()) {
            return Err(Error::format(format!(
                "duplicate subcache suffix {file_suffix:?}"
            )));
        }
        if !uuids.insert(uuid) {
            return Err(Error::format(format!(
                "duplicate subcache UUID {}",
                format_uuid(uuid)
            )));
        }
        result.push(SubCacheEntry {
            uuid,
            cache_vm_offset,
            file_suffix,
        });
    }
    Ok(result)
}

fn parse_mappings(data: &[u8], offset: usize, count: usize) -> Result<Vec<CacheMapping>> {
    validate_table_extent(data, offset, count, MAPPING_INFO_SIZE, "mapping")?;
    let mut mappings = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset
            .checked_add(
                i.checked_mul(MAPPING_INFO_SIZE)
                    .ok_or_else(|| Error::format(format!("mapping[{i}] stride overflows")))?,
            )
            .ok_or_else(|| Error::format(format!("mapping[{i}] offset overflows")))?;
        if off + MAPPING_INFO_SIZE > data.len() {
            return Err(Error::bounds(
                off as u64,
                MAPPING_INFO_SIZE as u64,
                data.len() as u64,
            ));
        }
        let mapping = CacheMapping {
            address: read_u64_le(data, off)?,
            size: read_u64_le(data, off + 8)?,
            file_offset: read_u64_le(data, off + 16)?,
            max_prot: read_u32_le(data, off + 24)?,
            init_prot: read_u32_le(data, off + 28)?,
        };
        if mapping.size == 0 {
            return Err(Error::format(format!("mapping[{i}] has zero size")));
        }
        let va_end = mapping.address.checked_add(mapping.size).ok_or_else(|| {
            Error::address(format!("mapping[{i}] virtual-address extent overflows"))
        })?;
        let file_end = mapping
            .file_offset
            .checked_add(mapping.size)
            .ok_or_else(|| Error::address(format!("mapping[{i}] file extent overflows")))?;
        if file_end > data.len() as u64 {
            return Err(Error::bounds(
                mapping.file_offset,
                mapping.size,
                data.len() as u64,
            ));
        }
        if mappings.iter().any(|prior: &CacheMapping| {
            let prior_end = prior.address + prior.size;
            mapping.address < prior_end && prior.address < va_end
        }) {
            return Err(Error::format(format!(
                "mapping[{i}] overlaps an earlier virtual-address mapping"
            )));
        }
        mappings.push(mapping);
    }
    Ok(mappings)
}

/// Parse the old-style dyld_cache_image_info entries.
/// Layout: address(u64) + modTime(u64) + inode(u64) + pathFileOffset(u32) + pad(u32)
fn parse_images_old(data: &[u8], offset: usize, count: usize) -> Result<Vec<CacheImage>> {
    validate_table_extent(data, offset, count, IMAGE_INFO_SIZE, "old image")?;
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset
            .checked_add(
                i.checked_mul(IMAGE_INFO_SIZE)
                    .ok_or_else(|| Error::format(format!("old image[{i}] stride overflows")))?,
            )
            .ok_or_else(|| Error::format(format!("old image[{i}] offset overflows")))?;
        if off + IMAGE_INFO_SIZE > data.len() {
            return Err(Error::bounds(
                off as u64,
                IMAGE_INFO_SIZE as u64,
                data.len() as u64,
            ));
        }
        let address = read_u64_le(data, off)?;
        let path_offset = read_u32_le(data, off + 24)?;
        let path = read_c_string(data, path_offset as usize, "old image path")?;

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
    validate_table_extent(data, offset, count, IMAGE_TEXT_INFO_SIZE, "imagesText")?;
    let mut images = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset
            .checked_add(
                i.checked_mul(IMAGE_TEXT_INFO_SIZE)
                    .ok_or_else(|| Error::format(format!("imagesText[{i}] stride overflows")))?,
            )
            .ok_or_else(|| Error::format(format!("imagesText[{i}] offset overflows")))?;
        if off + IMAGE_TEXT_INFO_SIZE > data.len() {
            return Err(Error::bounds(
                off as u64,
                IMAGE_TEXT_INFO_SIZE as u64,
                data.len() as u64,
            ));
        }
        // Skip uuid (16 bytes)
        let address = read_u64_le(data, off + 16)?;
        let text_size = read_u32_le(data, off + 24)?;
        let path_offset = read_u32_le(data, off + 28)?;
        let path = read_c_string(data, path_offset as usize, "imagesText path")?;

        images.push(CacheImage {
            address,
            path,
            text_size,
        });
    }
    Ok(images)
}

fn validate_table_extent(
    data: &[u8],
    offset: usize,
    count: usize,
    stride: usize,
    label: &str,
) -> Result<()> {
    let size = count
        .checked_mul(stride)
        .ok_or_else(|| Error::format(format!("{label} table size overflows")))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::format(format!("{label} table extent overflows")))?;
    if end > data.len() {
        return Err(Error::bounds(
            offset as u64,
            u64::try_from(size).unwrap_or(u64::MAX),
            data.len() as u64,
        ));
    }
    Ok(())
}
