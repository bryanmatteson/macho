use super::*;

const DYLD_CACHE_MAGIC_FAMILY_PREFIX: &[u8] = b"dyld_v";
const HEADER_MIN_SIZE: usize = 32;
const MAX_APPLE_CACHE_HEADER_SIZE: usize = 1024;
pub(super) const MAPPING_INFO_SIZE: usize = 32;
pub(super) const MAPPING_AND_SLIDE_INFO_SIZE: usize = 56;
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
const MAPPING_WITH_SLIDE_OFFSET_OFF: usize = 0x138;
const MAPPING_WITH_SLIDE_COUNT_OFF: usize = 0x13c;
const SUBCACHE_ARRAY_OFFSET_OFF: usize = 0x188;
const SUBCACHE_ARRAY_COUNT_OFF: usize = 0x18c;
const SYMBOL_FILE_UUID_OFF: usize = 0x190;
const CACHE_SUBTYPE_OFF: usize = 0x1c8;
const IMAGES_OFFSET_OFF: usize = 0x1c0;
const IMAGES_COUNT_OFF: usize = 0x1c4;
const TPRO_MAPPINGS_OFFSET_OFF: usize = 0x200;
const TPRO_MAPPINGS_COUNT_OFF: usize = 0x204;
const TPRO_MAPPING_INFO_SIZE: usize = 16;
const SUBCACHE_ENTRY_V1_SIZE: usize = 24;
const SUBCACHE_ENTRY_V2_SIZE: usize = 56;
const LOCAL_SYMBOLS_INFO_SIZE: usize = 24;
const LOCAL_SYMBOLS_ENTRY_V1_SIZE: usize = 12;
const LOCAL_SYMBOLS_ENTRY_V2_SIZE: usize = 16;

/// Published dyld shared-cache magic generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DyldCacheFormatVersion {
    /// Historical monolithic caches, including big-endian PowerPC families.
    V0,
    /// Current cache format, including monolithic and split-cache families.
    V1,
}

/// Struct generation selected using Apple's header-field presence rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DyldCacheHeaderGeneration {
    /// Header predates the subcache array.
    Legacy,
    /// Header contains `dyld_subcache_entry_v1` records with numeric suffixes.
    SubcacheV1,
    /// Header contains suffix-bearing `dyld_subcache_entry` records.
    SubcacheV2,
}

/// Read-only index of a dyld shared cache file.
///
/// Supports enumeration and extraction of embedded Mach-O images without
/// modifying the cache. Extracted image slices can be fed directly into
/// [`crate::dyld_cache::format::parse`] for normal inspection.
#[derive(Debug, Clone, Serialize)]
pub struct DyldCache {
    /// The header field.
    pub header: DyldCacheHeader,
    /// The mappings field.
    pub mappings: Vec<CacheMapping>,
    /// Thread-protected ranges declared by current cache headers.
    pub tpro_mappings: Vec<CacheTproMapping>,
    /// The images field.
    pub images: Vec<CacheImage>,
    /// Subcache files required by this cache, in header order.
    pub subcaches: Vec<SubCacheEntry>,
    /// Validated cache-level local-symbol store, when embedded in this member.
    pub local_symbols: Option<CacheLocalSymbolsInfo>,
}

#[derive(Debug, Clone, Serialize)]
/// The DyldCacheHeader type.
pub struct DyldCacheHeader {
    /// The magic field.
    pub magic: String,
    /// Published magic generation.
    pub format_version: DyldCacheFormatVersion,
    /// Numeric byte order selected from the exact magic architecture.
    pub byte_order: DyldCacheByteOrder,
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
    /// Authoritative Apple header/subcache struct generation.
    pub generation: DyldCacheHeaderGeneration,
}

/// Validated metadata for an embedded dyld cache local-symbol store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheLocalSymbolsInfo {
    /// Absolute file offset of the local-symbol chunk.
    pub file_offset: u64,
    /// Byte length of the complete local-symbol chunk.
    pub file_size: u64,
    /// Relative offset of the nlist array in the chunk.
    pub nlist_offset: u32,
    /// Number of nlist entries.
    pub nlist_count: u32,
    /// Relative offset of the string pool in the chunk.
    pub strings_offset: u32,
    /// Byte length of the string pool.
    pub strings_size: u32,
    /// Relative offset of per-image local-symbol entries in the chunk.
    pub entries_offset: u32,
    /// Parsed per-image local-symbol entries.
    pub entries: Vec<CacheLocalSymbolsEntry>,
}

/// One per-image range in a cache-level local-symbol store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheLocalSymbolsEntry {
    /// Legacy file offset or modern VM offset of the image from the cache base.
    pub dylib_offset: u64,
    /// First nlist index owned by the image.
    pub nlist_start_index: u32,
    /// Number of local nlist entries owned by the image.
    pub nlist_count: u32,
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
    /// File offset of slide metadata for this mapping, when declared.
    pub slide_info_file_offset: Option<u64>,
    /// Byte length of slide metadata for this mapping, when declared.
    pub slide_info_file_size: Option<u64>,
    /// Raw `DYLD_CACHE_MAPPING_*` flags from the extended mapping table.
    pub flags: Option<u64>,
}

/// One thread-protected cache range from `dyld_cache_tpro_mapping_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CacheTproMapping {
    /// Unslid virtual address of the protected range.
    pub address: u64,
    /// Byte length of the protected range.
    pub size: u64,
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

    // The full 16-byte magic encodes both the published layout generation and
    // architecture, for example `dyld_v0     ppc` or `dyld_v1  x86_64`.
    let magic_bytes = &data[..16];
    let magic = std::str::from_utf8(magic_bytes)
        .map_err(|_| Error::format("dyld cache magic is not UTF-8"))?
        .trim_end_matches('\0')
        .to_string();
    let (format_version, arch) = parse_magic(&magic)?;
    let byte_order = byte_order_for_arch(&arch)?;

    let mapping_offset = read_u32(data, 16, byte_order)?;
    let mapping_count = read_u32(data, 20, byte_order)?;
    let images_offset_old = read_u32(data, 24, byte_order)?;
    let images_count_old = read_u32(data, 28, byte_order)?;

    let header_size = mapping_offset as usize;
    if header_size < HEADER_MIN_SIZE || !header_size.is_multiple_of(8) {
        return Err(Error::format(format!(
            "dyld cache mapping offset {header_size:#x} is not a valid aligned header extent"
        )));
    }
    if header_size > MAX_APPLE_CACHE_HEADER_SIZE {
        return Err(Error::unsupported(format!(
            "dyld cache header extent {header_size:#x} exceeds Apple's supported 1024-byte header envelope"
        )));
    }
    if header_size > data.len() {
        return Err(Error::bounds(0, mapping_offset as u64, data.len() as u64));
    }

    let generation = if !field_present(header_size, SUBCACHE_ARRAY_COUNT_OFF, 4) {
        DyldCacheHeaderGeneration::Legacy
    } else if !field_present(header_size, CACHE_SUBTYPE_OFF, 4) {
        DyldCacheHeaderGeneration::SubcacheV1
    } else {
        DyldCacheHeaderGeneration::SubcacheV2
    };

    let uuid = if field_present(header_size, UUID_OFF, 16) {
        read_uuid(data, UUID_OFF)?
    } else {
        [0; 16]
    };
    let (local_symbols_offset, local_symbols_size) =
        if field_present(header_size, LOCAL_SYMBOLS_SIZE_OFF, 8) {
            (
                read_u64(data, LOCAL_SYMBOLS_OFFSET_OFF, byte_order)?,
                read_u64(data, LOCAL_SYMBOLS_SIZE_OFF, byte_order)?,
            )
        } else {
            (0, 0)
        };
    let symbol_file_uuid = if field_present(header_size, SYMBOL_FILE_UUID_OFF, 16) {
        read_uuid(data, SYMBOL_FILE_UUID_OFF)?
    } else {
        [0; 16]
    };

    let header = DyldCacheHeader {
        magic,
        format_version,
        byte_order,
        arch,
        mapping_offset,
        mapping_count,
        uuid,
        local_symbols_offset,
        local_symbols_size,
        symbol_file_uuid,
        generation,
    };

    let mappings = parse_mappings_for_header(
        data,
        header_size,
        mapping_offset as usize,
        mapping_count as usize,
        byte_order,
    )?;
    let tpro_mappings = parse_tpro_mappings(data, header_size, byte_order)?;

    // Apple's reader selects the relocated image array from the header-layout
    // boundary, never from whether the obsolete fields happen to be nonzero.
    // `imagesText` remains a useful auxiliary index for layouts whose selected
    // image array is genuinely empty.
    let (images_offset, images_count, image_array_name) = if header_size >= IMAGES_COUNT_OFF {
        (
            read_u32(data, IMAGES_OFFSET_OFF, byte_order)?,
            read_u32(data, IMAGES_COUNT_OFF, byte_order)?,
            "current image",
        )
    } else {
        (images_offset_old, images_count_old, "legacy image")
    };
    let images = if images_offset == 0 && images_count == 0 {
        parse_images_text_if_present(data, header_size, byte_order)?
    } else if images_offset == 0 || images_count == 0 {
        return Err(Error::format(format!(
            "dyld cache {image_array_name} offset and count must both be zero or nonzero"
        )));
    } else {
        parse_images_old(
            data,
            images_offset as usize,
            images_count as usize,
            byte_order,
        )?
    };

    let subcaches = parse_subcaches(data, generation, byte_order)?;
    if symbol_file_uuid != [0; 16]
        && subcaches
            .iter()
            .any(|entry| entry.file_suffix == ".symbols")
    {
        return Err(Error::format(
            "dyld cache declares .symbols both as a subcache and through symbolFileUUID",
        ));
    }
    let local_symbols = parse_local_symbols(
        data,
        local_symbols_offset,
        local_symbols_size,
        header_size >= SYMBOL_FILE_UUID_OFF,
        &header.arch,
        byte_order,
    )?;
    if symbol_file_uuid != [0; 16] && local_symbols.is_some() {
        return Err(Error::format(
            "dyld cache declares both embedded and separate local-symbol stores",
        ));
    }

    Ok(DyldCache {
        header,
        mappings,
        tpro_mappings,
        images,
        subcaches,
        local_symbols,
    })
}

fn parse_images_text_if_present(
    data: &[u8],
    header_size: usize,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<CacheImage>> {
    if header_size < MODERN_HEADER_MIN {
        return Ok(Vec::new());
    }
    let images_text_offset = read_u64(data, IMAGES_TEXT_OFFSET_OFF, byte_order)?;
    let images_text_count = read_u64(data, IMAGES_TEXT_COUNT_OFF, byte_order)?;
    if images_text_count == 0 && images_text_offset == 0 {
        return Ok(Vec::new());
    }
    if images_text_count == 0 || images_text_offset == 0 {
        return Err(Error::format(
            "dyld cache imagesText offset and count must both be zero or nonzero",
        ));
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
    parse_images_text(data, off, cnt, byte_order)
}

fn parse_subcaches(
    data: &[u8],
    generation: DyldCacheHeaderGeneration,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<SubCacheEntry>> {
    if generation == DyldCacheHeaderGeneration::Legacy {
        return Ok(Vec::new());
    }
    let offset = read_u32(data, SUBCACHE_ARRAY_OFFSET_OFF, byte_order)? as usize;
    let count = read_u32(data, SUBCACHE_ARRAY_COUNT_OFF, byte_order)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    if offset == 0 {
        return Err(Error::format(
            "dyld cache declares subcaches with a zero table offset",
        ));
    }
    let has_suffix = generation == DyldCacheHeaderGeneration::SubcacheV2;
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
        if uuid == [0; 16] {
            return Err(Error::format(format!("subcache[{index}] has a zero UUID")));
        }
        let cache_vm_offset = read_u64(data, entry_offset + 16, byte_order)?;
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

fn parse_local_symbols(
    data: &[u8],
    file_offset: u64,
    file_size: u64,
    uses_64_bit_dylib_offsets: bool,
    arch: &str,
    byte_order: DyldCacheByteOrder,
) -> Result<Option<CacheLocalSymbolsInfo>> {
    if file_offset == 0 && file_size == 0 {
        return Ok(None);
    }
    if file_offset == 0 || file_size == 0 {
        return Err(Error::format(
            "dyld cache local-symbol offset and size must both be zero or nonzero",
        ));
    }
    let start = usize::try_from(file_offset)
        .map_err(|_| Error::unsupported("local-symbol offset exceeds host limits"))?;
    let size = usize::try_from(file_size)
        .map_err(|_| Error::unsupported("local-symbol size exceeds host limits"))?;
    validate_table_extent(data, start, 1, size, "local-symbol chunk")?;
    if size < LOCAL_SYMBOLS_INFO_SIZE {
        return Err(Error::format(
            "local-symbol chunk is smaller than its header",
        ));
    }
    let chunk = &data[start..start + size];
    let nlist_offset = read_u32(chunk, 0, byte_order)?;
    let nlist_count = read_u32(chunk, 4, byte_order)?;
    let strings_offset = read_u32(chunk, 8, byte_order)?;
    let strings_size = read_u32(chunk, 12, byte_order)?;
    let entries_offset = read_u32(chunk, 16, byte_order)?;
    let entries_count = read_u32(chunk, 20, byte_order)?;
    let nlist_stride = nlist_stride_for_arch(arch)?;
    let nlist_range = table_range(
        chunk,
        nlist_offset as usize,
        nlist_count as usize,
        nlist_stride,
        "local nlist",
    )?;
    let strings_range = table_range(
        chunk,
        strings_offset as usize,
        strings_size as usize,
        1,
        "local string",
    )?;
    let entry_stride = if uses_64_bit_dylib_offsets {
        LOCAL_SYMBOLS_ENTRY_V2_SIZE
    } else {
        LOCAL_SYMBOLS_ENTRY_V1_SIZE
    };
    let entries_range = table_range(
        chunk,
        entries_offset as usize,
        entries_count as usize,
        entry_stride,
        "local-symbol entry",
    )?;
    for (label, range) in [
        ("local nlist", &nlist_range),
        ("local string", &strings_range),
        ("local-symbol entry", &entries_range),
    ] {
        if !range.is_empty() && range.start < LOCAL_SYMBOLS_INFO_SIZE {
            return Err(Error::format(format!(
                "{label} table overlaps the local-symbol header"
            )));
        }
    }
    for (left_label, left, right_label, right) in [
        ("local nlist", &nlist_range, "local string", &strings_range),
        (
            "local nlist",
            &nlist_range,
            "local-symbol entry",
            &entries_range,
        ),
        (
            "local string",
            &strings_range,
            "local-symbol entry",
            &entries_range,
        ),
    ] {
        if ranges_overlap(left, right) {
            return Err(Error::format(format!(
                "{left_label} and {right_label} tables overlap"
            )));
        }
    }
    let strings = &chunk[strings_range.clone()];
    for index in 0..nlist_count as usize {
        let offset = nlist_range.start + index * nlist_stride;
        let string_index = read_u32(chunk, offset, byte_order)? as usize;
        if string_index >= strings.len() {
            return Err(Error::format(format!(
                "local nlist[{index}] string index {string_index:#x} exceeds string pool size {:#x}",
                strings.len()
            )));
        }
        if !strings[string_index..].contains(&0) {
            return Err(Error::format(format!(
                "local nlist[{index}] name is not NUL-terminated in the string pool"
            )));
        }
    }
    let mut entries = Vec::with_capacity(entries_count as usize);
    let mut dylib_offsets = BTreeSet::new();
    let mut nlist_ranges = Vec::<Range<u32>>::new();
    for index in 0..entries_count as usize {
        let offset = entries_offset as usize + index * entry_stride;
        let (dylib_offset, nlist_start_offset) = if entry_stride == LOCAL_SYMBOLS_ENTRY_V2_SIZE {
            (read_u64(chunk, offset, byte_order)?, offset + 8)
        } else {
            (u64::from(read_u32(chunk, offset, byte_order)?), offset + 4)
        };
        let nlist_start_index = read_u32(chunk, nlist_start_offset, byte_order)?;
        let entry_nlist_count = read_u32(chunk, nlist_start_offset + 4, byte_order)?;
        let end = nlist_start_index
            .checked_add(entry_nlist_count)
            .ok_or_else(|| Error::format(format!("local-symbol entry[{index}] range overflows")))?;
        if end > nlist_count {
            return Err(Error::format(format!(
                "local-symbol entry[{index}] nlist range {nlist_start_index}..{end} exceeds {nlist_count} entries"
            )));
        }
        if !dylib_offsets.insert(dylib_offset) {
            return Err(Error::format(format!(
                "duplicate local-symbol dylib offset {dylib_offset:#x}"
            )));
        }
        let nlist_range = nlist_start_index..end;
        if !nlist_range.is_empty()
            && nlist_ranges
                .iter()
                .any(|prior| nlist_range.start < prior.end && prior.start < nlist_range.end)
        {
            return Err(Error::format(format!(
                "local-symbol entry[{index}] nlist range overlaps an earlier entry"
            )));
        }
        nlist_ranges.push(nlist_range);
        entries.push(CacheLocalSymbolsEntry {
            dylib_offset,
            nlist_start_index,
            nlist_count: entry_nlist_count,
        });
    }
    Ok(Some(CacheLocalSymbolsInfo {
        file_offset,
        file_size,
        nlist_offset,
        nlist_count,
        strings_offset,
        strings_size,
        entries_offset,
        entries,
    }))
}

fn table_range(
    data: &[u8],
    offset: usize,
    count: usize,
    stride: usize,
    label: &str,
) -> Result<Range<usize>> {
    validate_table_extent(data, offset, count, stride, label)?;
    let size = count
        .checked_mul(stride)
        .ok_or_else(|| Error::format(format!("{label} table size overflows")))?;
    Ok(offset..offset + size)
}

fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    !left.is_empty() && !right.is_empty() && left.start < right.end && right.start < left.end
}

fn nlist_stride_for_arch(arch: &str) -> Result<usize> {
    match arch {
        "x86_64" | "x86_64h" | "arm64" | "arm64e" | "arm64_32" | "ppc64" => Ok(16),
        "i386" | "armv5" | "armv6" | "armv7" | "armv7f" | "armv7s" | "armv7k" => Ok(12),
        "ppc" => Ok(12),
        _ => Err(Error::unsupported(format!(
            "dyld cache architecture {arch:?} has no known local-symbol nlist layout"
        ))),
    }
}

fn parse_magic(magic: &str) -> Result<(DyldCacheFormatVersion, String)> {
    let (version, suffix) = if let Some(suffix) = magic.strip_prefix("dyld_v0") {
        (DyldCacheFormatVersion::V0, suffix)
    } else if let Some(suffix) = magic.strip_prefix("dyld_v1") {
        (DyldCacheFormatVersion::V1, suffix)
    } else if magic.as_bytes().starts_with(DYLD_CACHE_MAGIC_FAMILY_PREFIX) {
        return Err(Error::unsupported(
            "dyld cache magic declares an unsupported format generation",
        ));
    } else {
        return Err(Error::format("not a dyld shared cache (bad magic)"));
    };
    let arch = suffix.trim().to_owned();
    nlist_stride_for_arch(&arch)?;
    Ok((version, arch))
}

fn byte_order_for_arch(arch: &str) -> Result<DyldCacheByteOrder> {
    match arch {
        "ppc" | "ppc64" => Ok(DyldCacheByteOrder::Big),
        _ => nlist_stride_for_arch(arch).map(|_| DyldCacheByteOrder::Little),
    }
}

fn field_present(header_size: usize, offset: usize, size: usize) -> bool {
    offset
        .checked_add(size)
        .is_some_and(|end| header_size >= end)
}

fn parse_mappings_for_header(
    data: &[u8],
    header_size: usize,
    offset: usize,
    count: usize,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<CacheMapping>> {
    let legacy = parse_mappings(data, offset, count, byte_order)?;
    if !field_present(header_size, MAPPING_WITH_SLIDE_COUNT_OFF, 4) {
        return Ok(legacy);
    }
    let extended_offset = read_u32(data, MAPPING_WITH_SLIDE_OFFSET_OFF, byte_order)? as usize;
    let extended_count = read_u32(data, MAPPING_WITH_SLIDE_COUNT_OFF, byte_order)? as usize;
    if extended_offset == 0 && extended_count == 0 {
        return Ok(legacy);
    }
    if extended_offset == 0 || extended_count != count {
        return Err(Error::format(format!(
            "extended mapping table must contain {count} records at a nonzero offset"
        )));
    }
    validate_table_extent(
        data,
        extended_offset,
        extended_count,
        MAPPING_AND_SLIDE_INFO_SIZE,
        "extended mapping",
    )?;
    let mut extended = Vec::with_capacity(extended_count);
    for (index, legacy_mapping) in legacy.iter().enumerate() {
        let record = extended_offset + index * MAPPING_AND_SLIDE_INFO_SIZE;
        let slide_info_file_offset = read_u64(data, record + 24, byte_order)?;
        let slide_info_file_size = read_u64(data, record + 32, byte_order)?;
        if (slide_info_file_offset == 0) != (slide_info_file_size == 0) {
            return Err(Error::format(format!(
                "extended mapping[{index}] slide-info offset and size must both be zero or nonzero"
            )));
        }
        if slide_info_file_size != 0 {
            validate_file_range(
                data,
                slide_info_file_offset,
                slide_info_file_size,
                &format!("extended mapping[{index}] slide info"),
            )?;
        }
        let mapping = CacheMapping {
            address: read_u64(data, record, byte_order)?,
            size: read_u64(data, record + 8, byte_order)?,
            file_offset: read_u64(data, record + 16, byte_order)?,
            slide_info_file_offset: (slide_info_file_size != 0).then_some(slide_info_file_offset),
            slide_info_file_size: (slide_info_file_size != 0).then_some(slide_info_file_size),
            flags: Some(read_u64(data, record + 40, byte_order)?),
            max_prot: read_u32(data, record + 48, byte_order)?,
            init_prot: read_u32(data, record + 52, byte_order)?,
        };
        validate_mapping(data, index, &mapping, &extended)?;
        if mapping.address != legacy_mapping.address
            || mapping.size != legacy_mapping.size
            || mapping.file_offset != legacy_mapping.file_offset
            || mapping.max_prot != legacy_mapping.max_prot
            || mapping.init_prot != legacy_mapping.init_prot
        {
            return Err(Error::format(format!(
                "extended mapping[{index}] disagrees with the legacy mapping table"
            )));
        }
        extended.push(mapping);
    }
    Ok(extended)
}

fn parse_mappings(
    data: &[u8],
    offset: usize,
    count: usize,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<CacheMapping>> {
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
            address: read_u64(data, off, byte_order)?,
            size: read_u64(data, off + 8, byte_order)?,
            file_offset: read_u64(data, off + 16, byte_order)?,
            max_prot: read_u32(data, off + 24, byte_order)?,
            init_prot: read_u32(data, off + 28, byte_order)?,
            slide_info_file_offset: None,
            slide_info_file_size: None,
            flags: None,
        };
        validate_mapping(data, i, &mapping, &mappings)?;
        mappings.push(mapping);
    }
    Ok(mappings)
}

fn validate_mapping(
    data: &[u8],
    index: usize,
    mapping: &CacheMapping,
    prior_mappings: &[CacheMapping],
) -> Result<()> {
    if mapping.size == 0 {
        return Err(Error::format(format!("mapping[{index}] has zero size")));
    }
    let va_end = mapping.address.checked_add(mapping.size).ok_or_else(|| {
        Error::address(format!("mapping[{index}] virtual-address extent overflows"))
    })?;
    validate_file_range(
        data,
        mapping.file_offset,
        mapping.size,
        &format!("mapping[{index}]"),
    )?;
    if prior_mappings.iter().any(|prior| {
        let prior_end = prior.address + prior.size;
        mapping.address < prior_end && prior.address < va_end
    }) {
        return Err(Error::format(format!(
            "mapping[{index}] overlaps an earlier virtual-address mapping"
        )));
    }
    Ok(())
}

fn validate_file_range(data: &[u8], offset: u64, size: u64, label: &str) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::address(format!("{label} file extent overflows")))?;
    if end > data.len() as u64 {
        return Err(Error::bounds(offset, size, data.len() as u64));
    }
    Ok(())
}

fn parse_tpro_mappings(
    data: &[u8],
    header_size: usize,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<CacheTproMapping>> {
    if !field_present(header_size, TPRO_MAPPINGS_COUNT_OFF, 4) {
        return Ok(Vec::new());
    }
    let offset = read_u32(data, TPRO_MAPPINGS_OFFSET_OFF, byte_order)? as usize;
    let count = read_u32(data, TPRO_MAPPINGS_COUNT_OFF, byte_order)? as usize;
    if count == 0 {
        return Ok(Vec::new());
    }
    if offset == 0 {
        return Err(Error::format(
            "dyld cache declares TPRO mappings with a zero table offset",
        ));
    }
    validate_table_extent(data, offset, count, TPRO_MAPPING_INFO_SIZE, "TPRO mapping")?;
    let mut mappings = Vec::with_capacity(count);
    for index in 0..count {
        let record = offset + index * TPRO_MAPPING_INFO_SIZE;
        let mapping = CacheTproMapping {
            address: read_u64(data, record, byte_order)?,
            size: read_u64(data, record + 8, byte_order)?,
        };
        if mapping.size == 0 {
            return Err(Error::format(format!(
                "TPRO mapping[{index}] has zero size"
            )));
        }
        let end = mapping
            .address
            .checked_add(mapping.size)
            .ok_or_else(|| Error::address(format!("TPRO mapping[{index}] extent overflows")))?;
        if mappings.iter().any(|prior: &CacheTproMapping| {
            let prior_end = prior.address + prior.size;
            mapping.address < prior_end && prior.address < end
        }) {
            return Err(Error::format(format!(
                "TPRO mapping[{index}] overlaps an earlier TPRO mapping"
            )));
        }
        mappings.push(mapping);
    }
    Ok(mappings)
}

/// Parse the old-style dyld_cache_image_info entries.
/// Layout: address(u64) + modTime(u64) + inode(u64) + pathFileOffset(u32) + pad(u32)
fn parse_images_old(
    data: &[u8],
    offset: usize,
    count: usize,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<CacheImage>> {
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
        let address = read_u64(data, off, byte_order)?;
        let path_offset = read_u32(data, off + 24, byte_order)?;
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
fn parse_images_text(
    data: &[u8],
    offset: usize,
    count: usize,
    byte_order: DyldCacheByteOrder,
) -> Result<Vec<CacheImage>> {
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
        let address = read_u64(data, off + 16, byte_order)?;
        let text_size = read_u32(data, off + 24, byte_order)?;
        let path_offset = read_u32(data, off + 28, byte_order)?;
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
