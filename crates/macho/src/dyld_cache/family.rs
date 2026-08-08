use super::*;
use crate::dyld_cache::completeness::completeness_for;
use crate::dyld_cache::materialize::materialize_cache_image;

impl DyldCache {
    /// List all embedded images.
    pub fn images(&self) -> &[CacheImage] {
        &self.images
    }

    /// List cache memory mappings.
    pub fn mappings(&self) -> &[CacheMapping] {
        &self.mappings
    }

    /// Thread-protected ranges declared by the cache member.
    pub fn tpro_mappings(&self) -> &[CacheTproMapping] {
        &self.tpro_mappings
    }

    /// Architecture string extracted from the magic field.
    pub fn arch(&self) -> &str {
        &self.header.arch
    }

    /// Required sibling-cache declarations in deterministic header order.
    pub fn subcaches(&self) -> &[SubCacheEntry] {
        &self.subcaches
    }

    /// Validated embedded local-symbol metadata, when this member owns it.
    pub fn local_symbols(&self) -> Option<&CacheLocalSymbolsInfo> {
        self.local_symbols.as_ref()
    }

    /// Whether the header requires a separate `.symbols` family member.
    pub fn requires_symbols_member(&self) -> bool {
        self.header.symbol_file_uuid != [0; 16]
    }

    /// Convert a virtual address to a file offset using the mapping table.
    pub fn va_to_file_offset(&self, va: u64) -> Option<u64> {
        for m in &self.mappings {
            let mapping_end = m.address.checked_add(m.size)?;
            if va >= m.address && va < mapping_end {
                return m.file_offset.checked_add(va - m.address);
            }
        }
        None
    }
}

/// Borrowed bytes and a stable member name supplied to family parsing.
#[derive(Debug, Clone, Copy)]
pub struct CacheMemberInput<'data> {
    /// Filename or exact declared suffix used to identify this member.
    pub name: &'data str,
    /// Complete bytes of this cache family member.
    pub data: &'data [u8],
}

/// One validated cache family member.
#[derive(Debug)]
pub struct CacheFamilyMember<'data> {
    name: String,
    kind: CacheFamilyMemberKind,
    cache: DyldCache,
    data: &'data [u8],
}

/// Role of one file in a validated dyld cache family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheFamilyMemberKind {
    /// Primary cache containing the image index and family declarations.
    Primary,
    /// VM-mapped sibling declared by the primary subcache table.
    Subcache,
    /// Unmapped `.symbols` member declared by `symbolFileUUID`.
    Symbols,
}

impl CacheFamilyMember<'_> {
    /// Stable member name supplied by the caller.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parsed member metadata.
    pub fn cache(&self) -> &DyldCache {
        &self.cache
    }

    /// Validated role of this family member.
    pub fn kind(&self) -> CacheFamilyMemberKind {
        self.kind
    }
}

/// Fully validated offline dyld cache family.
#[derive(Debug)]
pub struct DyldCacheFamily<'data> {
    members: Vec<CacheFamilyMember<'data>>,
}

/// Typed state for one reconstruction evidence domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletenessState {
    /// All referenced bytes were reconstructed and remain addressable.
    Complete,
    /// The source image did not declare this domain.
    Absent,
    /// Source evidence exists outside the reconstructed image or was unavailable.
    Unresolved,
    /// Source evidence was deliberately excluded because it would be misleading.
    Rejected,
    /// A valid source layout for this domain is not implemented.
    Unsupported,
}

/// State and human-readable reason for one evidence domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentCompleteness {
    /// Typed state.
    pub state: CompletenessState,
    /// Precise explanation of the state.
    pub detail: String,
}

/// Evidence ledger for one reconstructed standalone image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconstructionCompleteness {
    /// File-backed Mach-O segments.
    pub segments: ComponentCompleteness,
    /// The `__LINKEDIT` segment and its file-coordinate references.
    pub linkedit: ComponentCompleteness,
    /// Mach-O symbol table.
    pub symbols: ComponentCompleteness,
    /// Export trie or legacy export stream.
    pub exports: ComponentCompleteness,
    /// Bind/import streams or chained-import table.
    pub imports: ComponentCompleteness,
    /// Rebase/bind or chained-fixup evidence.
    pub fixups: ComponentCompleteness,
    /// Cache-level local symbols, which are not ordinary image segments.
    pub local_symbols: ComponentCompleteness,
    /// Image-level code-signature evidence.
    pub code_signature: ComponentCompleteness,
}

/// Provenance for one reconstructed segment range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconstructionMapping {
    /// Byte start in the standalone output.
    pub file_start: u64,
    /// Exclusive byte end in the standalone output.
    pub file_end: u64,
    /// RVA start in the mapped image.
    pub rva_start: u64,
    /// Exclusive RVA end in the mapped image.
    pub rva_end: u64,
    /// Cache family members that supplied this range, in read order.
    pub source_members: Vec<String>,
}

/// Owned, parseable standalone Mach-O plus reconstruction evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReconstructedImage {
    /// Exact image path selected from the cache index.
    pub image_path: String,
    /// Architecture declared by the cache family.
    pub arch: String,
    /// Owned standalone Mach-O bytes.
    #[serde(skip)]
    bytes: Vec<u8>,
    /// Reconstructed byte length (also serialized when `bytes` are skipped).
    pub byte_len: usize,
    /// File/RVA/cache-member provenance.
    pub mappings: Vec<ReconstructionMapping>,
    /// File gaps filled with zero only to preserve Mach-O file coordinates.
    pub synthetic_padding: Vec<SerializableRange>,
    /// Structured completeness ledger.
    pub completeness: ReconstructionCompleteness,
}

impl ReconstructedImage {
    /// Parseable standalone thin Mach-O bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the result and return its standalone bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Serializable half-open byte range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SerializableRange {
    /// Inclusive range start.
    pub start: u64,
    /// Exclusive range end.
    pub end: u64,
}

impl<'data> DyldCacheFamily<'data> {
    /// Parse and validate a primary cache plus exactly its declared siblings.
    pub fn parse(
        primary: CacheMemberInput<'data>,
        siblings: impl IntoIterator<Item = CacheMemberInput<'data>>,
    ) -> Result<Self> {
        let primary_cache = parse_dyld_cache(primary.data)?;
        let mut image_paths = BTreeMap::new();
        for (index, image) in primary_cache.images.iter().enumerate() {
            if let Some(prior) = image_paths.insert(image.path.as_str(), index) {
                return Err(Error::format(format!(
                    "duplicate image path {:?} at indexes {prior} and {index}",
                    image.path
                )));
            }
        }
        let mut supplied = BTreeMap::new();
        for sibling in siblings {
            if supplied.insert(sibling.name, sibling.data).is_some() {
                return Err(Error::format(format!(
                    "duplicate cache family member {:?}",
                    sibling.name
                )));
            }
        }
        let mut expected_names = primary_cache
            .subcaches
            .iter()
            .map(|entry| entry.file_suffix.as_str())
            .collect::<BTreeSet<_>>();
        if primary_cache.header.symbol_file_uuid != [0; 16] {
            expected_names.insert(".symbols");
        }
        if let Some(unexpected) = supplied
            .keys()
            .find(|name| !expected_names.contains(**name))
        {
            return Err(Error::format(format!(
                "unexpected cache family member {unexpected:?}"
            )));
        }

        let primary_base = primary_cache
            .mappings
            .iter()
            .map(|mapping| mapping.address)
            .min()
            .ok_or_else(|| Error::unsupported("dyld cache has no mapped regions"))?;
        let arch = primary_cache.arch().to_owned();
        let mut members = vec![CacheFamilyMember {
            name: primary.name.to_owned(),
            kind: CacheFamilyMemberKind::Primary,
            cache: primary_cache,
            data: primary.data,
        }];
        let declarations = members[0].cache.subcaches.clone();
        for declaration in declarations {
            let data = supplied
                .get(declaration.file_suffix.as_str())
                .ok_or_else(|| {
                    Error::format(format!(
                        "missing required cache family member {:?}",
                        declaration.file_suffix
                    ))
                })?;
            let cache = parse_dyld_cache(data)?;
            if cache.header.uuid != declaration.uuid {
                return Err(Error::format(format!(
                    "cache family member {:?} UUID mismatch: expected {}, found {}",
                    declaration.file_suffix,
                    format_uuid(declaration.uuid),
                    format_uuid(cache.header.uuid)
                )));
            }
            if cache.arch() != arch {
                return Err(Error::unsupported(format!(
                    "cache family member {:?} architecture {:?} does not match {:?}",
                    declaration.file_suffix,
                    cache.arch(),
                    arch
                )));
            }
            validate_member_encoding(&members[0].cache, &cache, &declaration.file_suffix)?;
            if !cache.subcaches.is_empty() || cache.requires_symbols_member() {
                return Err(Error::format(format!(
                    "cache family member {:?} recursively declares family members",
                    declaration.file_suffix
                )));
            }
            let actual_base = cache
                .mappings
                .iter()
                .map(|mapping| mapping.address)
                .min()
                .ok_or_else(|| {
                    Error::unsupported(format!(
                        "cache family member {:?} has no mapped regions",
                        declaration.file_suffix
                    ))
                })?;
            let expected_base = primary_base
                .checked_add(declaration.cache_vm_offset)
                .ok_or_else(|| Error::address("subcache VM base overflows"))?;
            if actual_base != expected_base {
                return Err(Error::format(format!(
                    "cache family member {:?} VM base mismatch: expected {expected_base:#x}, found {actual_base:#x}",
                    declaration.file_suffix
                )));
            }
            members.push(CacheFamilyMember {
                name: declaration.file_suffix,
                kind: CacheFamilyMemberKind::Subcache,
                cache,
                data,
            });
        }
        let symbol_uuid = members[0].cache.header.symbol_file_uuid;
        if symbol_uuid != [0; 16] {
            let data = supplied.get(".symbols").ok_or_else(|| {
                Error::format("missing required cache family member \".symbols\"")
            })?;
            let cache = parse_dyld_cache(data)?;
            if cache.header.uuid != symbol_uuid {
                return Err(Error::format(format!(
                    "cache family member \".symbols\" UUID mismatch: expected {}, found {}",
                    format_uuid(symbol_uuid),
                    format_uuid(cache.header.uuid)
                )));
            }
            if cache.arch() != arch {
                return Err(Error::unsupported(format!(
                    "cache family member \".symbols\" architecture {:?} does not match {:?}",
                    cache.arch(),
                    arch
                )));
            }
            validate_member_encoding(&members[0].cache, &cache, ".symbols")?;
            if !cache.subcaches.is_empty() || cache.requires_symbols_member() {
                return Err(Error::format(
                    "cache family member \".symbols\" recursively declares family members",
                ));
            }
            if cache.local_symbols.is_none() {
                return Err(Error::format(
                    "cache family member \".symbols\" has no local-symbol store",
                ));
            }
            let indexed_addresses = members[0]
                .cache
                .images
                .iter()
                .map(|image| image.address)
                .collect::<BTreeSet<_>>();
            for (index, entry) in cache
                .local_symbols
                .as_ref()
                .expect("presence checked above")
                .entries
                .iter()
                .enumerate()
            {
                let address = primary_base
                    .checked_add(entry.dylib_offset)
                    .ok_or_else(|| Error::address("local-symbol image address overflows"))?;
                if !indexed_addresses.contains(&address) {
                    return Err(Error::format(format!(
                        "cache family member \".symbols\" entry[{index}] refers to unindexed image VM offset {:#x}",
                        entry.dylib_offset
                    )));
                }
            }
            members.push(CacheFamilyMember {
                name: ".symbols".to_owned(),
                kind: CacheFamilyMemberKind::Symbols,
                cache,
                data,
            });
        }
        validate_family_mappings(&members)?;
        Ok(Self { members })
    }

    /// Primary-cache metadata and image index.
    pub fn primary(&self) -> &DyldCache {
        &self.members[0].cache
    }

    /// Validated family members, primary first and siblings in declaration order.
    pub fn members(&self) -> &[CacheFamilyMember<'data>] {
        &self.members
    }

    /// Find image indexes whose path contains `query`, in cache index order.
    pub fn search_images(&self, query: &str) -> Vec<usize> {
        self.primary()
            .images
            .iter()
            .enumerate()
            .filter_map(|(index, image)| image.path.contains(query).then_some(index))
            .collect()
    }

    /// Find one image by exact install path.
    pub fn image_index_by_path(&self, path: &str) -> Option<usize> {
        self.primary()
            .images
            .iter()
            .position(|image| image.path == path)
    }

    /// Reconstruct one indexed image as an owned standalone Mach-O.
    pub fn reconstruct_image(
        &self,
        index: usize,
        limits: MaterializationLimits,
    ) -> Result<ReconstructedImage> {
        let image = self
            .primary()
            .images
            .get(index)
            .ok_or_else(|| Error::format(format!("image index {index} out of range")))?;
        if image.path.is_empty() {
            return Err(Error::format(format!("image index {index} has no path")));
        }
        let materialized = materialize_cache_image(self, image.address, limits)?;
        // Strict parsing is the delivery boundary: never return an artifact
        // whose rewritten load-command references fail core validation.
        let container = crate::core::format::parse(&materialized.bytes).map_err(Error::from)?;
        let macho = container
            .first_macho()
            .ok_or_else(|| Error::format("reconstructed image has no thin Mach-O"))?;
        let completeness = completeness_for(self, macho);
        let mappings = materialized
            .mappings
            .iter()
            .map(|mapping| {
                let va_start = image
                    .address
                    .checked_add(mapping.rva.start)
                    .ok_or_else(|| Error::address("reconstruction provenance VA overflows"))?;
                let va_end = image
                    .address
                    .checked_add(mapping.rva.end)
                    .ok_or_else(|| Error::address("reconstruction provenance VA overflows"))?;
                Ok(ReconstructionMapping {
                    file_start: mapping.file.start,
                    file_end: mapping.file.end,
                    rva_start: mapping.rva.start,
                    rva_end: mapping.rva.end,
                    source_members: self.source_members_for(va_start..va_end)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let synthetic_padding = materialized
            .synthetic_padding
            .iter()
            .map(|range| SerializableRange {
                start: range.start,
                end: range.end,
            })
            .collect();
        let bytes = materialized.bytes;
        Ok(ReconstructedImage {
            image_path: image.path.clone(),
            arch: self.primary().arch().to_owned(),
            byte_len: bytes.len(),
            bytes,
            mappings,
            synthetic_padding,
            completeness,
        })
    }

    pub(super) fn read_va_exact(&self, range: Range<u64>) -> Result<Vec<u8>> {
        if range.start > range.end {
            return Err(Error::address("cache read range is reversed"));
        }
        let length = range.end - range.start;
        let capacity = usize::try_from(length)
            .map_err(|_| Error::unsupported("cache read exceeds host address space"))?;
        let mut result = Vec::with_capacity(capacity);
        let mut cursor = range.start;
        while cursor < range.end {
            let (member, mapping) = self.mapping_for_va(cursor).ok_or_else(|| {
                Error::address(format!("VA {cursor:#x} is not mapped by the cache family"))
            })?;
            let mapping_end = mapping
                .address
                .checked_add(mapping.size)
                .ok_or_else(|| Error::address("validated cache mapping extent overflows"))?;
            let chunk_end = mapping_end.min(range.end);
            let source_start = mapping
                .file_offset
                .checked_add(cursor - mapping.address)
                .ok_or_else(|| Error::address("cache source offset overflows"))?;
            let source_end = source_start
                .checked_add(chunk_end - cursor)
                .ok_or_else(|| Error::address("cache source extent overflows"))?;
            let start = usize::try_from(source_start)
                .map_err(|_| Error::unsupported("cache source offset exceeds host limits"))?;
            let end = usize::try_from(source_end)
                .map_err(|_| Error::unsupported("cache source extent exceeds host limits"))?;
            let bytes = member.data.get(start..end).ok_or_else(|| {
                Error::bounds(
                    source_start,
                    source_end - source_start,
                    member.data.len() as u64,
                )
            })?;
            result.extend_from_slice(bytes);
            cursor = chunk_end;
        }
        Ok(result)
    }

    pub(super) fn read_c_string_va(
        &self,
        start: u64,
        available: u64,
        subject: &str,
    ) -> Result<Vec<u8>> {
        const MAX_SYMBOL_NAME: u64 = 1024 * 1024;
        let limit = available.min(MAX_SYMBOL_NAME);
        let mut result = Vec::new();
        let mut cursor = 0_u64;
        while cursor < limit {
            let chunk_len = (limit - cursor).min(256);
            let chunk_start = start
                .checked_add(cursor)
                .ok_or_else(|| Error::address(format!("{subject} address overflows")))?;
            let chunk_end = chunk_start
                .checked_add(chunk_len)
                .ok_or_else(|| Error::address(format!("{subject} extent overflows")))?;
            let chunk = self.read_va_exact(chunk_start..chunk_end)?;
            if let Some(end) = chunk.iter().position(|byte| *byte == 0) {
                result.extend_from_slice(&chunk[..end]);
                return Ok(result);
            }
            result.extend_from_slice(&chunk);
            cursor += chunk_len;
        }
        Err(Error::unsupported(format!(
            "{subject} is not NUL-terminated within {limit} bytes"
        )))
    }

    fn mapping_for_va(&self, va: u64) -> Option<(&CacheFamilyMember<'data>, &CacheMapping)> {
        self.members.iter().find_map(|member| {
            if member.kind == CacheFamilyMemberKind::Symbols {
                return None;
            }
            member.cache.mappings.iter().find_map(|mapping| {
                let end = mapping.address.checked_add(mapping.size)?;
                (va >= mapping.address && va < end).then_some((member, mapping))
            })
        })
    }

    fn source_members_for(&self, range: Range<u64>) -> Result<Vec<String>> {
        let mut result = Vec::new();
        let mut cursor = range.start;
        while cursor < range.end {
            let (member, mapping) = self.mapping_for_va(cursor).ok_or_else(|| {
                Error::address(format!("VA {cursor:#x} is not mapped by the cache family"))
            })?;
            if result.last().is_none_or(|name| name != member.name()) {
                result.push(member.name.clone());
            }
            cursor = mapping
                .address
                .checked_add(mapping.size)
                .ok_or_else(|| Error::address("validated cache mapping extent overflows"))?
                .min(range.end);
        }
        Ok(result)
    }
}

fn validate_family_mappings(members: &[CacheFamilyMember<'_>]) -> Result<()> {
    let mut mappings = Vec::new();
    for member in members {
        if member.kind == CacheFamilyMemberKind::Symbols {
            continue;
        }
        for mapping in &member.cache.mappings {
            let end = mapping
                .address
                .checked_add(mapping.size)
                .ok_or_else(|| Error::address("validated cache mapping extent overflows"))?;
            if mappings
                .iter()
                .any(|(start, prior_end): &(u64, u64)| mapping.address < *prior_end && *start < end)
            {
                return Err(Error::format(format!(
                    "cache family member {:?} has a mapping that overlaps another member",
                    member.name
                )));
            }
            mappings.push((mapping.address, end));
        }
        for (index, tpro) in member.cache.tpro_mappings.iter().enumerate() {
            let end = tpro
                .address
                .checked_add(tpro.size)
                .ok_or_else(|| Error::address("validated TPRO mapping extent overflows"))?;
            let contained = member.cache.mappings.iter().any(|mapping| {
                mapping
                    .address
                    .checked_add(mapping.size)
                    .is_some_and(|mapping_end| {
                        tpro.address >= mapping.address && end <= mapping_end
                    })
            });
            if !contained {
                return Err(Error::format(format!(
                    "cache family member {:?} TPRO mapping[{index}] is not contained in one of its VM mappings",
                    member.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_member_encoding(primary: &DyldCache, member: &DyldCache, name: &str) -> Result<()> {
    if member.header.format_version != primary.header.format_version {
        return Err(Error::format(format!(
            "cache family member {name:?} format generation differs from the primary"
        )));
    }
    if member.header.byte_order != primary.header.byte_order {
        return Err(Error::format(format!(
            "cache family member {name:?} byte order differs from the primary"
        )));
    }
    Ok(())
}
