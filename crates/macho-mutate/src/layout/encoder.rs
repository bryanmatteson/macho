use crate::format::constants::*;
use crate::format::io::Endian;
use crate::model::header::Bitness;
use crate::model::load_command::*;
use crate::model::section::SectionType;
use crate::model::segment::Segment;
use crate::section::{EditableSegment, PlacedSection};
use crate::{Error, Result};

/// Encode a load command to bytes. The encoded bytes include cmd + cmdsize
/// and are padded to the required alignment.
pub fn encode_load_command(
    lc: &LoadCommand,
    segments: &[Segment],
    endian: Endian,
    bitness: Bitness,
) -> Result<Vec<u8>> {
    let segments = segments
        .iter()
        .cloned()
        .map(EditableSegment::from)
        .collect::<Vec<_>>();
    encode_edited_load_command(lc, &segments, endian, bitness)
}

pub(crate) fn encode_edited_load_command(
    lc: &LoadCommand,
    segments: &[EditableSegment<'_>],
    endian: Endian,
    bitness: Bitness,
) -> Result<Vec<u8>> {
    let align = if bitness == Bitness::Bits64 { 8 } else { 4 };
    let mut bytes = match lc {
        LoadCommand::Segment64(d) => encode_segment_64(d, segments, endian)?,
        LoadCommand::Segment32(d) => encode_segment_32(d, segments, endian)?,
        LoadCommand::Symtab(d) => encode_symtab(d, endian),
        LoadCommand::Dysymtab(d) => encode_dysymtab(d, endian),
        LoadCommand::Uuid(d) => encode_uuid(d, endian),
        LoadCommand::BuildVersion(d) => encode_build_version(d, endian)?,
        LoadCommand::SourceVersion(d) => encode_source_version(d, endian),
        LoadCommand::Main(d) => encode_main(d, endian),
        LoadCommand::DyldInfo(d) => encode_dyld_info(d, endian, LC_DYLD_INFO),
        LoadCommand::DyldInfoOnly(d) => encode_dyld_info(d, endian, LC_DYLD_INFO_ONLY),
        LoadCommand::LoadDylib(d) => encode_dylib(d, endian, LC_LOAD_DYLIB)?,
        LoadCommand::IdDylib(d) => encode_dylib(d, endian, LC_ID_DYLIB)?,
        LoadCommand::LoadWeakDylib(d) => encode_dylib(d, endian, LC_LOAD_WEAK_DYLIB)?,
        LoadCommand::ReexportDylib(d) => encode_dylib(d, endian, LC_REEXPORT_DYLIB)?,
        LoadCommand::LazyLoadDylib(d) => encode_dylib(d, endian, LC_LAZY_LOAD_DYLIB)?,
        LoadCommand::LoadUpwardDylib(d) => encode_dylib(d, endian, LC_LOAD_UPWARD_DYLIB)?,
        LoadCommand::Rpath(d) => encode_string_cmd(d, endian, LC_RPATH)?,
        LoadCommand::TargetTriple(d) => encode_string_cmd(d, endian, LC_TARGET_TRIPLE)?,
        LoadCommand::LoadDylinker(d) => encode_string_cmd(d, endian, LC_LOAD_DYLINKER)?,
        LoadCommand::IdDylinker(d) => encode_string_cmd(d, endian, LC_ID_DYLINKER)?,
        LoadCommand::DyldEnvironment(d) => encode_string_cmd(d, endian, LC_DYLD_ENVIRONMENT)?,
        LoadCommand::SubFramework(d) => encode_string_cmd(d, endian, LC_SUB_FRAMEWORK)?,
        LoadCommand::SubUmbrella(d) => encode_string_cmd(d, endian, LC_SUB_UMBRELLA)?,
        LoadCommand::SubClient(d) => encode_string_cmd(d, endian, LC_SUB_CLIENT)?,
        LoadCommand::SubLibrary(d) => encode_string_cmd(d, endian, LC_SUB_LIBRARY)?,
        LoadCommand::CodeSignature(d) => encode_linkedit(d, endian, LC_CODE_SIGNATURE),
        LoadCommand::SegmentSplitInfo(d) => encode_linkedit(d, endian, LC_SEGMENT_SPLIT_INFO),
        LoadCommand::FunctionStarts(d) => encode_linkedit(d, endian, LC_FUNCTION_STARTS),
        LoadCommand::DataInCode(d) => encode_linkedit(d, endian, LC_DATA_IN_CODE),
        LoadCommand::DylibCodeSignDrs(d) => encode_linkedit(d, endian, LC_DYLIB_CODE_SIGN_DRS),
        LoadCommand::LinkerOptimizationHint(d) => {
            encode_linkedit(d, endian, LC_LINKER_OPTIMIZATION_HINT)
        }
        LoadCommand::DyldExportsTrie(d) => encode_linkedit(d, endian, LC_DYLD_EXPORTS_TRIE),
        LoadCommand::DyldChainedFixups(d) => encode_linkedit(d, endian, LC_DYLD_CHAINED_FIXUPS),
        LoadCommand::AtomInfo(d) => encode_linkedit(d, endian, LC_ATOM_INFO),
        LoadCommand::FunctionVariants(d) => encode_linkedit(d, endian, LC_FUNCTION_VARIANTS),
        LoadCommand::FunctionVariantFixups(d) => {
            encode_linkedit(d, endian, LC_FUNCTION_VARIANT_FIXUPS)
        }
        LoadCommand::VersionMinMacOS(d) => encode_version_min(d, endian, LC_VERSION_MIN_MACOSX),
        LoadCommand::VersionMinIOS(d) => encode_version_min(d, endian, LC_VERSION_MIN_IPHONEOS),
        LoadCommand::VersionMinTvOS(d) => encode_version_min(d, endian, LC_VERSION_MIN_TVOS),
        LoadCommand::VersionMinWatchOS(d) => encode_version_min(d, endian, LC_VERSION_MIN_WATCHOS),
        LoadCommand::EncryptionInfo(d) => encode_encryption_info(d, endian, LC_ENCRYPTION_INFO),
        LoadCommand::EncryptionInfo64(d) => encode_encryption_info_64(d, endian),
        LoadCommand::Thread(d) | LoadCommand::UnixThread(d) => {
            let cmd = if matches!(lc, LoadCommand::Thread(_)) {
                LC_THREAD
            } else {
                LC_UNIXTHREAD
            };
            encode_raw_data(d, endian, cmd)?
        }
        LoadCommand::PreboundDylib(d) | LoadCommand::Ident(d) => {
            let cmd = if matches!(lc, LoadCommand::PreboundDylib(_)) {
                LC_PREBOUND_DYLIB
            } else {
                LC_IDENT
            };
            encode_raw_data(d, endian, cmd)?
        }
        LoadCommand::LinkerOption(d) => encode_linker_option(d, endian)?,
        LoadCommand::Note(d) => encode_note(d, endian)?,
        LoadCommand::FilesetEntry(d) => encode_fileset_entry(d, endian)?,
        LoadCommand::PrebindCksum(d) => encode_prebind_cksum(d, endian),
        LoadCommand::TwolevelHints(d) => encode_twolevel_hints(d, endian),
        LoadCommand::Routines(d) => encode_routines(d, endian, LC_ROUTINES)?,
        LoadCommand::Routines64(d) => encode_routines_64(d, endian),
        LoadCommand::Unknown(d) => encode_unknown(d, endian)?,
    };

    // Pad to alignment
    while bytes.len() % align != 0 {
        bytes.push(0);
    }

    // Update cmdsize field (always at offset 4) to match actual size
    if bytes.len() >= 8 {
        let final_size = u32::try_from(bytes.len())
            .map_err(|_| Error::invalid("encoded load command exceeds Mach-O's u32 size field"))?;
        let final_size = endian.encode_u32(final_size).to_ne_bytes();
        bytes[4..8].copy_from_slice(&final_size);
    }

    Ok(bytes)
}

// Helper: push u32 in file byte order
fn push_u32(buf: &mut Vec<u8>, endian: Endian, val: u32) {
    buf.extend_from_slice(&endian.encode_u32(val).to_ne_bytes());
}

fn push_u64(buf: &mut Vec<u8>, endian: Endian, val: u64) {
    buf.extend_from_slice(&endian.encode_u64(val).to_ne_bytes());
}

fn push_i32(buf: &mut Vec<u8>, endian: Endian, val: i32) {
    buf.extend_from_slice(&endian.encode_i32(val).to_ne_bytes());
}

fn checked_padded_size(
    base: usize,
    payload: usize,
    terminator: usize,
    alignment: usize,
    label: &str,
) -> Result<usize> {
    let unaligned = base
        .checked_add(payload)
        .and_then(|size| size.checked_add(terminator))
        .ok_or_else(|| Error::invalid(format!("{label} command size overflow")))?;
    let size = unaligned
        .checked_add(alignment - 1)
        .map(|size| size & !(alignment - 1))
        .ok_or_else(|| Error::invalid(format!("{label} command alignment overflow")))?;
    u32::try_from(size)
        .map_err(|_| Error::invalid(format!("{label} command exceeds Mach-O's u32 size field")))?;
    Ok(size)
}

fn reject_nul(value: &str, label: &str) -> Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(Error::invalid(format!("{label} must not contain NUL")));
    }
    Ok(())
}

fn encode_segment_64(
    d: &SegmentCommandData,
    segments: &[EditableSegment<'_>],
    endian: Endian,
) -> Result<Vec<u8>> {
    let seg = segments
        .get(d.segment_index)
        .ok_or_else(|| Error::invalid(format!("segment index {} out of range", d.segment_index)))?;

    let nsects = seg
        .original
        .sections()
        .len()
        .checked_add(seg.added_sections.len())
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(|| Error::invalid("section count exceeds u32"))?;
    let cmdsize = usize::try_from(nsects)
        .ok()
        .and_then(|count| count.checked_mul(80))
        .and_then(|sections_size| 72usize.checked_add(sections_size))
        .ok_or_else(|| Error::invalid("64-bit segment command size overflow"))?;
    let cmdsize_u32 = u32::try_from(cmdsize)
        .map_err(|_| Error::invalid("64-bit segment command exceeds Mach-O's u32 size field"))?;
    let mut buf = Vec::with_capacity(cmdsize);

    push_u32(&mut buf, endian, LC_SEGMENT_64);
    push_u32(&mut buf, endian, cmdsize_u32);
    buf.extend_from_slice(seg.original.name().as_bytes());
    push_u64(&mut buf, endian, seg.original.vm_addr().0);
    push_u64(&mut buf, endian, seg.vm_size);
    push_u64(&mut buf, endian, seg.original.file_offset().0);
    push_u64(&mut buf, endian, seg.file_size);
    push_i32(&mut buf, endian, seg.original.max_prot().bits());
    push_i32(&mut buf, endian, seg.original.init_prot().bits());
    push_u32(&mut buf, endian, nsects);
    push_u32(&mut buf, endian, seg.original.flags().bits());

    for sect in seg.original.sections() {
        buf.extend_from_slice(sect.section_name().as_bytes());
        buf.extend_from_slice(sect.segment_name().as_bytes());
        push_u64(&mut buf, endian, sect.addr().0);
        push_u64(&mut buf, endian, sect.size());
        let offset = u32::try_from(sect.offset().0)
            .map_err(|_| Error::invalid("section file offset exceeds Mach-O's u32 field"))?;
        let relocation_offset = u32::try_from(sect.relocation_offset().0)
            .map_err(|_| Error::invalid("section relocation offset exceeds u32"))?;
        push_u32(&mut buf, endian, offset);
        push_u32(&mut buf, endian, sect.align());
        push_u32(&mut buf, endian, relocation_offset);
        push_u32(&mut buf, endian, sect.relocation_count());
        let flags = (section_type_to_u8(&sect.section_type()) as u32) | sect.attributes().bits();
        push_u32(&mut buf, endian, flags);
        push_u32(&mut buf, endian, sect.reserved1());
        push_u32(&mut buf, endian, sect.reserved2());
        push_u32(&mut buf, endian, sect.reserved3());
    }
    for section in &seg.added_sections {
        encode_added_section_64(&mut buf, endian, section)?;
    }

    Ok(buf)
}

fn encode_segment_32(
    d: &SegmentCommandData,
    segments: &[EditableSegment<'_>],
    endian: Endian,
) -> Result<Vec<u8>> {
    let seg = segments
        .get(d.segment_index)
        .ok_or_else(|| Error::invalid(format!("segment index {} out of range", d.segment_index)))?;

    let nsects = seg
        .original
        .sections()
        .len()
        .checked_add(seg.added_sections.len())
        .and_then(|count| u32::try_from(count).ok())
        .ok_or_else(|| Error::invalid("section count exceeds u32"))?;
    let cmdsize = usize::try_from(nsects)
        .ok()
        .and_then(|count| count.checked_mul(68))
        .and_then(|sections_size| 56usize.checked_add(sections_size))
        .ok_or_else(|| Error::invalid("32-bit segment command size overflow"))?;
    let cmdsize_u32 = u32::try_from(cmdsize)
        .map_err(|_| Error::invalid("32-bit segment command exceeds Mach-O's u32 size field"))?;
    let mut buf = Vec::with_capacity(cmdsize);

    push_u32(&mut buf, endian, LC_SEGMENT);
    push_u32(&mut buf, endian, cmdsize_u32);
    let vm_addr = u32::try_from(seg.original.vm_addr().0)
        .map_err(|_| Error::invalid("32-bit segment VM address exceeds u32"))?;
    let vm_size = u32::try_from(seg.vm_size)
        .map_err(|_| Error::invalid("32-bit segment VM size exceeds u32"))?;
    let file_offset = u32::try_from(seg.original.file_offset().0)
        .map_err(|_| Error::invalid("32-bit segment file offset exceeds u32"))?;
    let file_size = u32::try_from(seg.file_size)
        .map_err(|_| Error::invalid("32-bit segment file size exceeds u32"))?;
    buf.extend_from_slice(seg.original.name().as_bytes());
    push_u32(&mut buf, endian, vm_addr);
    push_u32(&mut buf, endian, vm_size);
    push_u32(&mut buf, endian, file_offset);
    push_u32(&mut buf, endian, file_size);
    push_i32(&mut buf, endian, seg.original.max_prot().bits());
    push_i32(&mut buf, endian, seg.original.init_prot().bits());
    push_u32(&mut buf, endian, nsects);
    push_u32(&mut buf, endian, seg.original.flags().bits());

    for sect in seg.original.sections() {
        let address = u32::try_from(sect.addr().0)
            .map_err(|_| Error::invalid("32-bit section VM address exceeds u32"))?;
        let size = u32::try_from(sect.size())
            .map_err(|_| Error::invalid("32-bit section size exceeds u32"))?;
        let offset = u32::try_from(sect.offset().0)
            .map_err(|_| Error::invalid("32-bit section file offset exceeds u32"))?;
        let relocation_offset = u32::try_from(sect.relocation_offset().0)
            .map_err(|_| Error::invalid("32-bit section relocation offset exceeds u32"))?;
        buf.extend_from_slice(sect.section_name().as_bytes());
        buf.extend_from_slice(sect.segment_name().as_bytes());
        push_u32(&mut buf, endian, address);
        push_u32(&mut buf, endian, size);
        push_u32(&mut buf, endian, offset);
        push_u32(&mut buf, endian, sect.align());
        push_u32(&mut buf, endian, relocation_offset);
        push_u32(&mut buf, endian, sect.relocation_count());
        let flags = (section_type_to_u8(&sect.section_type()) as u32) | sect.attributes().bits();
        push_u32(&mut buf, endian, flags);
        push_u32(&mut buf, endian, sect.reserved1());
        push_u32(&mut buf, endian, sect.reserved2());
    }
    for section in &seg.added_sections {
        encode_added_section_32(&mut buf, endian, section)?;
    }

    Ok(buf)
}

fn encode_added_section_64(
    buf: &mut Vec<u8>,
    endian: Endian,
    section: &PlacedSection<'_>,
) -> Result<()> {
    let file_offset = u32::try_from(section.file_offset)
        .map_err(|_| Error::invalid("section file offset exceeds Mach-O's u32 field"))?;
    push_fixed_name(buf, section.request.section_name());
    push_fixed_name(buf, section.request.segment_name());
    push_u64(buf, endian, section.address);
    push_u64(buf, endian, section.request.content().size());
    push_u32(buf, endian, file_offset);
    push_u32(buf, endian, section.request.alignment());
    push_u32(buf, endian, 0);
    push_u32(buf, endian, 0);
    let flags = (section_type_to_u8(&section.request.section_type()) as u32)
        | section.request.attributes().bits();
    push_u32(buf, endian, flags);
    let (reserved1, reserved2, reserved3) = section.request.reserved();
    push_u32(buf, endian, reserved1);
    push_u32(buf, endian, reserved2);
    push_u32(buf, endian, reserved3);
    Ok(())
}

fn encode_added_section_32(
    buf: &mut Vec<u8>,
    endian: Endian,
    section: &PlacedSection<'_>,
) -> Result<()> {
    let address = u32::try_from(section.address)
        .map_err(|_| Error::invalid("32-bit section VM address exceeds u32"))?;
    let size = u32::try_from(section.request.content().size())
        .map_err(|_| Error::invalid("32-bit section size exceeds u32"))?;
    let file_offset = u32::try_from(section.file_offset)
        .map_err(|_| Error::invalid("32-bit section file offset exceeds u32"))?;
    push_fixed_name(buf, section.request.section_name());
    push_fixed_name(buf, section.request.segment_name());
    push_u32(buf, endian, address);
    push_u32(buf, endian, size);
    push_u32(buf, endian, file_offset);
    push_u32(buf, endian, section.request.alignment());
    push_u32(buf, endian, 0);
    push_u32(buf, endian, 0);
    let flags = (section_type_to_u8(&section.request.section_type()) as u32)
        | section.request.attributes().bits();
    push_u32(buf, endian, flags);
    let (reserved1, reserved2, _) = section.request.reserved();
    push_u32(buf, endian, reserved1);
    push_u32(buf, endian, reserved2);
    Ok(())
}

fn push_fixed_name(buf: &mut Vec<u8>, name: &str) {
    let mut fixed = [0u8; 16];
    fixed[..name.len()].copy_from_slice(name.as_bytes());
    buf.extend_from_slice(&fixed);
}

fn encode_symtab(d: &SymtabData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, endian, LC_SYMTAB);
    push_u32(&mut buf, endian, 24);
    push_u32(&mut buf, endian, d.sym_offset);
    push_u32(&mut buf, endian, d.nsyms);
    push_u32(&mut buf, endian, d.str_offset);
    push_u32(&mut buf, endian, d.str_size);
    buf
}

fn encode_dysymtab(d: &DysymtabData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    push_u32(&mut buf, endian, LC_DYSYMTAB);
    push_u32(&mut buf, endian, 80);
    push_u32(&mut buf, endian, d.ilocalsym);
    push_u32(&mut buf, endian, d.nlocalsym);
    push_u32(&mut buf, endian, d.iextdefsym);
    push_u32(&mut buf, endian, d.nextdefsym);
    push_u32(&mut buf, endian, d.iundefsym);
    push_u32(&mut buf, endian, d.nundefsym);
    push_u32(&mut buf, endian, d.tocoff);
    push_u32(&mut buf, endian, d.ntoc);
    push_u32(&mut buf, endian, d.modtaboff);
    push_u32(&mut buf, endian, d.nmodtab);
    push_u32(&mut buf, endian, d.extrefsymoff);
    push_u32(&mut buf, endian, d.nextrefsyms);
    push_u32(&mut buf, endian, d.indirectsymoff);
    push_u32(&mut buf, endian, d.nindirectsyms);
    push_u32(&mut buf, endian, d.extreloff);
    push_u32(&mut buf, endian, d.nextrel);
    push_u32(&mut buf, endian, d.locreloff);
    push_u32(&mut buf, endian, d.nlocrel);
    buf
}

fn encode_uuid(d: &UuidData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, endian, LC_UUID);
    push_u32(&mut buf, endian, 24);
    buf.extend_from_slice(&d.uuid);
    buf
}

fn encode_build_version(d: &BuildVersionData, endian: Endian) -> Result<Vec<u8>> {
    let ntools = u32::try_from(d.tools.len())
        .map_err(|_| Error::invalid("build-version tool count exceeds u32"))?;
    let cmdsize = d
        .tools
        .len()
        .checked_mul(8)
        .and_then(|size| size.checked_add(24))
        .ok_or_else(|| Error::invalid("build-version command size overflow"))?;
    let cmdsize_u32 = u32::try_from(cmdsize)
        .map_err(|_| Error::invalid("build-version command exceeds Mach-O's u32 size field"))?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, LC_BUILD_VERSION);
    push_u32(&mut buf, endian, cmdsize_u32);
    push_u32(&mut buf, endian, d.platform.0);
    push_u32(&mut buf, endian, d.minos.0);
    push_u32(&mut buf, endian, d.sdk.0);
    push_u32(&mut buf, endian, ntools);
    for tool in &d.tools {
        push_u32(&mut buf, endian, tool.tool.0);
        push_u32(&mut buf, endian, tool.version.0);
    }
    Ok(buf)
}

fn encode_source_version(d: &SourceVersionData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    push_u32(&mut buf, endian, LC_SOURCE_VERSION);
    push_u32(&mut buf, endian, 16);
    push_u64(&mut buf, endian, d.version.0);
    buf
}

fn encode_main(d: &EntryPointData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, endian, LC_MAIN);
    push_u32(&mut buf, endian, 24);
    push_u64(&mut buf, endian, d.entry_offset);
    push_u64(&mut buf, endian, d.stack_size);
    buf
}

fn encode_dyld_info(d: &DyldInfoData, endian: Endian, cmd: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(48);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, 48);
    push_u32(&mut buf, endian, d.rebase_off);
    push_u32(&mut buf, endian, d.rebase_size);
    push_u32(&mut buf, endian, d.bind_off);
    push_u32(&mut buf, endian, d.bind_size);
    push_u32(&mut buf, endian, d.weak_bind_off);
    push_u32(&mut buf, endian, d.weak_bind_size);
    push_u32(&mut buf, endian, d.lazy_bind_off);
    push_u32(&mut buf, endian, d.lazy_bind_size);
    push_u32(&mut buf, endian, d.export_off);
    push_u32(&mut buf, endian, d.export_size);
    buf
}

fn encode_dylib(d: &DylibData, endian: Endian, cmd: u32) -> Result<Vec<u8>> {
    reject_nul(&d.name, "dylib name")?;
    let name_bytes = d.name.as_bytes();
    let str_offset = 24u32; // cmd + cmdsize + name_offset + timestamp + versions = 24
    let cmdsize = checked_padded_size(24, name_bytes.len(), 1, 4, "dylib")?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, cmd);
    push_u32(
        &mut buf,
        endian,
        u32::try_from(cmdsize).map_err(|_| Error::invalid("dylib command size exceeds u32"))?,
    );
    push_u32(&mut buf, endian, str_offset);
    push_u32(&mut buf, endian, d.timestamp);
    push_u32(&mut buf, endian, d.current_version.0);
    push_u32(&mut buf, endian, d.compatibility_version.0);
    buf.extend_from_slice(name_bytes);
    buf.push(0); // null terminator
    while buf.len() < cmdsize {
        buf.push(0);
    }
    Ok(buf)
}

fn encode_string_cmd(d: &StringData, endian: Endian, cmd: u32) -> Result<Vec<u8>> {
    reject_nul(&d.value, "load-command string")?;
    let str_bytes = d.value.as_bytes();
    let str_offset = 12u32; // cmd + cmdsize + string_offset
    let cmdsize = checked_padded_size(12, str_bytes.len(), 1, 4, "string")?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, cmd);
    push_u32(
        &mut buf,
        endian,
        u32::try_from(cmdsize).map_err(|_| Error::invalid("string command size exceeds u32"))?,
    );
    push_u32(&mut buf, endian, str_offset);
    buf.extend_from_slice(str_bytes);
    buf.push(0);
    while buf.len() < cmdsize {
        buf.push(0);
    }
    Ok(buf)
}

fn encode_linkedit(d: &LinkeditData, endian: Endian, cmd: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, 16);
    push_u32(&mut buf, endian, d.data_offset);
    push_u32(&mut buf, endian, d.data_size);
    buf
}

fn encode_version_min(d: &VersionMinData, endian: Endian, cmd: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, 16);
    push_u32(&mut buf, endian, d.version.0);
    push_u32(&mut buf, endian, d.sdk.0);
    buf
}

fn encode_encryption_info(d: &EncryptionInfoData, endian: Endian, cmd: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, 20);
    push_u32(&mut buf, endian, d.crypt_offset);
    push_u32(&mut buf, endian, d.crypt_size);
    push_u32(&mut buf, endian, d.crypt_id);
    buf
}

fn encode_encryption_info_64(d: &EncryptionInfoData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    push_u32(&mut buf, endian, LC_ENCRYPTION_INFO_64);
    push_u32(&mut buf, endian, 24);
    push_u32(&mut buf, endian, d.crypt_offset);
    push_u32(&mut buf, endian, d.crypt_size);
    push_u32(&mut buf, endian, d.crypt_id);
    push_u32(&mut buf, endian, 0); // pad
    buf
}

fn encode_raw_data(d: &RawData, endian: Endian, cmd: u32) -> Result<Vec<u8>> {
    let cmdsize = 8usize
        .checked_add(d.data.len())
        .ok_or_else(|| Error::invalid("raw load-command size overflow"))?;
    let cmdsize_u32 = u32::try_from(cmdsize)
        .map_err(|_| Error::invalid("raw load command exceeds Mach-O's u32 size field"))?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, cmdsize_u32);
    buf.extend_from_slice(&d.data);
    Ok(buf)
}

fn encode_linker_option(d: &LinkerOptionData, endian: Endian) -> Result<Vec<u8>> {
    let count = u32::try_from(d.strings.len())
        .map_err(|_| Error::invalid("linker-option string count exceeds u32"))?;
    let payload_size = d.strings.iter().try_fold(0usize, |size, string| {
        reject_nul(string, "linker option")?;
        size.checked_add(string.len())
            .and_then(|size| size.checked_add(1))
            .ok_or_else(|| Error::invalid("linker-option payload size overflow"))
    })?;
    let mut payload = Vec::with_capacity(payload_size);
    for s in &d.strings {
        payload.extend_from_slice(s.as_bytes());
        payload.push(0);
    }
    let cmdsize = checked_padded_size(12, payload.len(), 0, 4, "linker-option")?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, LC_LINKER_OPTION);
    push_u32(
        &mut buf,
        endian,
        u32::try_from(cmdsize)
            .map_err(|_| Error::invalid("linker-option command size exceeds u32"))?,
    );
    push_u32(&mut buf, endian, count);
    buf.extend_from_slice(&payload);
    while buf.len() < cmdsize {
        buf.push(0);
    }
    Ok(buf)
}

fn encode_note(d: &NoteData, endian: Endian) -> Result<Vec<u8>> {
    reject_nul(&d.data_owner, "note owner")?;
    if d.data_owner.len() > 16 {
        return Err(Error::invalid("note owner exceeds Mach-O's 16-byte field"));
    }
    let mut buf = Vec::with_capacity(40);
    push_u32(&mut buf, endian, LC_NOTE);
    push_u32(&mut buf, endian, 40);
    let mut owner = [0u8; 16];
    let bytes = d.data_owner.as_bytes();
    owner[..bytes.len()].copy_from_slice(bytes);
    buf.extend_from_slice(&owner);
    push_u64(&mut buf, endian, d.offset);
    push_u64(&mut buf, endian, d.size);
    Ok(buf)
}

fn encode_fileset_entry(d: &FilesetEntryData, endian: Endian) -> Result<Vec<u8>> {
    reject_nul(&d.entry_id, "fileset entry identifier")?;
    let str_offset = 32u32;
    let cmdsize = checked_padded_size(32, d.entry_id.len(), 1, 8, "fileset-entry")?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, LC_FILESET_ENTRY);
    push_u32(
        &mut buf,
        endian,
        u32::try_from(cmdsize)
            .map_err(|_| Error::invalid("fileset-entry command size exceeds u32"))?,
    );
    push_u64(&mut buf, endian, d.vm_addr);
    push_u64(&mut buf, endian, d.file_offset);
    push_u32(&mut buf, endian, str_offset);
    push_u32(&mut buf, endian, 0); // reserved
    buf.extend_from_slice(d.entry_id.as_bytes());
    buf.push(0);
    while buf.len() < cmdsize {
        buf.push(0);
    }
    Ok(buf)
}

fn encode_prebind_cksum(d: &PrebindCksumData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12);
    push_u32(&mut buf, endian, LC_PREBIND_CKSUM);
    push_u32(&mut buf, endian, 12);
    push_u32(&mut buf, endian, d.cksum);
    buf
}

fn encode_twolevel_hints(d: &TwolevelHintsData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    push_u32(&mut buf, endian, LC_TWOLEVEL_HINTS);
    push_u32(&mut buf, endian, 16);
    push_u32(&mut buf, endian, d.offset);
    push_u32(&mut buf, endian, d.nhints);
    buf
}

fn encode_routines(d: &RoutinesData, endian: Endian, cmd: u32) -> Result<Vec<u8>> {
    let init_address = u32::try_from(d.init_address)
        .map_err(|_| Error::invalid("32-bit routine address exceeds u32"))?;
    let init_module = u32::try_from(d.init_module)
        .map_err(|_| Error::invalid("32-bit routine module exceeds u32"))?;
    let mut buf = Vec::with_capacity(40);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, 40);
    push_u32(&mut buf, endian, init_address);
    push_u32(&mut buf, endian, init_module);
    for _ in 0..6 {
        push_u32(&mut buf, endian, 0);
    }
    Ok(buf)
}

fn encode_routines_64(d: &RoutinesData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(72);
    push_u32(&mut buf, endian, LC_ROUTINES_64);
    push_u32(&mut buf, endian, 72);
    push_u64(&mut buf, endian, d.init_address);
    push_u64(&mut buf, endian, d.init_module);
    for _ in 0..6 {
        push_u64(&mut buf, endian, 0);
    }
    buf
}

fn encode_unknown(d: &UnknownLoadCommand, endian: Endian) -> Result<Vec<u8>> {
    let cmdsize = 8usize
        .checked_add(d.data.len())
        .ok_or_else(|| Error::invalid("unknown load-command size overflow"))?;
    let cmdsize_u32 = u32::try_from(cmdsize)
        .map_err(|_| Error::invalid("unknown load command exceeds Mach-O's u32 size field"))?;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, d.cmd);
    push_u32(&mut buf, endian, cmdsize_u32);
    buf.extend_from_slice(&d.data);
    Ok(buf)
}

/// Encode a section type + attributes back to flags u32.
fn section_type_to_u8(st: &SectionType) -> u8 {
    match st {
        SectionType::Regular => 0,
        SectionType::ZeroFill => 1,
        SectionType::CStringLiterals => 2,
        SectionType::FourByteLiterals => 3,
        SectionType::EightByteLiterals => 4,
        SectionType::LiteralPointers => 5,
        SectionType::NonLazySymbolPointers => 6,
        SectionType::LazySymbolPointers => 7,
        SectionType::SymbolStubs => 8,
        SectionType::ModInitFuncPointers => 9,
        SectionType::ModTermFuncPointers => 0xa,
        SectionType::Coalesced => 0xb,
        SectionType::GbZeroFill => 0xc,
        SectionType::Interposing => 0xd,
        SectionType::SixteenByteLiterals => 0xe,
        SectionType::DTraceDof => 0xf,
        SectionType::LazyDylibSymbolPointers => 0x10,
        SectionType::ThreadLocalRegular => 0x11,
        SectionType::ThreadLocalZeroFill => 0x12,
        SectionType::ThreadLocalVariables => 0x13,
        SectionType::ThreadLocalVariablePointers => 0x14,
        SectionType::ThreadLocalInitFunctionPointers => 0x15,
        SectionType::InitFuncOffsets => 0x16,
        SectionType::Unknown(v) => *v,
    }
}
