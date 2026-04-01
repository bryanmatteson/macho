use crate::format::constants::*;
use crate::format::io::Endian;
use crate::model::header::Bitness;
use crate::model::load_command::*;
use crate::model::section::SectionType;
use crate::model::segment::Segment;
use crate::{Error, Result};

/// Encode a load command to bytes. The encoded bytes include cmd + cmdsize
/// and are padded to the required alignment.
pub fn encode_load_command(
    lc: &LoadCommand,
    segments: &[Segment],
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
        LoadCommand::BuildVersion(d) => encode_build_version(d, endian),
        LoadCommand::SourceVersion(d) => encode_source_version(d, endian),
        LoadCommand::Main(d) => encode_main(d, endian),
        LoadCommand::DyldInfo(d) => encode_dyld_info(d, endian, LC_DYLD_INFO),
        LoadCommand::DyldInfoOnly(d) => encode_dyld_info(d, endian, LC_DYLD_INFO_ONLY),
        LoadCommand::LoadDylib(d) => encode_dylib(d, endian, LC_LOAD_DYLIB),
        LoadCommand::IdDylib(d) => encode_dylib(d, endian, LC_ID_DYLIB),
        LoadCommand::LoadWeakDylib(d) => encode_dylib(d, endian, LC_LOAD_WEAK_DYLIB),
        LoadCommand::ReexportDylib(d) => encode_dylib(d, endian, LC_REEXPORT_DYLIB),
        LoadCommand::LazyLoadDylib(d) => encode_dylib(d, endian, LC_LAZY_LOAD_DYLIB),
        LoadCommand::LoadUpwardDylib(d) => encode_dylib(d, endian, LC_LOAD_UPWARD_DYLIB),
        LoadCommand::Rpath(d) => encode_string_cmd(d, endian, LC_RPATH),
        LoadCommand::TargetTriple(d) => encode_string_cmd(d, endian, LC_TARGET_TRIPLE),
        LoadCommand::LoadDylinker(d) => encode_string_cmd(d, endian, LC_LOAD_DYLINKER),
        LoadCommand::IdDylinker(d) => encode_string_cmd(d, endian, LC_ID_DYLINKER),
        LoadCommand::DyldEnvironment(d) => encode_string_cmd(d, endian, LC_DYLD_ENVIRONMENT),
        LoadCommand::SubFramework(d) => encode_string_cmd(d, endian, LC_SUB_FRAMEWORK),
        LoadCommand::SubUmbrella(d) => encode_string_cmd(d, endian, LC_SUB_UMBRELLA),
        LoadCommand::SubClient(d) => encode_string_cmd(d, endian, LC_SUB_CLIENT),
        LoadCommand::SubLibrary(d) => encode_string_cmd(d, endian, LC_SUB_LIBRARY),
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
            encode_raw_data(d, endian, cmd)
        }
        LoadCommand::PreboundDylib(d) | LoadCommand::Ident(d) => {
            let cmd = if matches!(lc, LoadCommand::PreboundDylib(_)) {
                LC_PREBOUND_DYLIB
            } else {
                LC_IDENT
            };
            encode_raw_data(d, endian, cmd)
        }
        LoadCommand::LinkerOption(d) => encode_linker_option(d, endian),
        LoadCommand::Note(d) => encode_note(d, endian),
        LoadCommand::FilesetEntry(d) => encode_fileset_entry(d, endian),
        LoadCommand::PrebindCksum(d) => encode_prebind_cksum(d, endian),
        LoadCommand::TwolevelHints(d) => encode_twolevel_hints(d, endian),
        LoadCommand::Routines(d) => encode_routines(d, endian, LC_ROUTINES),
        LoadCommand::Routines64(d) => encode_routines_64(d, endian),
        LoadCommand::Unknown(d) => encode_unknown(d, endian),
    };

    // Pad to alignment
    while bytes.len() % align != 0 {
        bytes.push(0);
    }

    // Update cmdsize field (always at offset 4) to match actual size
    if bytes.len() >= 8 {
        let final_size = endian.encode_u32(bytes.len() as u32).to_ne_bytes();
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

fn encode_segment_64(
    d: &SegmentCommandData,
    segments: &[Segment],
    endian: Endian,
) -> Result<Vec<u8>> {
    let seg = segments
        .get(d.segment_index)
        .ok_or_else(|| Error::Format(format!("segment index {} out of range", d.segment_index)))?;

    let nsects = seg.sections.len() as u32;
    let cmdsize = 72 + nsects as usize * 80;
    let mut buf = Vec::with_capacity(cmdsize);

    push_u32(&mut buf, endian, LC_SEGMENT_64);
    push_u32(&mut buf, endian, cmdsize as u32);
    buf.extend_from_slice(seg.name.as_bytes());
    push_u64(&mut buf, endian, seg.vm_addr.0);
    push_u64(&mut buf, endian, seg.vm_size);
    push_u64(&mut buf, endian, seg.file_offset.0);
    push_u64(&mut buf, endian, seg.file_size);
    push_i32(&mut buf, endian, seg.max_prot.bits());
    push_i32(&mut buf, endian, seg.init_prot.bits());
    push_u32(&mut buf, endian, nsects);
    push_u32(&mut buf, endian, seg.flags.bits());

    for sect in &seg.sections {
        buf.extend_from_slice(sect.section_name.as_bytes());
        buf.extend_from_slice(sect.segment_name.as_bytes());
        push_u64(&mut buf, endian, sect.addr.0);
        push_u64(&mut buf, endian, sect.size);
        push_u32(&mut buf, endian, sect.offset.0 as u32);
        push_u32(&mut buf, endian, sect.align);
        push_u32(&mut buf, endian, sect.reloff.0 as u32);
        push_u32(&mut buf, endian, sect.nreloc);
        let flags = (section_type_to_u8(&sect.section_type) as u32) | sect.attributes.bits();
        push_u32(&mut buf, endian, flags);
        push_u32(&mut buf, endian, sect.reserved1);
        push_u32(&mut buf, endian, sect.reserved2);
        push_u32(&mut buf, endian, sect.reserved3);
    }

    Ok(buf)
}

fn encode_segment_32(
    d: &SegmentCommandData,
    segments: &[Segment],
    endian: Endian,
) -> Result<Vec<u8>> {
    let seg = segments
        .get(d.segment_index)
        .ok_or_else(|| Error::Format(format!("segment index {} out of range", d.segment_index)))?;

    let nsects = seg.sections.len() as u32;
    let cmdsize = 56 + nsects as usize * 68;
    let mut buf = Vec::with_capacity(cmdsize);

    push_u32(&mut buf, endian, LC_SEGMENT);
    push_u32(&mut buf, endian, cmdsize as u32);
    buf.extend_from_slice(seg.name.as_bytes());
    push_u32(&mut buf, endian, seg.vm_addr.0 as u32);
    push_u32(&mut buf, endian, seg.vm_size as u32);
    push_u32(&mut buf, endian, seg.file_offset.0 as u32);
    push_u32(&mut buf, endian, seg.file_size as u32);
    push_i32(&mut buf, endian, seg.max_prot.bits());
    push_i32(&mut buf, endian, seg.init_prot.bits());
    push_u32(&mut buf, endian, nsects);
    push_u32(&mut buf, endian, seg.flags.bits());

    for sect in &seg.sections {
        buf.extend_from_slice(sect.section_name.as_bytes());
        buf.extend_from_slice(sect.segment_name.as_bytes());
        push_u32(&mut buf, endian, sect.addr.0 as u32);
        push_u32(&mut buf, endian, sect.size as u32);
        push_u32(&mut buf, endian, sect.offset.0 as u32);
        push_u32(&mut buf, endian, sect.align);
        push_u32(&mut buf, endian, sect.reloff.0 as u32);
        push_u32(&mut buf, endian, sect.nreloc);
        let flags = (section_type_to_u8(&sect.section_type) as u32) | sect.attributes.bits();
        push_u32(&mut buf, endian, flags);
        push_u32(&mut buf, endian, sect.reserved1);
        push_u32(&mut buf, endian, sect.reserved2);
    }

    Ok(buf)
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

fn encode_build_version(d: &BuildVersionData, endian: Endian) -> Vec<u8> {
    let ntools = d.tools.len() as u32;
    let cmdsize = 24 + ntools as usize * 8;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, LC_BUILD_VERSION);
    push_u32(&mut buf, endian, cmdsize as u32);
    push_u32(&mut buf, endian, d.platform.0);
    push_u32(&mut buf, endian, d.minos.0);
    push_u32(&mut buf, endian, d.sdk.0);
    push_u32(&mut buf, endian, ntools);
    for tool in &d.tools {
        push_u32(&mut buf, endian, tool.tool.0);
        push_u32(&mut buf, endian, tool.version.0);
    }
    buf
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

fn encode_dylib(d: &DylibData, endian: Endian, cmd: u32) -> Vec<u8> {
    let name_bytes = d.name.as_bytes();
    let str_offset = 24u32; // cmd + cmdsize + name_offset + timestamp + versions = 24
    let cmdsize = (str_offset as usize + name_bytes.len() + 1 + 3) & !3; // null + pad to 4
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, cmdsize as u32);
    push_u32(&mut buf, endian, str_offset);
    push_u32(&mut buf, endian, d.timestamp);
    push_u32(&mut buf, endian, d.current_version.0);
    push_u32(&mut buf, endian, d.compatibility_version.0);
    buf.extend_from_slice(name_bytes);
    buf.push(0); // null terminator
    while buf.len() < cmdsize {
        buf.push(0);
    }
    buf
}

fn encode_string_cmd(d: &StringData, endian: Endian, cmd: u32) -> Vec<u8> {
    let str_bytes = d.value.as_bytes();
    let str_offset = 12u32; // cmd + cmdsize + string_offset
    let cmdsize = (str_offset as usize + str_bytes.len() + 1 + 3) & !3;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, cmdsize as u32);
    push_u32(&mut buf, endian, str_offset);
    buf.extend_from_slice(str_bytes);
    buf.push(0);
    while buf.len() < cmdsize {
        buf.push(0);
    }
    buf
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

fn encode_raw_data(d: &RawData, endian: Endian, cmd: u32) -> Vec<u8> {
    let cmdsize = 8 + d.data.len();
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, cmdsize as u32);
    buf.extend_from_slice(&d.data);
    buf
}

fn encode_linker_option(d: &LinkerOptionData, endian: Endian) -> Vec<u8> {
    let mut payload = Vec::new();
    for s in &d.strings {
        payload.extend_from_slice(s.as_bytes());
        payload.push(0);
    }
    let cmdsize = (12 + payload.len() + 3) & !3;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, LC_LINKER_OPTION);
    push_u32(&mut buf, endian, cmdsize as u32);
    push_u32(&mut buf, endian, d.strings.len() as u32);
    buf.extend_from_slice(&payload);
    while buf.len() < cmdsize {
        buf.push(0);
    }
    buf
}

fn encode_note(d: &NoteData, endian: Endian) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    push_u32(&mut buf, endian, LC_NOTE);
    push_u32(&mut buf, endian, 40);
    let mut owner = [0u8; 16];
    let bytes = d.data_owner.as_bytes();
    let len = bytes.len().min(16);
    owner[..len].copy_from_slice(&bytes[..len]);
    buf.extend_from_slice(&owner);
    push_u64(&mut buf, endian, d.offset);
    push_u64(&mut buf, endian, d.size);
    buf
}

fn encode_fileset_entry(d: &FilesetEntryData, endian: Endian) -> Vec<u8> {
    let str_offset = 32u32;
    let cmdsize = (str_offset as usize + d.entry_id.len() + 1 + 7) & !7;
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, LC_FILESET_ENTRY);
    push_u32(&mut buf, endian, cmdsize as u32);
    push_u64(&mut buf, endian, d.vm_addr);
    push_u64(&mut buf, endian, d.file_offset);
    push_u32(&mut buf, endian, str_offset);
    push_u32(&mut buf, endian, 0); // reserved
    buf.extend_from_slice(d.entry_id.as_bytes());
    buf.push(0);
    while buf.len() < cmdsize {
        buf.push(0);
    }
    buf
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

fn encode_routines(d: &RoutinesData, endian: Endian, cmd: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(40);
    push_u32(&mut buf, endian, cmd);
    push_u32(&mut buf, endian, 40);
    push_u32(&mut buf, endian, d.init_address as u32);
    push_u32(&mut buf, endian, d.init_module as u32);
    for _ in 0..6 {
        push_u32(&mut buf, endian, 0);
    }
    buf
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

fn encode_unknown(d: &UnknownLoadCommand, endian: Endian) -> Vec<u8> {
    let cmdsize = 8 + d.data.len();
    let mut buf = Vec::with_capacity(cmdsize);
    push_u32(&mut buf, endian, d.cmd);
    push_u32(&mut buf, endian, cmdsize as u32);
    buf.extend_from_slice(&d.data);
    buf
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
