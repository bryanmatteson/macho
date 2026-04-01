use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::io::endian::Endian;
use crate::format::io::pod::{self, *};
use crate::format::sections::{parse_sections_32, parse_sections_64};
use crate::model::addr::{ThinFileOffset, Va};
use crate::model::load_command::*;
use crate::model::names::SegmentName;
use crate::model::segment::Segment;

pub fn parse_load_commands(
    data: &[u8],
    endian: Endian,
    _bitness: crate::model::header::Bitness,
    offset: usize,
    ncmds: u32,
    sizeofcmds: u32,
) -> Result<(Vec<ParsedLoadCommand>, Vec<Segment>)> {
    // Cap capacity to avoid OOM from malformed ncmds. Each command is at least
    // 8 bytes, so sizeofcmds / 8 is the theoretical max. Also cap to a
    // reasonable absolute limit.
    let max_cmds = (sizeofcmds as usize / 8).min(ncmds as usize).min(10_000);
    let mut commands = Vec::with_capacity(max_cmds);
    let mut segments: Vec<Segment> = Vec::new();
    let mut cur = offset;
    let cmd_end = offset.checked_add(sizeofcmds as usize).ok_or_else(|| {
        Error::Command(format!(
            "sizeofcmds {sizeofcmds:#x} overflows when added to header offset {offset:#x}"
        ))
    })?;

    for _ in 0..ncmds {
        if cur + 8 > data.len() || cur + 8 > cmd_end {
            return Err(Error::Command(
                "load command extends beyond sizeofcmds".into(),
            ));
        }

        let raw_lc: RawLoadCommand = pod::read_pod(data, cur)?;
        let cmd = endian.interpret_u32(raw_lc.cmd);
        let cmdsize = endian.interpret_u32(raw_lc.cmdsize) as usize;

        if cmdsize < 8 || cmdsize % 4 != 0 {
            return Err(Error::Command(format!(
                "load command at offset {cur:#x} has invalid cmdsize {cmdsize} \
                 (must be >= 8 and 4-byte aligned)"
            )));
        }
        if cur + cmdsize > data.len() || cur + cmdsize > cmd_end {
            return Err(Error::Command(format!(
                "load command at offset {cur:#x} extends beyond file/command region"
            )));
        }

        let cmd_data = &data[cur..cur + cmdsize];
        let kind = parse_single_command(data, cmd_data, cur, cmd, endian, &mut segments)?;

        commands.push(ParsedLoadCommand {
            kind,
            file_offset: ThinFileOffset(cur as u64),
            raw_size: cmdsize as u32,
        });

        cur += cmdsize;
    }

    Ok((commands, segments))
}

fn parse_single_command(
    file_data: &[u8],
    cmd_data: &[u8],
    cmd_offset: usize,
    cmd: u32,
    endian: Endian,
    segments: &mut Vec<Segment>,
) -> Result<LoadCommand> {
    match cmd {
        LC_SEGMENT => parse_segment_32(file_data, cmd_offset, endian, segments),
        LC_SEGMENT_64 => parse_segment_64(file_data, cmd_offset, endian, segments),
        LC_SYMTAB => parse_symtab(cmd_data, endian),
        LC_DYSYMTAB => parse_dysymtab(cmd_data, endian),
        LC_UUID => parse_uuid(cmd_data),
        LC_BUILD_VERSION => parse_build_version(cmd_data, endian),
        LC_MAIN => parse_main(cmd_data, endian),
        LC_SOURCE_VERSION => parse_source_version(cmd_data, endian),
        LC_DYLD_INFO => parse_dyld_info(cmd_data, endian, false),
        LC_DYLD_INFO_ONLY => parse_dyld_info(cmd_data, endian, true),
        LC_CODE_SIGNATURE => parse_linkedit(cmd_data, endian).map(LoadCommand::CodeSignature),
        LC_SEGMENT_SPLIT_INFO => {
            parse_linkedit(cmd_data, endian).map(LoadCommand::SegmentSplitInfo)
        }
        LC_FUNCTION_STARTS => parse_linkedit(cmd_data, endian).map(LoadCommand::FunctionStarts),
        LC_DATA_IN_CODE => parse_linkedit(cmd_data, endian).map(LoadCommand::DataInCode),
        LC_DYLIB_CODE_SIGN_DRS => {
            parse_linkedit(cmd_data, endian).map(LoadCommand::DylibCodeSignDrs)
        }
        LC_LINKER_OPTIMIZATION_HINT => {
            parse_linkedit(cmd_data, endian).map(LoadCommand::LinkerOptimizationHint)
        }
        LC_DYLD_EXPORTS_TRIE => parse_linkedit(cmd_data, endian).map(LoadCommand::DyldExportsTrie),
        LC_DYLD_CHAINED_FIXUPS => {
            parse_linkedit(cmd_data, endian).map(LoadCommand::DyldChainedFixups)
        }
        LC_ATOM_INFO => parse_linkedit(cmd_data, endian).map(LoadCommand::AtomInfo),
        LC_FUNCTION_VARIANTS => parse_linkedit(cmd_data, endian).map(LoadCommand::FunctionVariants),
        LC_FUNCTION_VARIANT_FIXUPS => {
            parse_linkedit(cmd_data, endian).map(LoadCommand::FunctionVariantFixups)
        }
        LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
        | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => parse_dylib(cmd_data, cmd, endian),
        LC_RPATH => parse_string_cmd(cmd_data, endian).map(LoadCommand::Rpath),
        LC_TARGET_TRIPLE => parse_string_cmd(cmd_data, endian).map(LoadCommand::TargetTriple),
        LC_LOAD_DYLINKER => parse_string_cmd(cmd_data, endian).map(LoadCommand::LoadDylinker),
        LC_ID_DYLINKER => parse_string_cmd(cmd_data, endian).map(LoadCommand::IdDylinker),
        LC_DYLD_ENVIRONMENT => parse_string_cmd(cmd_data, endian).map(LoadCommand::DyldEnvironment),
        LC_SUB_FRAMEWORK => parse_string_cmd(cmd_data, endian).map(LoadCommand::SubFramework),
        LC_SUB_UMBRELLA => parse_string_cmd(cmd_data, endian).map(LoadCommand::SubUmbrella),
        LC_SUB_CLIENT => parse_string_cmd(cmd_data, endian).map(LoadCommand::SubClient),
        LC_SUB_LIBRARY => parse_string_cmd(cmd_data, endian).map(LoadCommand::SubLibrary),
        LC_VERSION_MIN_MACOSX => {
            parse_version_min(cmd_data, endian).map(LoadCommand::VersionMinMacOS)
        }
        LC_VERSION_MIN_IPHONEOS => {
            parse_version_min(cmd_data, endian).map(LoadCommand::VersionMinIOS)
        }
        LC_VERSION_MIN_TVOS => parse_version_min(cmd_data, endian).map(LoadCommand::VersionMinTvOS),
        LC_VERSION_MIN_WATCHOS => {
            parse_version_min(cmd_data, endian).map(LoadCommand::VersionMinWatchOS)
        }
        LC_ENCRYPTION_INFO => {
            parse_encryption_info(cmd_data, endian).map(LoadCommand::EncryptionInfo)
        }
        LC_ENCRYPTION_INFO_64 => {
            parse_encryption_info_64(cmd_data, endian).map(LoadCommand::EncryptionInfo64)
        }
        LC_LINKER_OPTION => parse_linker_option(cmd_data, endian),
        LC_NOTE => parse_note(cmd_data, endian),
        LC_FILESET_ENTRY => parse_fileset_entry(cmd_data, endian),
        LC_PREBIND_CKSUM => parse_prebind_cksum(cmd_data, endian),
        LC_TWOLEVEL_HINTS => parse_twolevel_hints(cmd_data, endian),
        LC_ROUTINES => parse_routines(cmd_data, endian).map(LoadCommand::Routines),
        LC_ROUTINES_64 => parse_routines_64(cmd_data, endian).map(LoadCommand::Routines64),
        LC_THREAD => Ok(LoadCommand::Thread(RawData {
            data: cmd_data[8..].to_vec(),
        })),
        LC_UNIXTHREAD => Ok(LoadCommand::UnixThread(RawData {
            data: cmd_data[8..].to_vec(),
        })),
        LC_PREBOUND_DYLIB => Ok(LoadCommand::PreboundDylib(RawData {
            data: cmd_data[8..].to_vec(),
        })),
        LC_IDENT => Ok(LoadCommand::Ident(RawData {
            data: cmd_data[8..].to_vec(),
        })),
        _ => Ok(LoadCommand::Unknown(UnknownLoadCommand {
            cmd,
            data: cmd_data[8..].to_vec(),
        })),
    }
}

fn parse_segment_32(
    data: &[u8],
    offset: usize,
    endian: Endian,
    segments: &mut Vec<Segment>,
) -> Result<LoadCommand> {
    let raw: RawSegmentCommand32 = pod::read_pod(data, offset)?;
    let nsects = endian.interpret_u32(raw.nsects);
    let sect_offset = offset + size_of::<RawSegmentCommand32>();
    let sections = parse_sections_32(data, endian, sect_offset, nsects)?;

    segments.push(Segment {
        name: SegmentName::from_bytes(raw.segname),
        vm_addr: Va(endian.interpret_u32(raw.vmaddr) as u64),
        vm_size: endian.interpret_u32(raw.vmsize) as u64,
        file_offset: ThinFileOffset(endian.interpret_u32(raw.fileoff) as u64),
        file_size: endian.interpret_u32(raw.filesize) as u64,
        max_prot: VmProtection::from_bits_truncate(endian.interpret_i32(raw.maxprot)),
        init_prot: VmProtection::from_bits_truncate(endian.interpret_i32(raw.initprot)),
        flags: SegmentFlags::from_bits_truncate(endian.interpret_u32(raw.flags)),
        sections,
    });

    Ok(LoadCommand::Segment32(SegmentCommandData {
        segment_index: segments.len() - 1,
    }))
}

fn parse_segment_64(
    data: &[u8],
    offset: usize,
    endian: Endian,
    segments: &mut Vec<Segment>,
) -> Result<LoadCommand> {
    let raw: RawSegmentCommand64 = pod::read_pod(data, offset)?;
    let nsects = endian.interpret_u32(raw.nsects);
    let sect_offset = offset + size_of::<RawSegmentCommand64>();
    let sections = parse_sections_64(data, endian, sect_offset, nsects)?;

    segments.push(Segment {
        name: SegmentName::from_bytes(raw.segname),
        vm_addr: Va(endian.interpret_u64(raw.vmaddr)),
        vm_size: endian.interpret_u64(raw.vmsize),
        file_offset: ThinFileOffset(endian.interpret_u64(raw.fileoff)),
        file_size: endian.interpret_u64(raw.filesize),
        max_prot: VmProtection::from_bits_truncate(endian.interpret_i32(raw.maxprot)),
        init_prot: VmProtection::from_bits_truncate(endian.interpret_i32(raw.initprot)),
        flags: SegmentFlags::from_bits_truncate(endian.interpret_u32(raw.flags)),
        sections,
    });

    Ok(LoadCommand::Segment64(SegmentCommandData {
        segment_index: segments.len() - 1,
    }))
}

fn parse_symtab(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawSymtabCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::Symtab(SymtabData {
        sym_offset: endian.interpret_u32(raw.symoff),
        nsyms: endian.interpret_u32(raw.nsyms),
        str_offset: endian.interpret_u32(raw.stroff),
        str_size: endian.interpret_u32(raw.strsize),
    }))
}

fn parse_dysymtab(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawDysymtabCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::Dysymtab(DysymtabData {
        ilocalsym: endian.interpret_u32(raw.ilocalsym),
        nlocalsym: endian.interpret_u32(raw.nlocalsym),
        iextdefsym: endian.interpret_u32(raw.iextdefsym),
        nextdefsym: endian.interpret_u32(raw.nextdefsym),
        iundefsym: endian.interpret_u32(raw.iundefsym),
        nundefsym: endian.interpret_u32(raw.nundefsym),
        tocoff: endian.interpret_u32(raw.tocoff),
        ntoc: endian.interpret_u32(raw.ntoc),
        modtaboff: endian.interpret_u32(raw.modtaboff),
        nmodtab: endian.interpret_u32(raw.nmodtab),
        extrefsymoff: endian.interpret_u32(raw.extrefsymoff),
        nextrefsyms: endian.interpret_u32(raw.nextrefsyms),
        indirectsymoff: endian.interpret_u32(raw.indirectsymoff),
        nindirectsyms: endian.interpret_u32(raw.nindirectsyms),
        extreloff: endian.interpret_u32(raw.extreloff),
        nextrel: endian.interpret_u32(raw.nextrel),
        locreloff: endian.interpret_u32(raw.locreloff),
        nlocrel: endian.interpret_u32(raw.nlocrel),
    }))
}

fn parse_uuid(cmd_data: &[u8]) -> Result<LoadCommand> {
    let raw: RawUuidCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::Uuid(UuidData { uuid: raw.uuid }))
}

fn parse_build_version(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawBuildVersionCommand = pod::read_pod(cmd_data, 0)?;
    let ntools = endian.interpret_u32(raw.ntools);
    let tool_offset = size_of::<RawBuildVersionCommand>();
    let max_tools =
        ((cmd_data.len() - tool_offset) / size_of::<RawBuildToolVersion>()).min(ntools as usize);
    let mut tools = Vec::with_capacity(max_tools);

    for i in 0..ntools as usize {
        let raw_tool: RawBuildToolVersion =
            pod::read_pod(cmd_data, tool_offset + i * size_of::<RawBuildToolVersion>())?;
        tools.push(BuildToolVersion {
            tool: Tool(endian.interpret_u32(raw_tool.tool)),
            version: PackedVersion(endian.interpret_u32(raw_tool.version)),
        });
    }

    Ok(LoadCommand::BuildVersion(BuildVersionData {
        platform: Platform(endian.interpret_u32(raw.platform)),
        minos: PackedVersion(endian.interpret_u32(raw.minos)),
        sdk: PackedVersion(endian.interpret_u32(raw.sdk)),
        tools,
    }))
}

fn parse_main(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawEntryPointCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::Main(EntryPointData {
        entry_offset: endian.interpret_u64(raw.entryoff),
        stack_size: endian.interpret_u64(raw.stacksize),
    }))
}

fn parse_source_version(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawSourceVersionCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::SourceVersion(SourceVersionData {
        version: SourceVersion(endian.interpret_u64(raw.version)),
    }))
}

fn parse_dyld_info(cmd_data: &[u8], endian: Endian, only: bool) -> Result<LoadCommand> {
    let raw: RawDyldInfoCommand = pod::read_pod(cmd_data, 0)?;
    let data = DyldInfoData {
        rebase_off: endian.interpret_u32(raw.rebase_off),
        rebase_size: endian.interpret_u32(raw.rebase_size),
        bind_off: endian.interpret_u32(raw.bind_off),
        bind_size: endian.interpret_u32(raw.bind_size),
        weak_bind_off: endian.interpret_u32(raw.weak_bind_off),
        weak_bind_size: endian.interpret_u32(raw.weak_bind_size),
        lazy_bind_off: endian.interpret_u32(raw.lazy_bind_off),
        lazy_bind_size: endian.interpret_u32(raw.lazy_bind_size),
        export_off: endian.interpret_u32(raw.export_off),
        export_size: endian.interpret_u32(raw.export_size),
    };
    Ok(if only {
        LoadCommand::DyldInfoOnly(data)
    } else {
        LoadCommand::DyldInfo(data)
    })
}

fn parse_linkedit(cmd_data: &[u8], endian: Endian) -> Result<LinkeditData> {
    let raw: RawLinkeditDataCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LinkeditData {
        data_offset: endian.interpret_u32(raw.dataoff),
        data_size: endian.interpret_u32(raw.datasize),
    })
}

fn parse_dylib(cmd_data: &[u8], cmd: u32, endian: Endian) -> Result<LoadCommand> {
    let raw: RawDylibCommand = pod::read_pod(cmd_data, 0)?;
    let name_off = endian.interpret_u32(raw.name_offset) as usize;
    let marker = endian.interpret_u32(raw.timestamp);

    // dylib_use_command: same LC_* cmd values but with DYLIB_USE_MARKER in the
    // timestamp field. The name_offset, current_version, and compat_version
    // fields are at the same offsets as the standard dylib_command, so we can
    // read them the same way. The additional flags field at byte 24 is stored
    // in raw.compatibility_version position for the standard struct — we don't
    // parse it separately yet but the name extraction is correct.
    let is_dylib_use = marker == DYLIB_USE_MARKER;

    let name = read_lc_string(cmd_data, name_off)?;

    let data = DylibData {
        name,
        timestamp: if is_dylib_use { 0 } else { marker },
        current_version: PackedVersion(endian.interpret_u32(raw.current_version)),
        compatibility_version: PackedVersion(endian.interpret_u32(raw.compatibility_version)),
    };

    Ok(match cmd {
        LC_ID_DYLIB => LoadCommand::IdDylib(data),
        LC_LOAD_WEAK_DYLIB => LoadCommand::LoadWeakDylib(data),
        LC_REEXPORT_DYLIB => LoadCommand::ReexportDylib(data),
        LC_LAZY_LOAD_DYLIB => LoadCommand::LazyLoadDylib(data),
        LC_LOAD_UPWARD_DYLIB => LoadCommand::LoadUpwardDylib(data),
        _ => LoadCommand::LoadDylib(data),
    })
}

fn parse_string_cmd(cmd_data: &[u8], endian: Endian) -> Result<StringData> {
    let raw: RawStringCommand = pod::read_pod(cmd_data, 0)?;
    let str_off = endian.interpret_u32(raw.string_offset) as usize;
    let value = read_lc_string(cmd_data, str_off)?;
    Ok(StringData { value })
}

fn parse_version_min(cmd_data: &[u8], endian: Endian) -> Result<VersionMinData> {
    let raw: RawVersionMinCommand = pod::read_pod(cmd_data, 0)?;
    Ok(VersionMinData {
        version: PackedVersion(endian.interpret_u32(raw.version)),
        sdk: PackedVersion(endian.interpret_u32(raw.sdk)),
    })
}

fn parse_encryption_info(cmd_data: &[u8], endian: Endian) -> Result<EncryptionInfoData> {
    let raw: RawEncryptionInfoCommand = pod::read_pod(cmd_data, 0)?;
    Ok(EncryptionInfoData {
        crypt_offset: endian.interpret_u32(raw.cryptoff),
        crypt_size: endian.interpret_u32(raw.cryptsize),
        crypt_id: endian.interpret_u32(raw.cryptid),
    })
}

fn parse_encryption_info_64(cmd_data: &[u8], endian: Endian) -> Result<EncryptionInfoData> {
    let raw: RawEncryptionInfoCommand64 = pod::read_pod(cmd_data, 0)?;
    Ok(EncryptionInfoData {
        crypt_offset: endian.interpret_u32(raw.cryptoff),
        crypt_size: endian.interpret_u32(raw.cryptsize),
        crypt_id: endian.interpret_u32(raw.cryptid),
    })
}

fn parse_linker_option(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawLinkerOptionCommand = pod::read_pod(cmd_data, 0)?;
    let count = endian.interpret_u32(raw.count) as usize;
    let payload = &cmd_data[size_of::<RawLinkerOptionCommand>()..];

    let mut strings = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if pos >= payload.len() {
            break;
        }
        match payload[pos..].iter().position(|&b| b == 0) {
            Some(null_pos) => {
                let s = String::from_utf8_lossy(&payload[pos..pos + null_pos]).into_owned();
                strings.push(s);
                pos += null_pos + 1;
            }
            None => {
                let s = String::from_utf8_lossy(&payload[pos..]).into_owned();
                strings.push(s);
                break;
            }
        }
    }

    Ok(LoadCommand::LinkerOption(LinkerOptionData { strings }))
}

fn parse_note(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawNoteCommand = pod::read_pod(cmd_data, 0)?;
    let owner = SegmentName::from_bytes(raw.data_owner);
    Ok(LoadCommand::Note(NoteData {
        data_owner: owner.as_str_lossy().into_owned(),
        offset: endian.interpret_u64(raw.offset),
        size: endian.interpret_u64(raw.size),
    }))
}

fn parse_fileset_entry(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawFilesetEntryCommand = pod::read_pod(cmd_data, 0)?;
    let id_off = endian.interpret_u32(raw.entry_id_offset) as usize;
    let entry_id = read_lc_string(cmd_data, id_off)?;

    Ok(LoadCommand::FilesetEntry(FilesetEntryData {
        vm_addr: endian.interpret_u64(raw.vmaddr),
        file_offset: endian.interpret_u64(raw.fileoff),
        entry_id,
    }))
}

fn parse_prebind_cksum(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawPrebindCksumCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::PrebindCksum(PrebindCksumData {
        cksum: endian.interpret_u32(raw.cksum),
    }))
}

fn parse_twolevel_hints(cmd_data: &[u8], endian: Endian) -> Result<LoadCommand> {
    let raw: RawTwolevelHintsCommand = pod::read_pod(cmd_data, 0)?;
    Ok(LoadCommand::TwolevelHints(TwolevelHintsData {
        offset: endian.interpret_u32(raw.offset),
        nhints: endian.interpret_u32(raw.nhints),
    }))
}

fn parse_routines(cmd_data: &[u8], endian: Endian) -> Result<RoutinesData> {
    let raw: RawRoutinesCommand = pod::read_pod(cmd_data, 0)?;
    Ok(RoutinesData {
        init_address: endian.interpret_u32(raw.init_address) as u64,
        init_module: endian.interpret_u32(raw.init_module) as u64,
    })
}

fn parse_routines_64(cmd_data: &[u8], endian: Endian) -> Result<RoutinesData> {
    let raw: RawRoutinesCommand64 = pod::read_pod(cmd_data, 0)?;
    Ok(RoutinesData {
        init_address: endian.interpret_u64(raw.init_address),
        init_module: endian.interpret_u64(raw.init_module),
    })
}

/// Read a null-terminated string from within a load command's data.
/// `str_offset` is relative to the start of the load command.
fn read_lc_string(cmd_data: &[u8], str_offset: usize) -> Result<String> {
    if str_offset >= cmd_data.len() {
        return Err(Error::Command(format!(
            "lc_str offset {str_offset:#x} is beyond command size {}",
            cmd_data.len()
        )));
    }
    let slice = &cmd_data[str_offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    Ok(String::from_utf8_lossy(&slice[..end]).into_owned())
}
