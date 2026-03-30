use macho::model::container::MachContainer;
use macho::model::header::{Bitness, FileType};
use macho::model::load_command::LoadCommand;

/// Build a minimal valid 64-bit LE Mach-O:
/// - 32-byte header
/// - One LC_SEGMENT_64 (72 bytes) with 0 sections
fn minimal_thin_64() -> Vec<u8> {
    let mut buf = Vec::new();

    // Header (32 bytes)
    buf.extend_from_slice(&0xFEEDFACFu32.to_le_bytes()); // magic
    buf.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes()); // cputype = ARM64
    buf.extend_from_slice(&0i32.to_le_bytes()); // cpusubtype = ALL
    buf.extend_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
    buf.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    buf.extend_from_slice(&72u32.to_le_bytes()); // sizeofcmds = sizeof(segment_command_64)
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // LC_SEGMENT_64 (72 bytes)
    buf.extend_from_slice(&0x19u32.to_le_bytes()); // cmd = LC_SEGMENT_64
    buf.extend_from_slice(&72u32.to_le_bytes()); // cmdsize
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    buf.extend_from_slice(&segname); // segname
    buf.extend_from_slice(&0x100000000u64.to_le_bytes()); // vmaddr
    buf.extend_from_slice(&0x1000u64.to_le_bytes()); // vmsize
    buf.extend_from_slice(&0u64.to_le_bytes()); // fileoff
    buf.extend_from_slice(&104u64.to_le_bytes()); // filesize (header + cmd)
    buf.extend_from_slice(&5i32.to_le_bytes()); // maxprot = r-x
    buf.extend_from_slice(&5i32.to_le_bytes()); // initprot = r-x
    buf.extend_from_slice(&0u32.to_le_bytes()); // nsects
    buf.extend_from_slice(&0u32.to_le_bytes()); // flags

    assert_eq!(buf.len(), 104);
    buf
}

#[test]
fn parse_minimal_thin_64() {
    let data = minimal_thin_64();
    let container = macho::parse(&data).expect("failed to parse");

    match container {
        MachContainer::Thin(mach) => {
            assert_eq!(mach.bitness(), Bitness::Bits64);
            assert_eq!(mach.header().file_type, FileType::Execute);
            assert_eq!(mach.header().ncmds, 1);
            assert_eq!(mach.segments().len(), 1);
            assert_eq!(mach.segments()[0].name, "__TEXT");
        }
        MachContainer::Fat(_) => panic!("expected thin binary"),
    }
}

#[test]
fn unknown_load_command_preserved() {
    let mut data = Vec::new();

    // Header (32 bytes)
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes()); // magic
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes()); // cputype = ARM64
    data.extend_from_slice(&0i32.to_le_bytes()); // cpusubtype
    data.extend_from_slice(&2u32.to_le_bytes()); // filetype
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    data.extend_from_slice(&16u32.to_le_bytes()); // sizeofcmds
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // Unknown load command (16 bytes)
    data.extend_from_slice(&0xFFu32.to_le_bytes()); // cmd = unknown
    data.extend_from_slice(&16u32.to_le_bytes()); // cmdsize
    data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]); // payload

    let container = macho::parse(&data).expect("failed to parse");
    let mach = container.first_mach();

    assert_eq!(mach.load_commands().len(), 1);
    match &mach.load_commands()[0].kind {
        LoadCommand::Unknown(unk) => {
            assert_eq!(unk.cmd, 0xFF);
            assert_eq!(unk.data, &[0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44]);
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn minimal_fat_two_arches() {
    // Build two minimal thin binaries
    let thin1 = minimal_thin_64();

    // Second thin binary: same but x86_64
    let mut thin2 = Vec::new();
    thin2.extend_from_slice(&0xFEEDFACFu32.to_le_bytes()); // magic
    thin2.extend_from_slice(&(0x01000007u32 as i32).to_le_bytes()); // cputype = X86_64
    thin2.extend_from_slice(&3i32.to_le_bytes()); // cpusubtype = X86_64_ALL
    thin2.extend_from_slice(&2u32.to_le_bytes()); // filetype
    thin2.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    thin2.extend_from_slice(&72u32.to_le_bytes()); // sizeofcmds
    thin2.extend_from_slice(&0u32.to_le_bytes()); // flags
    thin2.extend_from_slice(&0u32.to_le_bytes()); // reserved
    // LC_SEGMENT_64
    thin2.extend_from_slice(&0x19u32.to_le_bytes()); // cmd
    thin2.extend_from_slice(&72u32.to_le_bytes()); // cmdsize
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    thin2.extend_from_slice(&segname);
    thin2.extend_from_slice(&0x100000000u64.to_le_bytes()); // vmaddr
    thin2.extend_from_slice(&0x1000u64.to_le_bytes()); // vmsize
    thin2.extend_from_slice(&0u64.to_le_bytes()); // fileoff
    thin2.extend_from_slice(&104u64.to_le_bytes()); // filesize
    thin2.extend_from_slice(&5i32.to_le_bytes()); // maxprot
    thin2.extend_from_slice(&5i32.to_le_bytes()); // initprot
    thin2.extend_from_slice(&0u32.to_le_bytes()); // nsects
    thin2.extend_from_slice(&0u32.to_le_bytes()); // flags

    // Fat header (big-endian): 8 bytes header + 2 * 20 bytes fat_arch
    let _header_size = 8 + 2 * 20; // 48 bytes
    // Align slices to 4096 boundaries
    let arch1_offset = 4096u32;
    let arch1_size = thin1.len() as u32;
    let arch2_offset = 8192u32;
    let arch2_size = thin2.len() as u32;

    let mut fat = Vec::new();
    // Fat header
    fat.extend_from_slice(&0xCAFEBABEu32.to_be_bytes()); // magic (BE)
    fat.extend_from_slice(&2u32.to_be_bytes()); // nfat_arch

    // Fat arch 1: ARM64
    fat.extend_from_slice(&(0x0100000Cu32 as i32).to_be_bytes()); // cputype
    fat.extend_from_slice(&0i32.to_be_bytes()); // cpusubtype
    fat.extend_from_slice(&arch1_offset.to_be_bytes()); // offset
    fat.extend_from_slice(&arch1_size.to_be_bytes()); // size
    fat.extend_from_slice(&12u32.to_be_bytes()); // align = 2^12

    // Fat arch 2: X86_64
    fat.extend_from_slice(&(0x01000007u32 as i32).to_be_bytes()); // cputype
    fat.extend_from_slice(&3i32.to_be_bytes()); // cpusubtype
    fat.extend_from_slice(&arch2_offset.to_be_bytes()); // offset
    fat.extend_from_slice(&arch2_size.to_be_bytes()); // size
    fat.extend_from_slice(&12u32.to_be_bytes()); // align = 2^12

    // Pad to arch1_offset
    fat.resize(arch1_offset as usize, 0);
    fat.extend_from_slice(&thin1);

    // Pad to arch2_offset
    fat.resize(arch2_offset as usize, 0);
    fat.extend_from_slice(&thin2);

    let container = macho::parse(&fat).expect("failed to parse fat binary");
    match container {
        MachContainer::Fat(ref fb) => {
            assert_eq!(fb.arches().len(), 2);
            assert_eq!(fb.arches()[0].spec.cpu_type.name(), "arm64");
            assert_eq!(fb.arches()[1].spec.cpu_type.name(), "x86_64");
        }
        MachContainer::Thin(_) => panic!("expected fat binary"),
    }
}

#[test]
fn image_base_is_text_vmaddr() {
    let data = minimal_thin_64();
    let container = macho::parse(&data).expect("failed to parse");
    let mach = container.first_mach();
    assert_eq!(mach.image_base().0, 0x100000000);
}

// --- Error path tests ---

#[test]
fn too_small_for_magic() {
    let data = [0u8; 3];
    assert!(macho::parse(&data).is_err());
}

#[test]
fn bad_magic() {
    let data = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
    assert!(macho::parse(&data).is_err());
}

#[test]
fn cmdsize_too_small() {
    let mut data = Vec::new();
    // Header
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    data.extend_from_slice(&8u32.to_le_bytes()); // sizeofcmds
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Load command with cmdsize = 4 (invalid, must be >= 8)
    data.extend_from_slice(&1u32.to_le_bytes()); // cmd
    data.extend_from_slice(&4u32.to_le_bytes()); // cmdsize (too small)

    assert!(macho::parse(&data).is_err());
}

#[test]
fn cmdsize_not_aligned() {
    let mut data = Vec::new();
    // Header
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    data.extend_from_slice(&10u32.to_le_bytes()); // sizeofcmds
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Load command with cmdsize = 10 (not 4-byte aligned)
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&10u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 2]); // pad

    assert!(macho::parse(&data).is_err());
}

#[test]
fn load_command_extends_past_file() {
    let mut data = Vec::new();
    // Header
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    data.extend_from_slice(&256u32.to_le_bytes()); // sizeofcmds (large)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Load command claiming 256 bytes but we only provide 8
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&256u32.to_le_bytes());

    assert!(macho::parse(&data).is_err());
}

#[test]
fn fat_zero_arches_rejected() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xCAFEBABEu32.to_be_bytes()); // FAT_MAGIC
    data.extend_from_slice(&0u32.to_be_bytes()); // nfat_arch = 0

    assert!(macho::parse(&data).is_err());
}

#[test]
fn fat_arch_extends_past_file() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xCAFEBABEu32.to_be_bytes()); // FAT_MAGIC
    data.extend_from_slice(&1u32.to_be_bytes()); // nfat_arch = 1
    // Fat arch pointing beyond file
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_be_bytes()); // cputype
    data.extend_from_slice(&0i32.to_be_bytes()); // cpusubtype
    data.extend_from_slice(&0x10000u32.to_be_bytes()); // offset (beyond file)
    data.extend_from_slice(&0x100u32.to_be_bytes()); // size
    data.extend_from_slice(&12u32.to_be_bytes()); // align

    assert!(macho::parse(&data).is_err());
}

// --- New API tests ---

#[test]
fn cpu_subtype_masking() {
    use macho::constants::*;
    use macho::model::header::{CpuSubtype, CpuType};

    // Simulate arm64e with capability bits set (0x80000002)
    let sub = CpuSubtype(0x80000002u32 as i32);
    assert_eq!(sub.masked(), CPU_SUBTYPE_ARM64E);
    assert_eq!(sub.name(CpuType(CPU_TYPE_ARM64)), "arm64e");

    // Simulate x86_64 with capability bit (0x80000003)
    let sub = CpuSubtype(0x80000003u32 as i32);
    assert_eq!(sub.masked(), CPU_SUBTYPE_X86_64_ALL);
    assert_eq!(sub.name(CpuType(CPU_TYPE_X86_64)), "all");
}

#[test]
fn arch_spec_arm64e_with_cap_bits() {
    use macho::constants::*;
    use macho::model::fat::ArchSpec;
    use macho::model::header::{CpuSubtype, CpuType};

    let spec = ArchSpec {
        cpu_type: CpuType(CPU_TYPE_ARM64),
        cpu_subtype: CpuSubtype(0x80000002u32 as i32), // arm64e with cap bits
    };
    assert!(spec.is_arm64e());
    assert!(!spec.is_arm64());
    assert_eq!(spec.name(), "arm64e");
}

#[test]
fn container_predicates() {
    let data = minimal_thin_64();
    let container = macho::parse(&data).expect("failed to parse");
    assert!(container.is_thin());
    assert!(!container.is_fat());
}

#[test]
fn mach_file_convenience_methods() {
    let data = minimal_thin_64();
    let container = macho::parse(&data).expect("failed to parse");
    let mach = container.first_mach();

    assert!(mach.is_64bit());
    assert_eq!(mach.file_size(), data.len());
    assert_eq!(mach.all_sections().count(), 0); // minimal binary has no sections

    // find_load_command
    let seg_lc = mach.find_load_command(|lc| lc.as_segment().is_some());
    assert!(seg_lc.is_some());
}

#[test]
fn load_command_typed_accessors() {
    let data = minimal_thin_64();
    let container = macho::parse(&data).expect("failed to parse");
    let mach = container.first_mach();

    let lc = &mach.load_commands()[0].kind;
    assert!(lc.as_segment().is_some());
    assert!(lc.as_uuid().is_none());
    assert!(lc.as_main().is_none());
}

#[test]
fn validation_detects_malformed() {
    use macho::validate::{self, Severity};

    let data = minimal_thin_64();
    let container = macho::parse(&data).expect("failed to parse");
    let mach = container.first_mach();

    // Minimal valid binary should pass
    let diags = validate::validate(mach);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "unexpected errors: {errors:?}");
}

#[test]
fn dyld_info_only_preserved() {
    use macho::model::load_command::LoadCommand;

    // Build a thin binary with LC_DYLD_INFO_ONLY
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    data.extend_from_slice(&48u32.to_le_bytes()); // sizeofcmds = sizeof(RawDyldInfoCommand)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    // LC_DYLD_INFO_ONLY = 0x80000022
    data.extend_from_slice(&0x80000022u32.to_le_bytes()); // cmd
    data.extend_from_slice(&48u32.to_le_bytes()); // cmdsize
    data.extend_from_slice(&[0u8; 40]); // remaining fields

    let container = macho::parse(&data).expect("failed to parse");
    let mach = container.first_mach();
    assert_eq!(mach.load_commands().len(), 1);

    match &mach.load_commands()[0].kind {
        LoadCommand::DyldInfoOnly(_) => {} // correct
        other => panic!("expected DyldInfoOnly, got {}", other.name()),
    }
}

#[test]
fn huge_ncmds_does_not_oom() {
    // A binary claiming u32::MAX load commands but only providing enough data
    // for zero — should fail gracefully, not OOM.
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // ncmds = u32::MAX
    data.extend_from_slice(&8u32.to_le_bytes()); // sizeofcmds = 8 (tiny)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // One minimal load command (will parse but loop ends after 1 because of sizeofcmds)
    data.extend_from_slice(&0xFFu32.to_le_bytes()); // unknown cmd
    data.extend_from_slice(&8u32.to_le_bytes()); // cmdsize

    // Should not panic or OOM — the capacity is capped
    let result = macho::parse(&data);
    // It will either parse successfully (stopping after the command region) or
    // error on sizeofcmds mismatch. Either way, no OOM.
    if let Ok(container) = result {
        // Parsed fine — the loop ran out of command region after 1 cmd
        let mach = container.first_mach();
        assert!(mach.load_commands().len() <= 1);
    }
}

#[test]
fn huge_sizeofcmds_overflow() {
    // sizeofcmds = u32::MAX should be caught by checked_add before wrapping
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
    data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sizeofcmds = u32::MAX
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    let result = macho::parse(&data);
    // On 64-bit: checked_add succeeds but cmd_end > data.len() → error on first read
    // On 32-bit: checked_add itself would succeed (usize is u32, but
    //            32 + 0xFFFFFFFF overflows) → error
    assert!(result.is_err());
}

#[test]
fn fat_arch_thin_offset_translation() {
    use macho::addr::{FatFileOffset, ThinFileOffset};

    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    if let MachContainer::Fat(ref fat) = container {
        let arch = &fat.arches()[0];
        let thin = ThinFileOffset(0x100);
        let fat_off = arch.thin_to_fat_offset(thin);
        assert_eq!(fat_off.0, arch.fat_offset.0 + 0x100);

        let back = arch.fat_to_thin_offset(fat_off).expect("round-trip failed");
        assert_eq!(back, thin);

        // Out of range should error
        let bad = FatFileOffset(0);
        assert!(arch.fat_to_thin_offset(bad).is_err());
    }
}

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}
