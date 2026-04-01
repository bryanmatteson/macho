use macho::model::container::MachoContainer;
use macho::model::header::{Bitness, FileType};
use macho::model::load_command::LoadCommand;

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn parse_fat_binary() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    match &container {
        MachoContainer::Fat(fat) => {
            assert!(
                !fat.arches().is_empty(),
                "expected at least one architecture"
            );
            for arch in fat.arches() {
                assert!(!arch.macho.segments().is_empty());
                assert!(!arch.macho.load_commands().is_empty());
            }
        }
        MachoContainer::Thin(_) => {
            // On some systems /usr/bin/true might be thin; that's fine too
            let macho = container.first_mach();
            assert!(!macho.segments().is_empty());
        }
    }
}

#[test]
fn parse_thin_from_fat_arch() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    assert_eq!(macho.bitness(), Bitness::Bits64);
    assert_eq!(macho.header().file_type, FileType::Execute);

    // Should have a __TEXT segment
    let text_seg = macho
        .segments()
        .iter()
        .find(|s| s.name == "__TEXT")
        .expect("expected __TEXT segment");

    assert!(text_seg.vm_size > 0);
    assert!(!text_seg.sections.is_empty());
}

#[test]
fn address_translation_round_trip() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    // Find a non-zerofill section with data
    let section = macho
        .all_sections()
        .find(|s| s.size > 0 && !s.section_type.is_zerofill() && s.offset.0 > 0)
        .expect("expected a non-empty section");

    let map = macho.address_map();

    // VA -> ThinFileOffset should match section's offset
    let offset = map
        .va_to_thin_offset(section.addr)
        .expect("va_to_thin_offset failed");
    assert_eq!(
        offset, section.offset,
        "VA {:#x} should map to file offset {:#x}, got {:#x}",
        section.addr.0, section.offset.0, offset.0
    );

    // Round-trip: ThinFileOffset -> VA -> ThinFileOffset
    let va = map
        .thin_offset_to_va(offset)
        .expect("thin_offset_to_va failed");
    let offset2 = map
        .va_to_thin_offset(va)
        .expect("round-trip va_to_thin_offset failed");
    assert_eq!(offset, offset2, "round-trip failed");
}

#[test]
fn segments_contain_correct_sections() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        for seg in macho.segments() {
            for sect in &seg.sections {
                assert_eq!(
                    sect.segment_name, seg.name,
                    "section {}'s segment_name {:?} doesn't match parent segment {:?}",
                    sect.section_name, sect.segment_name, seg.name
                );

                if !sect.section_type.is_zerofill() && sect.size > 0 {
                    let sect_end = sect.offset.0 + sect.size;
                    let seg_end = seg.file_offset.0 + seg.file_size;
                    assert!(
                        sect.offset.0 >= seg.file_offset.0 && sect_end <= seg_end,
                        "section {} offset range {:#x}..{:#x} outside segment {} range {:#x}..{:#x}",
                        sect.section_name,
                        sect.offset.0,
                        sect_end,
                        seg.name,
                        seg.file_offset.0,
                        seg_end
                    );
                }
            }
        }
    }
}

#[test]
fn uuid_present() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();
    assert!(macho.uuid().is_some(), "expected UUID to be present");
}

#[test]
fn build_version_present() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let has_build_version = macho
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::BuildVersion(_)));

    assert!(has_build_version, "expected at least one LC_BUILD_VERSION");
}

#[test]
fn read_bytes_at_va() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    // Read some bytes from the text section
    let section = macho
        .section("__TEXT", "__text")
        .expect("expected __text section");
    let bytes = macho
        .read_bytes_at_va(section.addr, 4)
        .expect("read_bytes_at_va failed");
    assert_eq!(bytes.len(), 4);
}

#[test]
fn section_bytes_accessor() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let bytes = macho
        .section_bytes("__TEXT", "__text")
        .expect("section_bytes failed");
    assert!(!bytes.is_empty());
}

#[test]
fn validation_passes_for_system_binary() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        let diags = macho::model::validate::validate(macho);
        let errors: Vec<_> = diags
            .iter()
            .filter(|d| d.severity == macho::model::validate::Severity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "unexpected validation errors: {errors:?}"
        );
    }
}
