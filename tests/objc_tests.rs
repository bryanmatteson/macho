use macho::objc::{ObjCMetadata, parse_objc_metadata};

fn load_plutil() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/plutil").expect("failed to open /usr/bin/plutil");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn parse_objc_classes() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    // plutil has ObjC classes on arm64e
    for mach in container.mach_files() {
        match parse_objc_metadata(mach) {
            Ok(meta) => {
                if !meta.classes.is_empty() {
                    // Verify class names are valid strings
                    for class in &meta.classes {
                        assert!(!class.name.is_empty(), "class has empty name");
                    }

                    // plutil should have PLUContext
                    let has_plu = meta.classes.iter().any(|c| c.name.contains("PLU"));
                    assert!(has_plu, "expected PLU* classes in plutil");
                    return;
                }
            }
            Err(_) => continue,
        }
    }
    panic!("no ObjC classes found in any arch of /usr/bin/plutil");
}

#[test]
fn class_has_superclass() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        if let Ok(meta) = parse_objc_metadata(mach) {
            for class in &meta.classes {
                if class.name == "PLUContext" {
                    assert_eq!(
                        class.superclass_name.as_deref(),
                        Some("NSObject"),
                        "PLUContext should inherit from NSObject"
                    );
                    return;
                }
            }
        }
    }
}

#[test]
fn class_has_ivars() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        if let Ok(meta) = parse_objc_metadata(mach) {
            for class in &meta.classes {
                if class.name == "PLUContext" {
                    assert!(!class.ivars.is_empty(), "PLUContext should have ivars");
                    // Check that ivar names are reasonable
                    let has_command = class.ivars.iter().any(|i| i.name == "_command");
                    assert!(has_command, "PLUContext should have _command ivar");
                    return;
                }
            }
        }
    }
}

#[test]
fn class_has_properties() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        if let Ok(meta) = parse_objc_metadata(mach) {
            for class in &meta.classes {
                if class.name == "PLUContext" {
                    assert!(
                        !class.properties.is_empty(),
                        "PLUContext should have properties"
                    );
                    return;
                }
            }
        }
    }
}

#[test]
fn header_rendering() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        if let Ok(meta) = parse_objc_metadata(mach) {
            for class in &meta.classes {
                let header = macho::objc::render::render_class_header(class);
                assert!(header.contains("@interface"));
                assert!(header.contains("@end"));
                assert!(header.contains(&class.name));
            }
        }
    }
}

#[test]
fn no_objc_in_minimal_binary() {
    // Build a minimal binary with no ObjC sections
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // LC_SEGMENT_64
    data.extend_from_slice(&0x19u32.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    data.extend_from_slice(&segname);
    data.extend_from_slice(&0x100000000u64.to_le_bytes());
    data.extend_from_slice(&0x1000u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&104u64.to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    let container = macho::parse(&data).expect("parse failed");
    let mach = container.first_mach();

    // Should gracefully handle missing ObjC sections
    if let Ok(meta) = parse_objc_metadata(mach) {
        assert!(meta.classes.is_empty());
        assert!(meta.categories.is_empty());
        assert!(meta.protocols.is_empty());
    }
}

#[test]
fn objc_metadata_via_ext_trait() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let meta: Result<ObjCMetadata, _> = mach.ext();
        if let Ok(meta) = meta {
            if !meta.classes.is_empty() {
                return; // success
            }
        }
    }
}
