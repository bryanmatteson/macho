#![cfg(feature = "cli")]

use macho::metadata::objc::parse_objc_metadata;

#[cfg(target_os = "macos")]
use macho::metadata::objc::ObjCMetadata;

#[cfg(target_os = "macos")]
fn load_plutil() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/plutil").expect("failed to open /usr/bin/plutil");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
#[cfg(target_os = "macos")]
fn parse_objc_classes() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    // plutil has ObjC classes on arm64e
    for macho in container.macho_files() {
        match parse_objc_metadata(macho) {
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
#[cfg(target_os = "macos")]
fn class_has_superclass() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        if let Ok(meta) = parse_objc_metadata(macho) {
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
#[cfg(target_os = "macos")]
fn class_has_ivars() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        if let Ok(meta) = parse_objc_metadata(macho) {
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
#[cfg(target_os = "macos")]
fn class_has_properties() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        if let Ok(meta) = parse_objc_metadata(macho) {
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
#[cfg(target_os = "macos")]
fn header_rendering() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        if let Ok(meta) = parse_objc_metadata(macho) {
            for class in &meta.classes {
                let header = macho::analysis::reconstruct::objc::render::render_class_header(class);
                assert!(header.contains("@interface"));
                assert!(header.contains("@end"));
                assert!(header.contains(&class.name));
                if class.name == "PLUContext" {
                    assert!(header.contains("@property (strong) NSString *format;"));
                    assert!(header.contains("- (NSString *)format;"));
                    assert!(header.contains("- (void)setFormat:(NSString *)arg1;"));
                    assert!(header.contains(
                        "- (id)initWithArguments:(id)arg1 outputFileHandle:(id)arg2 errorFileHandle:(id)arg3;"
                    ));
                    return;
                }
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
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    // Should gracefully handle missing ObjC sections
    if let Ok(meta) = parse_objc_metadata(macho) {
        assert!(meta.classes.is_empty());
        assert!(meta.categories.is_empty());
        assert!(meta.protocols.is_empty());
    }
}

#[test]
#[cfg(target_os = "macos")]
fn objc_metadata_via_ext_trait() {
    let mmap = load_plutil();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        let meta: Result<ObjCMetadata, _> = macho.ext();
        if let Ok(meta) = meta
            && !meta.classes.is_empty()
        {
            return; // success
        }
    }
}

/// Regression: a `__objc_classlist` that lists one class object through two
/// pointer slots produces two same-address class observations. Before duplicate
/// entities were collapsed, this failed entity-identity validation
/// (`duplicate Objective-C entity ID`) and aborted the whole command — which is
/// exactly what broke `objc` on large real-world binaries. The command must now
/// succeed, collapse the duplicate to one class entity, and keep every entity
/// identity unique.
#[test]
fn duplicate_class_pointers_collapse_to_one_entity() {
    let path = std::env::temp_dir().join(format!(
        "macho-objc-dupclass-{}-{}.macho",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::write(
        &path,
        macho_test_support::disassembly_objc_duplicate_class(),
    )
    .expect("write fixture");
    let path_text = path.to_str().expect("utf8 path");

    let text = macho::cli::run_captured(["objc", path_text, "--color", "never"]);
    assert_eq!(
        text.code,
        0,
        "objc text run failed: {}",
        String::from_utf8_lossy(&text.stderr)
    );

    let json =
        macho::cli::run_captured(["objc", path_text, "--format", "json", "--color", "never"]);
    assert_eq!(
        json.code,
        0,
        "objc json run failed: {}",
        String::from_utf8_lossy(&json.stderr)
    );

    let document: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("valid JSON envelope");
    let entities = document["data"]["slices"][0]["entities"]
        .as_array()
        .expect("entities array");

    let class_entities: Vec<&serde_json::Value> = entities
        .iter()
        .filter(|entity| entity["kind"] == "class")
        .collect();
    assert_eq!(
        class_entities.len(),
        1,
        "the duplicated class must collapse to exactly one entity"
    );
    assert_eq!(
        class_entities[0]["value"]["common"]["observation_ids"]
            .as_array()
            .expect("class observation IDs")
            .len(),
        2,
        "the canonical entity must retain both source observations"
    );

    let baseline_path = path.with_file_name(format!(
        "macho-objc-singleclass-{}-{}.macho",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::write(
        &baseline_path,
        macho_test_support::disassembly_objc_boundary(),
    )
    .expect("write baseline fixture");
    let baseline = macho::cli::run_captured([
        "objc",
        baseline_path.to_str().expect("utf8 path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(
        baseline.code,
        0,
        "baseline objc JSON run failed: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    let baseline_document: serde_json::Value =
        serde_json::from_slice(&baseline.stdout).expect("valid baseline JSON envelope");
    let baseline_id =
        &baseline_document["data"]["slices"][0]["entities"][0]["value"]["common"]["id"];
    assert_eq!(
        &class_entities[0]["value"]["common"]["id"], baseline_id,
        "duplicate pointer slots must not change stable entity identity"
    );

    let executions = document["data"]["slices"][0]["executions"]
        .as_array()
        .expect("collector executions");
    assert_eq!(
        executions[0]["output_records"], 1,
        "runtime collector output counts canonical entities, not pointer slots"
    );

    let mut ids: Vec<&str> = entities
        .iter()
        .filter_map(|entity| entity["value"]["common"]["id"].as_str())
        .collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "every entity identity must be unique");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&baseline_path);
}
