use macho::data_surface::strings::{StringRegionKind, StringRegions};
use macho::data_surface::vtable::VtableIndex;
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;

fn first_mach(data: &[u8]) -> MachContainer<'_> {
    macho::parse(data).expect("parse")
}

fn get_mach<'a>(container: &'a MachContainer<'a>) -> &'a MachFile<'a> {
    match container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    }
}

// ---------------------------------------------------------------------------
// String region tests
// ---------------------------------------------------------------------------

#[test]
fn discover_finds_cstring_regions() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    assert!(
        !regions.regions.is_empty(),
        "should find at least one string region"
    );

    let cstring_regions: Vec<_> = regions
        .regions
        .iter()
        .filter(|r| r.kind == StringRegionKind::CString)
        .collect();
    assert!(
        !cstring_regions.is_empty(),
        "should find at least one CString region"
    );
}

#[test]
fn discover_finds_objc_string_regions() {
    let path = "/usr/bin/plutil";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let objc_regions: Vec<_> = regions
        .regions
        .iter()
        .filter(|r| r.kind == StringRegionKind::ObjCString)
        .collect();
    assert!(
        !objc_regions.is_empty(),
        "plutil should have ObjC string regions"
    );
}

#[test]
fn all_strings_returns_nonempty() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let all = regions.all_strings(mach);
    assert!(!all.is_empty(), "should find strings in string regions");

    // Every string should be non-empty
    for s in &all {
        assert!(!s.value.is_empty(), "found empty string");
    }
}

#[test]
fn strings_in_region_returns_valid_entries() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let first_region = &regions.regions[0];
    let strings = regions.strings_in_region(mach, first_region);

    assert!(!strings.is_empty(), "first region should have strings");

    for s in &strings {
        // VA should be within the region bounds
        assert!(
            s.va.0 >= first_region.start.0,
            "string VA {:#x} below region start {:#x}",
            s.va.0,
            first_region.start.0,
        );
        assert!(
            s.va.0 < first_region.start.0 + first_region.size,
            "string VA {:#x} beyond region end",
            s.va.0,
        );
    }
}

#[test]
fn search_finds_known_string() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let all = regions.all_strings(mach);

    if all.is_empty() {
        return;
    }

    // Pick the first string and search for it
    let target = &all[0].value;
    let matches = regions.search(mach, target);
    assert!(
        !matches.is_empty(),
        "searching for a known string should yield at least one match"
    );

    // Verify the match contains our query
    assert!(
        matches[0].value.contains(target.as_str()),
        "match should contain the query"
    );
}

#[test]
fn search_exact_matches_precisely() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let all = regions.all_strings(mach);

    if all.is_empty() {
        return;
    }

    let target = &all[0].value;
    let exact_matches = regions.search_exact(mach, target);
    assert!(
        !exact_matches.is_empty(),
        "exact search for a known string should yield at least one match"
    );

    for m in &exact_matches {
        assert_eq!(&m.value, target, "exact match should be identical to query");
    }
}

#[test]
fn search_nonexistent_returns_empty() {
    let path = "/usr/bin/true";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let matches = regions.search(mach, "zzznonexistentstringzzz_12345");
    assert!(
        matches.is_empty(),
        "searching for nonexistent string should return empty"
    );
}

#[test]
fn with_heuristic_finds_additional_regions() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let standard = StringRegions::discover(mach);
    let heuristic = StringRegions::with_heuristic(mach);

    // Heuristic should find at least as many regions as standard
    assert!(
        heuristic.regions.len() >= standard.regions.len(),
        "heuristic should find at least as many regions: {} vs {}",
        heuristic.regions.len(),
        standard.regions.len(),
    );

    // All standard regions should be present in heuristic
    for sr in &standard.regions {
        let found = heuristic.regions.iter().any(|hr| {
            hr.section_segment == sr.section_segment && hr.section_name == sr.section_name
        });
        assert!(
            found,
            "heuristic regions should contain all standard regions (missing {}, {})",
            sr.section_segment, sr.section_name,
        );
    }
}

#[test]
fn region_metadata_is_valid() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    for region in &regions.regions {
        assert!(region.size > 0, "region size should be > 0");
        assert!(region.start.0 > 0, "region VA should be > 0");
        assert!(
            !region.section_segment.is_empty(),
            "segment name should not be empty"
        );
        assert!(
            !region.section_name.is_empty(),
            "section name should not be empty"
        );
    }
}

#[test]
fn string_regions_serializes_to_json() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let regions = StringRegions::discover(mach);
    let json = serde_json::to_string(&regions).expect("should serialize to JSON");
    assert!(!json.is_empty());
    assert!(json.contains("CString") || json.contains("regions"));
}

// ---------------------------------------------------------------------------
// VTable tests
// ---------------------------------------------------------------------------

#[test]
fn vtable_build_finds_vtables_in_cpp_binary() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    assert!(
        !index.vtables.is_empty(),
        "swift-demangle should have C++ vtables"
    );
}

#[test]
fn vtable_entries_have_valid_metadata() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    for vtable in &index.vtables {
        assert!(vtable.va.0 > 0, "vtable VA should be > 0");
        assert!(vtable.size > 0, "vtable size should be > 0");
        assert!(
            !vtable.slots.is_empty(),
            "vtable should have at least one slot"
        );

        // Mangled name should start with __ZTV or _ZTV
        if let Some(ref mangled) = vtable.mangled_name {
            assert!(
                mangled.contains("ZTV"),
                "mangled vtable name should contain ZTV: {}",
                mangled,
            );
        }
    }
}

#[test]
fn vtable_slots_have_valid_offsets() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    let ptr_size: u64 = if mach.is_64bit() { 8 } else { 4 };

    for vtable in &index.vtables {
        for (i, slot) in vtable.slots.iter().enumerate() {
            assert_eq!(
                slot.offset,
                i as u64 * ptr_size,
                "slot offset should be sequential"
            );
            assert_eq!(
                slot.va.0,
                vtable.va.0 + slot.offset,
                "slot VA should be vtable VA + offset"
            );
        }
    }
}

#[test]
fn vtable_find_by_va_works() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    if index.vtables.is_empty() {
        return;
    }

    let first_va = index.vtables[0].va;
    let found = index.find_by_va(first_va);
    assert!(found.is_some(), "should find vtable by its VA");
    assert_eq!(found.unwrap().va, first_va);
}

#[test]
fn vtable_find_by_class_works() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");

    // Find a vtable that has a demangled name
    let named_vtable = index.vtables.iter().find(|v| v.name.is_some());
    if let Some(vtable) = named_vtable {
        let class_name = vtable.name.as_ref().unwrap();
        // Extract a search term from the demangled name
        // Demangled names look like "vtable for ClassName" or similar
        let search_term = if let Some(stripped) = class_name.strip_prefix("vtable for ") {
            stripped
        } else {
            class_name.as_str()
        };
        let found = index.find_by_class(search_term);
        assert!(
            found.is_some(),
            "should find vtable by class name fragment '{search_term}'"
        );
    }
}

#[test]
fn vtable_slot_at_works() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    if index.vtables.is_empty() || index.vtables[0].slots.is_empty() {
        return;
    }

    let first_slot_va = index.vtables[0].slots[0].va;
    let result = index.slot_at(first_slot_va);
    assert!(result.is_some(), "should find slot by VA");
    let (vtable, slot) = result.unwrap();
    assert_eq!(vtable.va, index.vtables[0].va);
    assert_eq!(slot.va, first_slot_va);
}

#[test]
fn vtable_no_vtables_in_c_binary() {
    let path = "/usr/bin/true";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    assert!(
        index.vtables.is_empty(),
        "/usr/bin/true (a C binary) should have no vtables"
    );
}

#[test]
fn vtable_index_serializes_to_json() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");
    let json = serde_json::to_string(&index).expect("should serialize to JSON");
    assert!(!json.is_empty());
    assert!(json.contains("vtables"));
}

#[test]
fn vtable_first_slot_is_address_point_or_zero() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let mach = get_mach(&container);

    let index = VtableIndex::build(mach).expect("build vtable index");

    // Most vtables should have their first slot as AddressPoint (offset-to-top = 0)
    let address_point_count = index
        .vtables
        .iter()
        .filter(|v| {
            matches!(
                v.slots.first().map(|s| &s.target),
                Some(macho::data_surface::vtable::SlotTarget::AddressPoint)
            )
        })
        .count();

    // At least some vtables should follow the standard layout
    if !index.vtables.is_empty() {
        assert!(
            address_point_count > 0,
            "at least some vtables should have AddressPoint as first slot"
        );
    }
}
