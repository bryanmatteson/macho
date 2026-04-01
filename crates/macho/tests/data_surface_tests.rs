use macho::analysis::strings::{StringRegionKind, StringRegions};
use macho::extract::vtables::VtableIndex;
use macho::model::container::MachoContainer;
use macho::model::macho_file::MachoFile;

fn first_mach(data: &[u8]) -> MachoContainer<'_> {
    macho::parse(data).expect("parse")
}

fn get_mach<'a>(container: &'a MachoContainer<'a>) -> &'a MachoFile<'a> {
    match container {
        MachoContainer::Fat(fat) => &fat.arches()[0].macho,
        MachoContainer::Thin(macho) => macho,
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
    let all = regions.all_strings(macho);
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
    let first_region = &regions.regions[0];
    let strings = regions.strings_in_region(macho, first_region);

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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
    let all = regions.all_strings(macho);

    if all.is_empty() {
        return;
    }

    // Pick the first string and search for it
    let target = &all[0].value;
    let matches = regions.search(macho, target);
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
    let all = regions.all_strings(macho);

    if all.is_empty() {
        return;
    }

    let target = &all[0].value;
    let exact_matches = regions.search_exact(macho, target);
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
    let matches = regions.search(macho, "zzznonexistentstringzzz_12345");
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
    let macho = get_mach(&container);

    let standard = StringRegions::discover(macho);
    let heuristic = StringRegions::with_heuristic(macho);

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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
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
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);
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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
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
                "mangled vtable name should contain ZTV: {mangled}",
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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
    let ptr_size: u64 = if macho.is_64bit() { 8 } else { 4 };

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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");

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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
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
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
    let json = serde_json::to_string(&index).expect("should serialize to JSON");
    assert!(!json.is_empty());
    assert!(json.contains("vtables"));
}

#[test]
fn vtable_first_slot_is_offset_to_top() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");

    // All vtables should have their first slot as OffsetToTop
    for vtable in &index.vtables {
        assert!(
            matches!(
                vtable.slots.first().map(|s| &s.target),
                Some(macho::extract::vtables::SlotTarget::OffsetToTop { .. })
            ),
            "first slot of vtable {:?} should be OffsetToTop, got {:?}",
            vtable.name,
            vtable.slots.first().map(|s| &s.target),
        );
    }
}

// ---------------------------------------------------------------------------
// Regression: vtable chained fixup resolution
// ---------------------------------------------------------------------------

#[test]
fn regression_vtable_slots_resolve_function_names_on_chained_fixup_binaries() {
    // Before the fix, vtable slot values on binaries with LC_DYLD_CHAINED_FIXUPS
    // were raw chained fixup entries (not resolved VAs), so all function pointer
    // slots were classified as Unknown. After the fix, they should resolve to
    // named functions.
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");
    assert!(!index.vtables.is_empty());

    // Count function-resolved slots across all vtables
    let function_slot_count: usize = index
        .vtables
        .iter()
        .flat_map(|v| v.slots.iter())
        .filter(|s| {
            matches!(
                &s.target,
                macho::extract::vtables::SlotTarget::Function { .. }
            )
        })
        .count();

    let unknown_slot_count: usize = index
        .vtables
        .iter()
        .flat_map(|v| v.slots.iter())
        .filter(|s| {
            matches!(
                &s.target,
                macho::extract::vtables::SlotTarget::Unknown { .. }
            )
        })
        .count();

    // We should have more function slots than unknown slots (the old code
    // had ALL slots as Unknown on chained fixup binaries)
    assert!(
        function_slot_count > unknown_slot_count,
        "function slots ({function_slot_count}) should exceed unknown slots ({unknown_slot_count}) \
         after chained fixup resolution"
    );
}

#[test]
fn regression_vtable_slot1_not_classified_as_pure_virtual() {
    // Before the fix, slot 1 (typeinfo pointer) was misclassified as PureVirtual
    // because ___cxa_pure_virtual is an undefined symbol with value 0, and the
    // raw chained fixup value at the typeinfo slot also happened to be 0.
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");

    for vtable in &index.vtables {
        if vtable.slots.len() >= 2 {
            assert!(
                matches!(
                    &vtable.slots[1].target,
                    macho::extract::vtables::SlotTarget::TypeInfo { .. }
                ),
                "slot 1 of vtable {:?} should be TypeInfo, got {:?}",
                vtable.name,
                vtable.slots[1].target,
            );
        }
    }
}

#[test]
fn regression_vtable_itanium_structure() {
    // Verify the standard Itanium ABI vtable structure:
    // slot 0 = offset-to-top, slot 1 = typeinfo, slot 2+ = virtual functions
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");

    for vtable in &index.vtables {
        if vtable.slots.len() < 3 {
            continue;
        }

        // Slot 0: OffsetToTop
        assert!(
            matches!(
                &vtable.slots[0].target,
                macho::extract::vtables::SlotTarget::OffsetToTop { .. }
            ),
            "vtable {:?} slot 0 should be OffsetToTop",
            vtable.name,
        );

        // Slot 1: TypeInfo
        assert!(
            matches!(
                &vtable.slots[1].target,
                macho::extract::vtables::SlotTarget::TypeInfo { .. }
            ),
            "vtable {:?} slot 1 should be TypeInfo",
            vtable.name,
        );

        // Slot 2+: should be Function, PureVirtual, or Unknown (not OffsetToTop/TypeInfo)
        for (i, slot) in vtable.slots.iter().enumerate().skip(2) {
            assert!(
                !matches!(
                    &slot.target,
                    macho::extract::vtables::SlotTarget::OffsetToTop { .. }
                        | macho::extract::vtables::SlotTarget::TypeInfo { .. }
                ),
                "vtable {:?} slot {} should not be OffsetToTop or TypeInfo (got {:?})",
                vtable.name,
                i,
                slot.target,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Regression: CFString regions should not produce garbage C strings
// ---------------------------------------------------------------------------

#[test]
fn regression_cfstring_region_does_not_produce_garbage_strings() {
    // __cfstring contains CFString structs (pointers + metadata), not raw
    // null-terminated C strings. Before the fix, extract_cstrings was called
    // on these struct bytes, producing garbage output.
    let path = "/usr/bin/plutil";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);

    // If the binary has a CFString region, strings_in_region should return
    // an empty Vec (we skip struct-format sections)
    for region in &regions.regions {
        if region.kind == StringRegionKind::CFString {
            let strings = regions.strings_in_region(macho, region);
            assert!(
                strings.is_empty(),
                "CFString region should not produce C strings (got {} strings)",
                strings.len(),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Regression: pure virtual detection uses symbol name, not VA
// ---------------------------------------------------------------------------

#[test]
fn regression_pure_virtual_detection_by_import_name() {
    // Pure virtual slots should be detected by import name matching
    // (___cxa_pure_virtual), not by VA comparison (which fails because
    // undefined symbols have VA = 0).
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let index = VtableIndex::build(macho).expect("build vtable index");

    // No slot at index 0 or 1 should be PureVirtual
    for vtable in &index.vtables {
        for slot in vtable.slots.iter().take(2) {
            assert!(
                !matches!(
                    &slot.target,
                    macho::extract::vtables::SlotTarget::PureVirtual
                ),
                "structural slots (offset-to-top, typeinfo) should never be PureVirtual \
                 in vtable {:?}",
                vtable.name,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Name-based section classification priority
// ---------------------------------------------------------------------------

#[test]
fn objc_sections_classified_before_type_fallback() {
    // ObjC sections like __objc_methname have S_CSTRING_LITERALS type but
    // should be classified as ObjCString, not CString. Name-based matching
    // must take priority.
    let path = "/usr/bin/plutil";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let regions = StringRegions::discover(macho);

    for region in &regions.regions {
        if region.section_name.starts_with("__objc_") {
            assert_eq!(
                region.kind,
                StringRegionKind::ObjCString,
                "ObjC section {} should be classified as ObjCString, not {:?}",
                region.section_name,
                region.kind,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn vtable_output_is_deterministic() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let index1 = VtableIndex::build(macho).expect("build vtable index");
    let index2 = VtableIndex::build(macho).expect("build vtable index");

    let json1 = serde_json::to_string(&index1).expect("json");
    let json2 = serde_json::to_string(&index2).expect("json");

    assert_eq!(
        json1, json2,
        "vtable output should be deterministic across runs"
    );
}

#[test]
fn string_region_output_is_deterministic() {
    let path = "/Library/Developer/CommandLineTools/usr/bin/swift-demangle";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {path} not found");
        return;
    }
    let data = std::fs::read(path).expect("read");
    let container = first_mach(&data);
    let macho = get_mach(&container);

    let regions1 = StringRegions::discover(macho);
    let regions2 = StringRegions::discover(macho);

    let json1 = serde_json::to_string(&regions1).expect("json");
    let json2 = serde_json::to_string(&regions2).expect("json");

    assert_eq!(
        json1, json2,
        "string region output should be deterministic across runs"
    );
}
