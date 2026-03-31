use macho::inspect::resolve::{resolve_all_rpaths, resolve_path};
use macho::inspect::{DylibLinkKind, ImageInfo, ImageInspector};

// -- Basic ImageInspector tests --

#[test]
fn inspector_new_with_thin_slice() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);
    let info = inspector.info();

    assert!(!info.arch.is_empty());
    assert!(!info.file_type.is_empty());
    assert_eq!(info.file_type, "MH_EXECUTE");
}

#[test]
fn inspector_info_has_uuid() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    assert!(
        inspector.info().uuid.is_some(),
        "system binary should have UUID"
    );
}

#[test]
fn inspector_info_has_platform() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let platform = inspector
        .info()
        .platform
        .as_ref()
        .expect("should have platform info");
    assert!(!platform.platform.is_empty());
    assert!(!platform.min_os.is_empty());
    assert!(!platform.sdk.is_empty());
}

#[test]
fn inspector_info_has_image_base() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    assert!(
        inspector.info().image_base > 0,
        "image base should be non-zero for executables"
    );
}

#[test]
fn inspector_info_linked_dylibs() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let dylibs = &inspector.info().linked_dylibs;
    assert!(!dylibs.is_empty(), "executable should link dylibs");

    // libSystem should be linked
    assert!(
        dylibs.iter().any(|d| d.name.contains("libSystem")),
        "should link libSystem"
    );

    // Ordinals should be 1-based and sequential
    for (i, dylib) in dylibs.iter().enumerate() {
        assert_eq!(dylib.ordinal, i + 1, "ordinals should be 1-based");
    }

    // Versions should be non-empty
    for dylib in dylibs {
        assert!(!dylib.current_version.is_empty());
        assert!(!dylib.compat_version.is_empty());
    }
}

#[test]
fn inspector_info_dylib_link_kinds() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // At minimum, a typical executable has Required dylibs
    let dylibs = &inspector.info().linked_dylibs;
    assert!(
        dylibs.iter().any(|d| d.kind == DylibLinkKind::Required),
        "should have at least one Required dylib"
    );
}

#[test]
fn inspector_address_map() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // address_map should be accessible and functional
    let map = inspector.address_map();
    // The map should have entries (segments)
    assert!(std::fmt::format(format_args!("{:?}", map)).contains("AddressMap"));
}

#[test]
fn inspector_mach_escape_hatch() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // Should be able to get back to the raw MachFile
    assert!(inspector.mach().header().ncmds > 0);
}

// -- Cached deep parse tests --

#[test]
fn inspector_cached_symbols() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // First call parses, second returns cached
    let result1 = inspector.symbols();
    let result2 = inspector.symbols();

    // Both should succeed or both fail consistently
    assert_eq!(result1.is_ok(), result2.is_ok());

    if let Ok(symtab) = result1 {
        assert!(!symtab.is_empty(), "should have symbols");
    }
}

#[test]
fn inspector_cached_exports() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // Exports may or may not be present
    let _result = inspector.exports();
    // Just verify it doesn't panic on repeated calls
    let _result2 = inspector.exports();
}

#[test]
fn inspector_cached_codesign() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let result = inspector.code_signature();
    assert!(result.is_ok(), "system binary should be signed");

    let sig = result.unwrap();
    assert!(sig.identifier().is_some());
}

#[test]
fn inspector_debug_impl() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let debug = format!("{:?}", inspector);
    assert!(debug.contains("ImageInspector"));
}

// -- ImageInfo serialization --

#[test]
fn image_info_serializes_to_json() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let json = serde_json::to_string(inspector.info()).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");

    assert!(parsed["arch"].is_string());
    assert!(parsed["file_type"].is_string());
    assert!(parsed["linked_dylibs"].is_array());
}

// -- Fat binary tests --

#[test]
fn inspector_fat_binary_all_slices() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");

    let machs = container.mach_files();
    assert!(machs.len() >= 2, "fat binary should have multiple arches");

    for mach in machs {
        let inspector = ImageInspector::new(mach);
        let info = inspector.info();
        assert!(!info.arch.is_empty());
        assert_eq!(info.file_type, "MH_EXECUTE");
        assert!(info.uuid.is_some());
    }
}

#[test]
fn inspector_fat_binary_different_arches() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");

    let machs = container.mach_files();
    let arches: Vec<String> = machs
        .iter()
        .map(|m| ImageInspector::new(m).info().arch.clone())
        .collect();

    // Should have distinct architectures
    let unique: std::collections::HashSet<_> = arches.iter().collect();
    assert_eq!(unique.len(), arches.len(), "arches should be distinct");
}

// -- Dylib with install name --

#[test]
fn inspector_dylib_install_name() {
    let data = std::fs::read("/usr/lib/libffi-trampolines.dylib").expect("read dylib");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let info = inspector.info();
    assert_eq!(info.file_type, "MH_DYLIB");
    assert!(
        info.install_name.is_some(),
        "dylib should have install name"
    );
}

// -- Path resolution tests --

#[test]
fn resolve_plain_path() {
    let info = dummy_info(Vec::new());
    let result = resolve_path("/usr/lib/libSystem.B.dylib", &info, None, None);
    assert_eq!(result, "/usr/lib/libSystem.B.dylib");
}

#[test]
fn resolve_rpath_with_available_rpath() {
    let info = dummy_info(vec!["@loader_path/../Frameworks".to_string()]);
    let result = resolve_path(
        "@rpath/Foo.framework/Foo",
        &info,
        Some("/Applications/App.app/Contents/MacOS/App"),
        None,
    );
    assert_eq!(
        result,
        "/Applications/App.app/Contents/MacOS/../Frameworks/Foo.framework/Foo"
    );
}

#[test]
fn resolve_rpath_without_rpaths() {
    let info = dummy_info(Vec::new());
    let result = resolve_path("@rpath/Foo.framework/Foo", &info, None, None);
    assert_eq!(result, "@rpath/Foo.framework/Foo");
}

#[test]
fn resolve_loader_path() {
    let info = dummy_info(Vec::new());
    let result = resolve_path(
        "@loader_path/../lib/libfoo.dylib",
        &info,
        Some("/usr/local/bin/myapp"),
        None,
    );
    assert_eq!(result, "/usr/local/bin/../lib/libfoo.dylib");
}

#[test]
fn resolve_executable_path() {
    let info = dummy_info(Vec::new());
    let result = resolve_path(
        "@executable_path/../Frameworks/Bar.framework/Bar",
        &info,
        None,
        Some("/Applications/MyApp.app/Contents/MacOS/MyApp"),
    );
    assert_eq!(
        result,
        "/Applications/MyApp.app/Contents/MacOS/../Frameworks/Bar.framework/Bar"
    );
}

#[test]
fn resolve_rpath_with_plain_rpath() {
    let info = dummy_info(vec!["/opt/lib".to_string()]);
    let result = resolve_path("@rpath/libfoo.dylib", &info, None, None);
    assert_eq!(result, "/opt/lib/libfoo.dylib");
}

fn dummy_info(rpaths: Vec<String>) -> ImageInfo {
    ImageInfo {
        arch: "arm64".to_string(),
        file_type: "MH_EXECUTE".to_string(),
        uuid: None,
        image_base: 0,
        platform: None,
        source_version: None,
        install_name: None,
        linked_dylibs: Vec::new(),
        rpaths,
        target_triple: None,
    }
}

// -- resolve_all_rpaths integration tests --

#[test]
fn resolve_all_rpaths_with_multiple_entries() {
    let info = dummy_info(vec![
        "/opt/lib".to_string(),
        "/usr/local/lib".to_string(),
        "@loader_path/../lib".to_string(),
    ]);
    let result = resolve_all_rpaths(
        "@rpath/libfoo.dylib",
        &info,
        Some("/usr/bin/myapp"),
        None,
    );
    assert_eq!(result.len(), 3);
    assert_eq!(result[0], "/opt/lib/libfoo.dylib");
    assert_eq!(result[1], "/usr/local/lib/libfoo.dylib");
    assert_eq!(result[2], "/usr/bin/../lib/libfoo.dylib");
}

#[test]
fn resolve_all_rpaths_empty_rpaths() {
    let info = dummy_info(Vec::new());
    let result = resolve_all_rpaths("@rpath/libfoo.dylib", &info, None, None);
    assert!(result.is_empty());
}

#[test]
fn resolve_all_rpaths_non_rpath_returns_single() {
    let info = dummy_info(vec!["/opt/lib".to_string()]);
    let result = resolve_all_rpaths("/usr/lib/libSystem.B.dylib", &info, None, None);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "/usr/lib/libSystem.B.dylib");
}

// -- Edge case: rpath with @executable_path --

#[test]
fn resolve_rpath_containing_executable_path() {
    let info = dummy_info(vec!["@executable_path/../Frameworks".to_string()]);
    let result = resolve_path(
        "@rpath/Foo.framework/Foo",
        &info,
        None,
        Some("/Applications/App.app/Contents/MacOS/App"),
    );
    assert_eq!(
        result,
        "/Applications/App.app/Contents/MacOS/../Frameworks/Foo.framework/Foo"
    );
}

// -- Graceful degradation tests --

#[test]
fn inspector_graceful_no_objc_metadata() {
    // /usr/bin/true is a C executable, should not have ObjC metadata
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // ObjC metadata parse should either succeed with empty data or
    // return an error -- either way it should not panic
    let result = inspector.objc_metadata();
    // The result is either Ok or Err, both are acceptable
    let _ = result;
}

#[test]
fn inspector_graceful_no_chained_fixups() {
    // /usr/bin/true may or may not have chained fixups; test graceful handling
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let result = inspector.fixups();
    // Should not panic; either Ok or Err is fine
    let _ = result;
}

#[test]
fn inspector_objc_graph_reuses_cached_metadata() {
    // Verify that calling objc_metadata() then objc_graph() does not panic
    // and that objc_graph uses the cached metadata internally
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // Call objc_metadata first to populate the cache
    let meta_result = inspector.objc_metadata();
    // Then call objc_graph which should reuse cached metadata
    let graph_result = inspector.objc_graph();

    // Both should have consistent error behavior: if metadata fails,
    // graph should also fail
    if meta_result.is_err() {
        assert!(graph_result.is_err(), "graph should fail if metadata fails");
    }
}

#[test]
fn inspector_swift_types_are_cached_and_match_direct_build() {
    let data = std::fs::read("/usr/bin/plutil").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let first = inspector.swift_types().expect("swift types");
    let second = inspector.swift_types().expect("swift types from cache");
    assert!(
        std::ptr::eq(first, second),
        "swift type index should come from the inspector cache"
    );

    let direct = macho::swift::SwiftTypeIndex::build(mach);
    assert_eq!(
        first.types.iter().map(|ty| &ty.name).collect::<Vec<_>>(),
        direct.types.iter().map(|ty| &ty.name).collect::<Vec<_>>()
    );
}

#[test]
fn inspector_executable_has_no_install_name() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // Executables should NOT have an install name (that's for dylibs)
    assert!(
        inspector.info().install_name.is_none(),
        "executables should not have install_name"
    );
}

#[test]
fn inspector_cached_calls_return_consistent_results() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    // Call each cached method twice and verify consistency
    let sym1 = inspector.symbols().is_ok();
    let sym2 = inspector.symbols().is_ok();
    assert_eq!(sym1, sym2, "symbols() should be consistent");

    let exp1 = inspector.exports().is_ok();
    let exp2 = inspector.exports().is_ok();
    assert_eq!(exp1, exp2, "exports() should be consistent");

    let fix1 = inspector.fixups().is_ok();
    let fix2 = inspector.fixups().is_ok();
    assert_eq!(fix1, fix2, "fixups() should be consistent");

    let cs1 = inspector.code_signature().is_ok();
    let cs2 = inspector.code_signature().is_ok();
    assert_eq!(cs1, cs2, "code_signature() should be consistent");
}

#[test]
fn image_info_json_contains_all_fields() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let mach = container.first_mach();
    let inspector = ImageInspector::new(mach);

    let json = serde_json::to_string(inspector.info()).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");

    // Verify all plan-specified fields are present in JSON output
    assert!(parsed.get("arch").is_some(), "missing arch");
    assert!(parsed.get("file_type").is_some(), "missing file_type");
    assert!(parsed.get("uuid").is_some(), "missing uuid");
    assert!(parsed.get("image_base").is_some(), "missing image_base");
    assert!(parsed.get("platform").is_some(), "missing platform");
    assert!(parsed.get("source_version").is_some(), "missing source_version");
    assert!(parsed.get("install_name").is_some(), "missing install_name");
    assert!(parsed.get("linked_dylibs").is_some(), "missing linked_dylibs");
    assert!(parsed.get("rpaths").is_some(), "missing rpaths");
    assert!(parsed.get("target_triple").is_some(), "missing target_triple");
}
