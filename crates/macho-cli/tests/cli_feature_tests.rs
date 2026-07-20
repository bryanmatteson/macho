mod support;

use std::time::{SystemTime, UNIX_EPOCH};

use macho::metadata::swift::SwiftTypeIndex;
use macho::model::container::MachoContainer;
use support::{copy_macho_fixture, run_cli, temp_file_path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn unique_marker(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn has_rpath(macho: &macho::model::macho_file::MachoFile<'_>, needle: &str) -> bool {
    macho
        .load_commands()
        .iter()
        .any(|lc| lc.kind().as_rpath() == Some(needle))
}

#[test]
fn snapshot_arch_filter_requires_match() {
    let fixture = copy_macho_fixture("/usr/bin/true", "snapshot-true");
    let output = run_cli([
        "snapshot",
        "--arch",
        "definitely_not_real",
        fixture.path().to_str().expect("utf8 path"),
    ]);

    assert!(
        !output.status.success(),
        "expected non-zero exit status for invalid arch filter"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no architecture matching 'definitely_not_real'"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn container_json_reports_fileset_entry_offsets() {
    let path = temp_file_path("fileset");
    let bytes = macho_test_support::fileset64_arm64();
    std::fs::write(&path, bytes).expect("failed to write temp Mach-O");

    let output = run_cli([
        "container",
        "--format",
        "json",
        path.to_str().expect("utf8 path"),
    ]);

    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "container command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let data = &json["data"];
    assert_eq!(data["format"], "Fileset");
    let entry = &data["fileset"]["entries"][0];

    assert_eq!(entry["arch"], "arm64");
    assert_eq!(entry["entry_id"], "com.example.first");
    assert_eq!(entry["vm_addr"], 0x1_0000_0000u64);
    assert_eq!(entry["file_offset"], 0x100u64);
}

#[test]
fn fileset_list_reports_no_match_for_filtered_arch() {
    let path = temp_file_path("fileset-filter");
    let bytes = macho_test_support::fileset64_arm64();
    std::fs::write(&path, bytes).expect("failed to write temp Mach-O");

    let output = run_cli([
        "fileset",
        "list",
        path.to_str().expect("utf8 path"),
        "--arch",
        "x86_64",
    ]);

    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "fileset command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No fileset entries matched architecture 'x86_64'."),
        "unexpected stdout: {stdout}"
    );
}

#[test]
fn container_json_accepts_selected_parity_domains() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "container-plutil");
    let output = run_cli([
        "container",
        "--format",
        "json",
        "--parity-domain",
        "imports",
        fixture.path().to_str().expect("utf8 path"),
    ]);

    assert!(
        output.status.success(),
        "container command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let data = &json["data"];
    assert_eq!(data["parity"]["domains"], serde_json::json!(["imports"]));
    if let Some(divergences) = data["parity"]["divergences"].as_array() {
        for divergence in divergences {
            assert_eq!(divergence["domain"], "imports");
        }
    }
}

#[test]
fn fileset_inspect_reports_single_not_found_message() {
    let path = temp_file_path("fileset-inspect-miss");
    let bytes = macho_test_support::fileset64_arm64();
    std::fs::write(&path, bytes).expect("failed to write temp Mach-O");

    let output = run_cli([
        "fileset",
        "inspect",
        path.to_str().expect("utf8 path"),
        "missing.entry",
    ]);

    let _ = std::fs::remove_file(&path);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("Fileset entry 'missing.entry' not found")
            .count(),
        1
    );
}

#[test]
fn fat_patch_bytes_requires_arch() {
    let fixture = copy_macho_fixture("/usr/bin/true", "fat-patch-bytes");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    if !matches!(container, MachoContainer::Fat(_)) {
        return;
    }

    let output = run_cli([
        "patch",
        fixture_path,
        "--bytes",
        "0x100:00010203",
        "--dry-run",
    ]);

    assert!(
        !output.status.success(),
        "expected non-zero exit status when patching fat binary bytes without --arch"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires --arch"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn fat_patch_add_rpath_selected_arch_only() {
    let fixture = copy_macho_fixture("/usr/bin/true", "fat-selected-true");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let fat = match &container {
        MachoContainer::Fat(fat) if fat.arches().len() >= 2 => fat,
        _ => return,
    };

    let selected_arch = fat.arches()[0].spec().name();
    let untouched_arch = fat.arches()[1].spec().name();
    let rpath = format!("/tmp/{}", unique_marker("macho-fat-selected"));
    let output_path = temp_file_path("fat-selected-rpath");

    let output = run_cli([
        "patch",
        fixture_path,
        "--add-rpath",
        &rpath,
        "--arch",
        &selected_arch,
        "--output",
        output_path.to_str().expect("utf8 path"),
    ]);

    assert!(
        output.status.success(),
        "patch command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let patched = std::fs::read(&output_path).expect("read patched binary");
    let patched_container = macho::parse(&patched).expect("parse patched binary");
    let patched_fat = match &patched_container {
        MachoContainer::Fat(fat) => fat,
        _ => panic!("expected fat output"),
    };

    let selected = patched_fat
        .arches()
        .iter()
        .find(|arch| arch.spec().name() == selected_arch)
        .expect("selected arch missing");
    assert!(
        has_rpath(selected.macho(), &rpath),
        "selected arch should contain new rpath"
    );

    let untouched = patched_fat
        .arches()
        .iter()
        .find(|arch| arch.spec().name() == untouched_arch)
        .expect("untouched arch missing");
    assert!(
        !has_rpath(untouched.macho(), &rpath),
        "non-selected arch should not contain new rpath"
    );

    let _ = std::fs::remove_file(&output_path);
}

#[test]
fn fat_patch_add_rpath_all_arches_by_default() {
    let fixture = copy_macho_fixture("/usr/bin/true", "fat-all-true");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let fat = match &container {
        MachoContainer::Fat(fat) => fat,
        _ => return,
    };

    let rpath = format!("/tmp/{}", unique_marker("macho-fat-all"));
    let output_path = temp_file_path("fat-all-rpath");

    let output = run_cli([
        "patch",
        fixture_path,
        "--add-rpath",
        &rpath,
        "--output",
        output_path.to_str().expect("utf8 path"),
    ]);

    assert!(
        output.status.success(),
        "patch command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let patched = std::fs::read(&output_path).expect("read patched binary");
    let patched_container = macho::parse(&patched).expect("parse patched binary");
    let patched_fat = match &patched_container {
        MachoContainer::Fat(fat) => fat,
        _ => panic!("expected fat output"),
    };

    assert_eq!(patched_fat.arches().len(), fat.arches().len());
    for arch in patched_fat.arches() {
        assert!(
            has_rpath(arch.macho(), &rpath),
            "arch {} should contain new rpath",
            arch.spec().name()
        );
    }

    let _ = std::fs::remove_file(&output_path);
}

#[test]
fn swift_json_kind_filter_applies_to_output() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "swift-plutil");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let fat = match &container {
        MachoContainer::Fat(fat) if !fat.arches().is_empty() => fat,
        _ => return,
    };

    let selected_arch = fat.arches()[0].spec().name();
    let Some(selected_kind) = SwiftTypeIndex::build(fat.arches()[0].macho())
        .types
        .first()
        .map(|ty| ty.kind)
    else {
        return;
    };
    let kind_arg = selected_kind.to_string();
    let expected_kind = serde_json::to_value(selected_kind).expect("serialize kind");

    let output = run_cli([
        "swift",
        fixture_path,
        "--arch",
        &selected_arch,
        "--kind",
        &kind_arg,
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "swift command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let slice = &json["data"]["slices"][0];
    let entities = slice["entities"]
        .as_array()
        .expect("canonical Swift entities array");
    let selected = slice["selection"]["selected_entity_ids"]
        .as_array()
        .expect("selected Swift entity IDs");

    assert!(
        !selected.is_empty(),
        "filtered Swift JSON output should contain at least one type"
    );
    assert!(
        selected.iter().all(|id| {
            entities.iter().any(|entity| {
                entity["id"] == *id
                    && entity["kind"]["kind"] == "known"
                    && entity["kind"]["value"] == expected_kind
            })
        }),
        "JSON output should honor the requested kind filter"
    );
}

#[test]
fn swift_name_state_and_repeatable_kind_filters_compose() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "swift-composed-filters");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let fat = match &container {
        MachoContainer::Fat(fat) if !fat.arches().is_empty() => fat,
        _ => return,
    };
    let selected_arch = fat.arches()[0].spec().name();
    let baseline = run_cli([
        "swift",
        fixture_path,
        "--arch",
        &selected_arch,
        "--format",
        "json",
    ]);
    assert!(baseline.status.success());
    let baseline: serde_json::Value =
        serde_json::from_slice(&baseline.stdout).expect("valid baseline JSON");
    let entities = baseline["data"]["slices"][0]["entities"]
        .as_array()
        .expect("Swift entities");
    let Some(entity) = entities.iter().find(|entity| {
        entity["kind"]["kind"] == "known" && entity["qualified_name"]["kind"] == "known"
    }) else {
        return;
    };
    let kind = entity["kind"]["value"].as_str().expect("known kind");
    let state = entity["state"].as_str().expect("entity state");
    let kind_arg = kind.replace('_', "-");
    let state_arg = state.replace('_', "-");
    let name = entity["qualified_name"]["value"]["path"]
        .as_array()
        .expect("qualified path")
        .iter()
        .map(|component| component.as_str().expect("name component"))
        .collect::<Vec<_>>()
        .join(".");

    let filtered = run_cli([
        "swift",
        fixture_path,
        "--arch",
        &selected_arch,
        "--kind",
        &kind_arg,
        "--state",
        &state_arg,
        "--name",
        &name,
        "--exact",
        "--format",
        "json",
    ]);
    assert!(
        filtered.status.success(),
        "{}",
        String::from_utf8_lossy(&filtered.stderr)
    );
    let filtered: serde_json::Value =
        serde_json::from_slice(&filtered.stdout).expect("valid filtered JSON");
    let slice = &filtered["data"]["slices"][0];
    let entities = slice["entities"].as_array().expect("Swift entities");
    let selected = slice["selection"]["selected_entity_ids"]
        .as_array()
        .expect("selected Swift IDs");
    assert!(!selected.is_empty());
    assert!(selected.iter().all(|id| {
        entities.iter().any(|entity| {
            if entity["id"] != *id || entity["kind"]["value"] != kind || entity["state"] != state {
                return false;
            }
            entity["qualified_name"]["value"]["path"]
                .as_array()
                .is_some_and(|path| {
                    path.iter()
                        .map(|component| component.as_str().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join(".")
                        == name
                })
        })
    }));
}

#[test]
fn objc_kind_presence_and_name_filters_compose() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "objc-composed-filters");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let arch = container
        .first_macho()
        .expect("fixture contains a Mach-O image")
        .header()
        .cpu_type()
        .name()
        .to_owned();
    let baseline = run_cli(["objc", fixture_path, "--arch", &arch, "--format", "json"]);
    assert!(baseline.status.success());
    let baseline: serde_json::Value =
        serde_json::from_slice(&baseline.stdout).expect("valid baseline JSON");
    let entities = baseline["data"]["slices"][0]["entities"]
        .as_array()
        .expect("Objective-C entities");
    let Some(entity) = entities.iter().find(|entity| {
        entity["kind"] == "class"
            && entity["value"]["common"]["presence"] == "defined"
            && entity["value"]["common"]["name"]["kind"] == "known"
    }) else {
        return;
    };
    let name = entity["value"]["common"]["name"]["value"]
        .as_str()
        .expect("known class name");

    let filtered = run_cli([
        "objc",
        fixture_path,
        "--arch",
        &arch,
        "--kind",
        "class",
        "--presence",
        "defined",
        "--name",
        name,
        "--format",
        "json",
    ]);
    assert!(
        filtered.status.success(),
        "{}",
        String::from_utf8_lossy(&filtered.stderr)
    );
    let filtered: serde_json::Value =
        serde_json::from_slice(&filtered.stdout).expect("valid filtered JSON");
    let slice = &filtered["data"]["slices"][0];
    let entities = slice["entities"].as_array().expect("Objective-C entities");
    let selected = slice["selection"]["selected_entity_ids"]
        .as_array()
        .expect("selected Objective-C IDs");
    assert!(!selected.is_empty());
    assert!(selected.iter().all(|id| {
        entities.iter().any(|entity| {
            entity["value"]["common"]["id"] == *id
                && entity["kind"] == "class"
                && entity["value"]["common"]["presence"] == "defined"
                && entity["value"]["common"]["name"]["value"]
                    .as_str()
                    .is_some_and(|candidate| candidate.contains(name))
        })
    }));
}

#[test]
fn objc_graph_json_reports_explicit_zero_surface_without_metadata() {
    let fixture = copy_macho_fixture("/usr/bin/true", "objc-graph-true");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let arch = container
        .first_macho()
        .expect("fixture contains a Mach-O image")
        .header()
        .cpu_type()
        .name()
        .to_string();

    let output = run_cli([
        "objc",
        "graph",
        fixture_path,
        "--arch",
        &arch,
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "objc graph command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let views = json["data"].as_array().expect("graph slice views");
    assert_eq!(views.len(), 1);
    assert_eq!(views[0]["arch"].as_str().map(str::is_empty), Some(false));
    for field in [
        "nodes",
        "inheritance",
        "conformances",
        "categories",
        "selector_owners",
    ] {
        assert_eq!(views[0][field], serde_json::json!([]), "field {field}");
    }
}

#[test]
fn objc_selectors_json_reports_candidates() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "objc-selectors-plutil");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let Some((arch, selector)) = container.macho_files().find_map(|macho| {
        let metadata = macho::metadata::objc::parse_objc_metadata(macho).ok()?;
        let graph =
            macho::analysis::reconstruct::objc::graph::ObjCGraph::build_from_mach(&metadata, macho);
        graph.selectors.keys().next().map(|selector| {
            (
                macho.header().cpu_type().name().to_owned(),
                selector.clone(),
            )
        })
    }) else {
        return;
    };

    let output = run_cli([
        "objc",
        "selectors",
        fixture_path,
        "--arch",
        &arch,
        "--name",
        &selector,
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "objc selectors command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let entries = json["data"].as_array().expect("selector view array");
    assert!(!entries.is_empty());
    assert!(entries.iter().all(|entry| {
        entry["selector"] == selector
            && entry["method_kind"].is_string()
            && entry["candidates"].is_array()
    }));
    for candidate in entries.iter().flat_map(|entry| {
        entry["candidates"]
            .as_array()
            .expect("candidate array")
            .iter()
    }) {
        assert!(candidate["member_id"].is_string());
        assert!(candidate["origin_id"].is_string());
        assert!(candidate["origin"].is_string());
    }
}

#[test]
fn objc_xrefs_json_reports_exact_address_resolution_status() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "objc-xrefs-plutil");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let arch = container
        .first_macho()
        .expect("fixture contains a Mach-O image")
        .header()
        .cpu_type()
        .name()
        .to_owned();

    let output = run_cli([
        "objc",
        "xrefs",
        fixture_path,
        "--arch",
        &arch,
        "--format",
        "json",
    ]);

    assert!(
        output.status.success(),
        "objc xrefs command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let entries = json["data"].as_array().expect("xref JSON array");
    for entry in entries {
        assert!(entry["member_id"].is_string());
        assert!(entry["origin_id"].is_string());
        assert!(entry["selector"].is_string());
        assert!(entry["implementation"].is_u64());
        assert!(matches!(
            entry["status"].as_str(),
            Some("resolved" | "ambiguous" | "unresolved")
        ));
        let symbols = entry["symbols"].as_array().expect("symbols array");
        match entry["status"].as_str().unwrap() {
            "resolved" => assert_eq!(symbols.len(), 1),
            "ambiguous" => assert!(symbols.len() > 1),
            "unresolved" => assert!(symbols.is_empty()),
            _ => unreachable!(),
        }
    }
}

#[test]
fn objc_headers_render_class_dump_style_property_accessors() {
    let fixture = copy_macho_fixture("/usr/bin/plutil", "objc-headers-plutil");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    let arch = container
        .first_macho()
        .expect("fixture contains a Mach-O image")
        .header()
        .cpu_type()
        .name()
        .to_string();

    let output = run_cli([
        "objc",
        fixture_path,
        "--arch",
        &arch,
        "--headers",
        "--class",
        "PLUContext",
    ]);

    assert!(
        output.status.success(),
        "objc headers command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("@interface PLUContext : NSObject"));
    assert!(stdout.contains(
        "- (id)initWithArguments:(id)arg1 outputFileHandle:(id)arg2 errorFileHandle:(id)arg3;"
    ));
    assert!(stdout.contains("@property (readwrite, strong, atomic) NSString * format;"));
    assert!(stdout.contains("- (id)format;"));
    assert!(stdout.contains("- (void)setFormat:(id)arg1;"));
}

#[test]
#[cfg(unix)]
fn patch_preserves_execute_bit() {
    let fixture = copy_macho_fixture("/usr/bin/true", "preserve-mode-true");
    let fixture_path = fixture.path().to_str().expect("utf8 path");
    let data = std::fs::read(fixture.path()).expect("read fixture");
    let container = macho::parse(&data).expect("parse fixture");
    if !matches!(container, MachoContainer::Fat(_)) {
        return;
    }

    let input_mode = std::fs::metadata(fixture.path())
        .expect("metadata for fixture")
        .permissions()
        .mode()
        & 0o111;
    assert_ne!(input_mode, 0, "test binary should be executable");

    let output_path = temp_file_path("preserve-mode");
    let output = run_cli([
        "patch",
        fixture_path,
        "--add-rpath",
        "/tmp/macho-preserve-mode",
        "--output",
        output_path.to_str().expect("utf8 path"),
    ]);

    assert!(
        output.status.success(),
        "patch command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output_mode = std::fs::metadata(&output_path)
        .expect("metadata for patched output")
        .permissions()
        .mode()
        & 0o111;
    assert_eq!(
        output_mode, input_mode,
        "patched output should preserve execute bits"
    );

    let _ = std::fs::remove_file(&output_path);
}

#[test]
fn data_surface_flags_parse_and_enforce_dependencies() {
    macho_cli::commands::parse_only([
        "macho",
        "strings",
        "fixture",
        "--min-length",
        "4",
        "--offsets",
        "--search",
        "query",
        "--exact",
    ])
    .unwrap();
    assert!(macho_cli::commands::parse_only(["macho", "strings", "fixture", "--exact"]).is_err());
    assert!(
        macho_cli::commands::parse_only(["macho", "strings", "fixture", "--min-length", "0",])
            .is_err()
    );
    macho_cli::commands::parse_only([
        "macho",
        "xrefs",
        "fixture",
        "--kind",
        "stub",
        "--kind",
        "chained-bind",
        "--import",
        "malloc",
        "--demangle",
    ])
    .unwrap();
    assert!(
        macho_cli::commands::parse_only([
            "macho", "xrefs", "fixture", "--to", "1000", "--import", "malloc",
        ])
        .is_err()
    );
    assert!(
        macho_cli::commands::parse_only(["macho", "xrefs", "fixture", "--kind", "bogus"]).is_err()
    );
    macho_cli::commands::parse_only([
        "macho", "ranges", "fixture", "--name", "_main", "--source", "nlist", "--source", "export",
    ])
    .unwrap();
    assert!(
        macho_cli::commands::parse_only(["macho", "ranges", "fixture", "--source", "bogus"])
            .is_err()
    );
    macho_cli::commands::parse_only([
        "macho",
        "vtables",
        "fixture",
        "--class",
        "Foo",
        "--demangle",
    ])
    .unwrap();
    // The pre-rename spelling stays available as a hidden alias.
    macho_cli::commands::parse_only(["macho", "vtables", "fixture", "--class-filter", "Foo"])
        .unwrap();
}

#[test]
fn language_surface_flags_parse_and_validate_closed_values() {
    macho_cli::commands::parse_only([
        "macho",
        "objc",
        "fixture",
        "--kind",
        "class",
        "--kind",
        "protocol",
        "--presence",
        "defined",
        "--name",
        "Controller",
        "--selector",
        "viewDidLoad",
    ])
    .unwrap();
    macho_cli::commands::parse_only([
        "macho",
        "objc",
        "graph",
        "fixture",
        "--kind",
        "protocol",
        "--presence",
        "defined",
    ])
    .unwrap();
    macho_cli::commands::parse_only([
        "macho",
        "objc",
        "xrefs",
        "fixture",
        "--class",
        "Controller",
        "--selector",
        "viewDidLoad",
    ])
    .unwrap();
    assert!(
        macho_cli::commands::parse_only(["macho", "objc", "fixture", "--presence", "guessed",])
            .is_err()
    );
    macho_cli::commands::parse_only([
        "macho",
        "swift",
        "fixture",
        "--kind",
        "class",
        "--kind",
        "protocol",
        "--state",
        "metadata-defined",
        "--state",
        "symbol-only",
        "--name",
        "Module.Type",
        "--exact",
    ])
    .unwrap();
    assert!(macho_cli::commands::parse_only(["macho", "swift", "fixture", "--exact"]).is_err());
    assert!(
        macho_cli::commands::parse_only(["macho", "swift", "fixture", "--state", "guessed",])
            .is_err()
    );
}

#[test]
fn ranges_name_and_source_filters_restrict_entries() {
    let path = temp_file_path("ranges-filters");
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_helper",
            external: false,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "__Z3foov",
            external: true,
            defined: true,
        },
    ]);
    std::fs::write(&path, bytes).expect("write fixture");
    let path_text = path.to_str().expect("utf8 path").to_owned();

    let named = run_cli(["ranges", &path_text, "--name", "_main", "--color", "never"]);
    assert!(
        named.status.success(),
        "{}",
        String::from_utf8_lossy(&named.stderr)
    );
    let named = String::from_utf8(named.stdout).expect("utf8 output");
    assert!(named.contains("_main"));
    assert!(!named.contains("_helper"));
    assert!(!named.contains("__Z3foov"));

    // The name filter also matches the demangled spelling of a mangled symbol.
    let demangled = run_cli(["ranges", &path_text, "--name", "foo()", "--color", "never"]);
    assert!(demangled.status.success());
    let demangled = String::from_utf8(demangled.stdout).expect("utf8 output");
    assert!(demangled.contains("__Z3foov"));
    assert!(!demangled.contains("_main"));

    let nlist = run_cli([
        "ranges", &path_text, "--source", "nlist", "--color", "never",
    ]);
    assert!(nlist.status.success());
    assert!(
        String::from_utf8(nlist.stdout)
            .expect("utf8 output")
            .contains("_main")
    );

    let exported = run_cli([
        "ranges", &path_text, "--source", "export", "--color", "never",
    ]);
    assert!(exported.status.success());
    assert!(
        String::from_utf8(exported.stdout)
            .expect("utf8 output")
            .contains("No symbol ranges found.")
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn xrefs_kind_and_import_filters_restrict_entries() {
    let source = "/usr/bin/tar";
    if !std::path::Path::new(source).exists() {
        eprintln!("skipping: {source} not found");
        return;
    }
    let fixture = copy_macho_fixture(source, "xrefs-filters");
    let path = fixture.path().to_str().expect("utf8 path");

    let stubs = run_cli(["xrefs", path, "--kind", "stub", "--color", "never"]);
    assert!(
        stubs.status.success(),
        "{}",
        String::from_utf8_lossy(&stubs.stderr)
    );
    let stubs = String::from_utf8(stubs.stdout).expect("utf8 output");
    let entries: Vec<&str> = stubs
        .lines()
        .filter(|line| line.starts_with("  0x"))
        .collect();
    assert!(!entries.is_empty(), "expected stub cross-references");
    assert!(entries.iter().all(|line| line.ends_with("[stub]")));

    let imports = run_cli(["xrefs", path, "--import", "malloc", "--color", "never"]);
    assert!(imports.status.success());
    let imports = String::from_utf8(imports.stdout).expect("utf8 output");
    let entries: Vec<&str> = imports
        .lines()
        .filter(|line| line.starts_with("  0x"))
        .collect();
    assert!(!entries.is_empty(), "expected malloc import references");
    assert!(entries.iter().all(|line| line.contains("malloc")));

    // Filters intersect: direct branches never target imports.
    let composed = run_cli([
        "xrefs", path, "--kind", "branch", "--import", "malloc", "--color", "never",
    ]);
    assert!(composed.status.success());
    let composed = String::from_utf8(composed.stdout).expect("utf8 output");
    assert!(composed.lines().all(|line| !line.starts_with("  0x")));
}

#[test]
fn strings_min_length_exact_and_offsets_shape_output() {
    let source = "/usr/bin/tar";
    if !std::path::Path::new(source).exists() {
        eprintln!("skipping: {source} not found");
        return;
    }
    let fixture = copy_macho_fixture(source, "strings-filters");
    let path = fixture.path().to_str().expect("utf8 path");

    let filtered = run_cli([
        "strings",
        path,
        "--min-length",
        "40",
        "--offsets",
        "--color",
        "never",
    ]);
    assert!(
        filtered.status.success(),
        "{}",
        String::from_utf8_lossy(&filtered.stderr)
    );
    let filtered = String::from_utf8(filtered.stdout).expect("utf8 output");
    // Retained values may contain embedded newlines, so line-based checks
    // consider only single-line values that satisfy the requested minimum.
    let mut first_value = None;
    let mut entry_count = 0usize;
    for line in filtered.lines().filter(|line| line.starts_with("  0x")) {
        // "  {va:#018x}  {offset:#010x}  {value}"
        let rest = &line[2..];
        let (va, rest) = rest.split_at(18);
        assert!(va.starts_with("0x"));
        let rest = rest.strip_prefix("  ").expect("column separator");
        let (offset, rest) = rest.split_at(10);
        assert!(offset.starts_with("0x"));
        let value = rest.strip_prefix("  ").expect("column separator");
        if value.chars().count() >= 40 {
            entry_count += 1;
            first_value.get_or_insert_with(|| value.to_owned());
        }
    }
    assert!(entry_count > 0, "expected at least one long string");

    // The minimum-length filter strictly reduces the retained count.
    let unfiltered = run_cli(["strings", path, "--color", "never"]);
    assert!(unfiltered.status.success());
    let count = |text: &str| -> usize {
        text.lines()
            .filter_map(|line| line.strip_prefix("Strings: "))
            .filter_map(|line| line.strip_suffix(" found"))
            .filter_map(|count| count.parse::<usize>().ok())
            .sum()
    };
    let unfiltered = String::from_utf8(unfiltered.stdout).expect("utf8 output");
    assert!(count(&unfiltered) > count(&filtered));

    let query = first_value.expect("at least one string");
    let exact = run_cli([
        "strings", path, "--search", &query, "--exact", "--color", "never",
    ]);
    assert!(exact.status.success());
    let exact = String::from_utf8(exact.stdout).expect("utf8 output");
    let values: Vec<&str> = exact
        .lines()
        .filter(|line| line.starts_with("  0x"))
        .map(|line| line[2..].split_at(18).1.strip_prefix("  ").expect("value"))
        .collect();
    assert!(!values.is_empty(), "exact search should find the string");
    assert!(values.iter().all(|value| *value == query));
}
