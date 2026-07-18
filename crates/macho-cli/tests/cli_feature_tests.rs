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
