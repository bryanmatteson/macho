use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::inspect::ImageInspector;
use macho::model::container::MachContainer;
use macho::objc::graph::ObjCGraph;
use macho::objc::parse_objc_metadata;
use macho::swift::SwiftTypeIndex;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn macho_bin() -> &'static str {
    env!("CARGO_BIN_EXE_macho")
}

fn temp_file_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{name}-{nanos}.bin"))
}

fn minimal_fileset_binary(entry_id: &str, vm_addr: u64, file_offset: u64) -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const MH_FILESET: u32 = 0xC;
    const LC_REQ_DYLD: u32 = 0x8000_0000;
    const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

    let str_offset = 32u32;
    let cmdsize = ((str_offset as usize + entry_id.len() + 1 + 7) & !7) as u32;

    let mut data = Vec::new();
    data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    data.extend_from_slice(&(CPU_TYPE_ARM64 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&MH_FILESET.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&cmdsize.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_FILESET_ENTRY.to_le_bytes());
    data.extend_from_slice(&cmdsize.to_le_bytes());
    data.extend_from_slice(&vm_addr.to_le_bytes());
    data.extend_from_slice(&file_offset.to_le_bytes());
    data.extend_from_slice(&str_offset.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(entry_id.as_bytes());
    data.push(0);
    while data.len() % 8 != 0 {
        data.push(0);
    }

    data
}

fn unique_marker(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    format!("{prefix}-{nanos}")
}

fn has_rpath(mach: &macho::model::mach::MachFile<'_>, needle: &str) -> bool {
    mach.load_commands()
        .iter()
        .any(|lc| lc.kind.as_rpath() == Some(needle))
}

fn objc_graph_fixture(path: &str) -> Option<(String, ObjCGraph)> {
    let data = std::fs::read(path).ok()?;
    let container = macho::parse(&data).ok()?;
    match &container {
        MachContainer::Fat(fat) => fat.arches().iter().find_map(|arch| {
            let metadata = parse_objc_metadata(&arch.mach).ok()?;
            let graph = ObjCGraph::build_from_mach(&metadata, &arch.mach);
            if graph.classes.is_empty() {
                None
            } else {
                Some((arch.spec.name(), graph))
            }
        }),
        MachContainer::Thin(mach) => {
            let metadata = parse_objc_metadata(mach).ok()?;
            let graph = ObjCGraph::build_from_mach(&metadata, mach);
            if graph.classes.is_empty() {
                None
            } else {
                Some((ImageInspector::new(mach).info().arch.clone(), graph))
            }
        }
    }
}

#[test]
fn snapshot_arch_filter_requires_match() {
    let output = Command::new(macho_bin())
        .args(["snapshot", "--arch", "definitely_not_real", "/usr/bin/true"])
        .output()
        .expect("failed to run macho snapshot");

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
    let bytes = minimal_fileset_binary("com.example.member", 0x1000_0000, 0x2000);
    std::fs::write(&path, bytes).expect("failed to write temp Mach-O");

    let output = Command::new(macho_bin())
        .args(["container", "--json", path.to_str().expect("utf8 path")])
        .output()
        .expect("failed to run macho container");

    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "container command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(json["format"], "Fileset");
    let entry = &json["fileset"]["entries"][0];

    assert_eq!(entry["arch"], "arm64");
    assert_eq!(entry["entry_id"], "com.example.member");
    assert_eq!(entry["vm_addr"], 0x1000_0000u64);
    assert_eq!(entry["file_offset"], 0x2000u64);
}

#[test]
fn fileset_list_reports_no_match_for_filtered_arch() {
    let path = temp_file_path("fileset-filter");
    let bytes = minimal_fileset_binary("com.example.member", 0x1000_0000, 0x2000);
    std::fs::write(&path, bytes).expect("failed to write temp Mach-O");

    let output = Command::new(macho_bin())
        .args([
            "fileset",
            "list",
            path.to_str().expect("utf8 path"),
            "--arch",
            "x86_64",
        ])
        .output()
        .expect("failed to run macho fileset list");

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
    let output = Command::new(macho_bin())
        .args([
            "container",
            "--json",
            "--parity-domain",
            "imports",
            "/usr/bin/plutil",
        ])
        .output()
        .expect("failed to run macho container");

    assert!(
        output.status.success(),
        "container command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(json["parity"]["domains"], serde_json::json!(["imports"]));
    if let Some(divergences) = json["parity"]["divergences"].as_array() {
        for divergence in divergences {
            assert_eq!(divergence["domain"], "imports");
        }
    }
}

#[test]
fn fileset_inspect_reports_single_not_found_message() {
    let path = temp_file_path("fileset-inspect-miss");
    let bytes = minimal_fileset_binary("com.example.member", 0x1000_0000, 0x2000);
    std::fs::write(&path, bytes).expect("failed to write temp Mach-O");

    let output = Command::new(macho_bin())
        .args([
            "fileset",
            "inspect",
            path.to_str().expect("utf8 path"),
            "missing.entry",
        ])
        .output()
        .expect("failed to run macho fileset inspect");

    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "fileset command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.matches("Fileset entry 'missing.entry' not found").count(), 1);
}

#[test]
fn fat_patch_bytes_requires_arch() {
    let data = std::fs::read("/usr/bin/true").expect("read /usr/bin/true");
    let container = macho::parse(&data).expect("parse /usr/bin/true");
    if !matches!(container, MachContainer::Fat(_)) {
        return;
    }

    let output = Command::new(macho_bin())
        .args([
            "patch",
            "patch-bytes",
            "/usr/bin/true",
            "--offset",
            "0x100",
            "--hex",
            "00010203",
            "--dry-run",
        ])
        .output()
        .expect("failed to run macho patch patch-bytes");

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
    let data = std::fs::read("/usr/bin/true").expect("read /usr/bin/true");
    let container = macho::parse(&data).expect("parse /usr/bin/true");
    let fat = match &container {
        MachContainer::Fat(fat) if fat.arches().len() >= 2 => fat,
        _ => return,
    };

    let selected_arch = fat.arches()[0].spec.name();
    let untouched_arch = fat.arches()[1].spec.name();
    let rpath = format!("/tmp/{}", unique_marker("macho-fat-selected"));
    let output_path = temp_file_path("fat-selected-rpath");

    let output = Command::new(macho_bin())
        .args([
            "patch",
            "add-rpath",
            "/usr/bin/true",
            &rpath,
            "--arch",
            &selected_arch,
            "--output",
            output_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("failed to run macho patch add-rpath");

    assert!(
        output.status.success(),
        "patch command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let patched = std::fs::read(&output_path).expect("read patched binary");
    let patched_container = macho::parse(&patched).expect("parse patched binary");
    let patched_fat = match &patched_container {
        MachContainer::Fat(fat) => fat,
        _ => panic!("expected fat output"),
    };

    let selected = patched_fat
        .arches()
        .iter()
        .find(|arch| arch.spec.name() == selected_arch)
        .expect("selected arch missing");
    assert!(
        has_rpath(&selected.mach, &rpath),
        "selected arch should contain new rpath"
    );

    let untouched = patched_fat
        .arches()
        .iter()
        .find(|arch| arch.spec.name() == untouched_arch)
        .expect("untouched arch missing");
    assert!(
        !has_rpath(&untouched.mach, &rpath),
        "non-selected arch should not contain new rpath"
    );

    let _ = std::fs::remove_file(&output_path);
}

#[test]
fn fat_patch_add_rpath_all_arches_by_default() {
    let data = std::fs::read("/usr/bin/true").expect("read /usr/bin/true");
    let container = macho::parse(&data).expect("parse /usr/bin/true");
    let fat = match &container {
        MachContainer::Fat(fat) => fat,
        _ => return,
    };

    let rpath = format!("/tmp/{}", unique_marker("macho-fat-all"));
    let output_path = temp_file_path("fat-all-rpath");

    let output = Command::new(macho_bin())
        .args([
            "patch",
            "add-rpath",
            "/usr/bin/true",
            &rpath,
            "--output",
            output_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("failed to run macho patch add-rpath");

    assert!(
        output.status.success(),
        "patch command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let patched = std::fs::read(&output_path).expect("read patched binary");
    let patched_container = macho::parse(&patched).expect("parse patched binary");
    let patched_fat = match &patched_container {
        MachContainer::Fat(fat) => fat,
        _ => panic!("expected fat output"),
    };

    assert_eq!(patched_fat.arches().len(), fat.arches().len());
    for arch in patched_fat.arches() {
        assert!(
            has_rpath(&arch.mach, &rpath),
            "arch {} should contain new rpath",
            arch.spec.name()
        );
    }

    let _ = std::fs::remove_file(&output_path);
}

#[test]
fn swift_json_kind_filter_applies_to_output() {
    let data = std::fs::read("/usr/bin/plutil").expect("read /usr/bin/plutil");
    let container = macho::parse(&data).expect("parse /usr/bin/plutil");
    let fat = match &container {
        MachContainer::Fat(fat) if !fat.arches().is_empty() => fat,
        _ => return,
    };

    let selected_arch = fat.arches()[0].spec.name();
    let selected_kind = SwiftTypeIndex::build(&fat.arches()[0].mach)
        .types
        .first()
        .map(|ty| ty.kind)
        .expect("expected Swift types in selected arch");
    let kind_arg = selected_kind.to_string();
    let expected_kind = serde_json::to_value(selected_kind).expect("serialize kind");

    let output = Command::new(macho_bin())
        .args([
            "swift",
            "/usr/bin/plutil",
            "--arch",
            &selected_arch,
            "--kind",
            &kind_arg,
            "--json",
        ])
        .output()
        .expect("failed to run macho swift");

    assert!(
        output.status.success(),
        "swift command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let types = json["types"]
        .as_array()
        .expect("filtered index types array");

    assert!(
        !types.is_empty(),
        "filtered Swift JSON output should contain at least one type"
    );
    assert!(
        types.iter().all(|ty| ty["kind"] == expected_kind),
        "JSON output should honor the requested kind filter"
    );
}

#[test]
fn objc_graph_json_returns_null_for_slice_without_metadata() {
    let data = std::fs::read("/usr/bin/true").expect("read /usr/bin/true");
    let container = macho::parse(&data).expect("parse /usr/bin/true");
    let arch = ImageInspector::new(container.first_mach())
        .info()
        .arch
        .clone();

    let output = Command::new(macho_bin())
        .args(["objc", "graph", "/usr/bin/true", "--arch", &arch, "--json"])
        .output()
        .expect("failed to run macho objc graph");

    assert!(
        output.status.success(),
        "objc graph command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    assert_eq!(json, serde_json::Value::Null);
}

#[test]
fn objc_selectors_json_reports_owners() {
    let Some((arch, graph)) = objc_graph_fixture("/usr/bin/plutil") else {
        return;
    };
    let (selector, owners) = graph
        .selectors
        .iter()
        .find(|(_, owners)| !owners.is_empty())
        .expect("expected at least one selector");

    let output = Command::new(macho_bin())
        .args([
            "objc",
            "selectors",
            "/usr/bin/plutil",
            "--arch",
            &arch,
            "--name",
            selector,
            "--json",
        ])
        .output()
        .expect("failed to run macho objc selectors");

    assert!(
        output.status.success(),
        "objc selectors command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let returned_owners = json["owners"].as_array().expect("owners array");

    assert_eq!(json["selector"], selector.as_str());
    assert_eq!(returned_owners.len(), owners.len());
    assert!(
        returned_owners
            .iter()
            .all(|owner| owner["class_name"].is_string() && owner["kind"].is_string()),
        "selector JSON should include serialized owners"
    );
}

#[test]
fn objc_xrefs_json_reports_symbol_links() {
    let Some((arch, graph)) = objc_graph_fixture("/usr/bin/plutil") else {
        return;
    };
    let Some((class_name, selector, symbol)) = graph.classes.values().find_map(|class| {
        class
            .effective_instance_methods
            .iter()
            .find_map(|method| {
                method
                    .imp_symbol
                    .as_ref()
                    .map(|symbol| (class.name.clone(), method.selector.clone(), symbol.clone()))
            })
            .or_else(|| {
                class.effective_class_methods.iter().find_map(|method| {
                    method
                        .imp_symbol
                        .as_ref()
                        .map(|symbol| (class.name.clone(), method.selector.clone(), symbol.clone()))
                })
            })
    }) else {
        return;
    };

    let output = Command::new(macho_bin())
        .args([
            "objc",
            "xrefs",
            "/usr/bin/plutil",
            "--arch",
            &arch,
            "--class",
            &class_name,
            "--json",
        ])
        .output()
        .expect("failed to run macho objc xrefs");

    assert!(
        output.status.success(),
        "objc xrefs command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let entries = json.as_array().expect("xref JSON array");
    assert!(
        entries.iter().any(|entry| {
            entry["class_name"] == class_name
                && entry["selector"] == selector
                && entry["imp_symbol"] == symbol
        }),
        "xref JSON should include the resolved method symbol link"
    );
}

#[test]
#[cfg(unix)]
fn patch_preserves_execute_bit() {
    let data = std::fs::read("/usr/bin/true").expect("read /usr/bin/true");
    let container = macho::parse(&data).expect("parse /usr/bin/true");
    if !matches!(container, MachContainer::Fat(_)) {
        return;
    }

    let input_mode = std::fs::metadata("/usr/bin/true")
        .expect("metadata for /usr/bin/true")
        .permissions()
        .mode()
        & 0o111;
    assert_ne!(input_mode, 0, "test binary should be executable");

    let output_path = temp_file_path("preserve-mode");
    let output = Command::new(macho_bin())
        .args([
            "patch",
            "add-rpath",
            "/usr/bin/true",
            "/tmp/macho-preserve-mode",
            "--output",
            output_path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("failed to run macho patch add-rpath");

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
