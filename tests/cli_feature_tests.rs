use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::model::container::MachContainer;
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
