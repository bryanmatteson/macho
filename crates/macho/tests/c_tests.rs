#![cfg(feature = "cli")]

mod support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::analysis::reconstruct::c::{CReconstructionPlan, analyze_headers, render_header};
use macho::cli::adapters::validate_c_header;
use support::run_cli;

fn unique_path(stem: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{stem}-{nanos}.{ext}"))
}

#[test]
fn c_header_validation_is_in_process_and_portable() {
    validate_c_header(
        "typedef struct Widget { int count; const char *name; } Widget;\n\
         int widget_sum(Widget *widget, int extra);\n",
    )
    .expect("validate a complete C header");
}

#[test]
fn header_correlation_marks_matches() {
    let bytes =
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_widget_sum",
            external: true,
            defined: true,
        }]);
    let container = macho::parse(&bytes).expect("parse object");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let correlator = macho::analysis::reconstruct::c::InMemoryHeaderCorrelator::new(vec![
        macho::analysis::reconstruct::c::HeaderSource {
            path: "fixture.h".to_owned(),
            contents: "int widget_sum(void);\n".to_owned(),
        },
    ]);
    let analysis = analyze_headers(
        macho,
        &CReconstructionPlan {
            correlator: Some(&correlator),
        },
    )
    .expect("analyze");

    assert!(
        analysis
            .correlated_headers
            .iter()
            .any(|item| item.symbol == "widget_sum")
    );
}

#[test]
fn c_command_outputs_json() {
    let object = unique_path("c-cli-json", "o");
    std::fs::write(
        &object,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_increment",
            external: true,
            defined: true,
        }]),
    )
    .expect("write object");

    let output = run_cli(["c", "--format", "json", object.to_str().expect("utf8 path")]);

    assert!(
        output.status.success(),
        "c command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "c");
    assert_eq!(json["data"]["schema_version"], 3);
    assert_eq!(json["data"]["language"], "c_abi");
    let slice = &json["data"]["slices"][0];
    assert!(slice["observations"].is_array());
    assert!(slice["entities"].is_array());
    assert_eq!(
        slice["resolved_plan"]["selected_entity_ids"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    let _ = std::fs::remove_file(&object);
}

#[test]
fn recovery_header_root_correlates_typed_signature_and_projects_it() {
    let object = unique_path("c-correlated-header", "o");
    let root = unique_path("c-correlated-root", "headers");
    std::fs::create_dir(&root).expect("create header root");
    std::fs::write(root.join("widget.h"), "int widget_sum(void);\n")
        .expect("write correlated header");
    std::fs::write(
        &object,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_widget_sum",
            external: true,
            defined: true,
        }]),
    )
    .expect("write object");

    let header_root = format!("fixture={}", root.display());
    let output = run_cli([
        "c",
        "--view",
        "header",
        "--header-root",
        &header_root,
        object.to_str().expect("UTF-8 path"),
    ]);

    assert!(
        output.status.success(),
        "C header projection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 header");
    assert!(stdout.contains("int widget_sum("), "{stdout}");
    assert!(!stdout.contains("0 declarations emitted"), "{stdout}");

    let _ = std::fs::remove_file(&object);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn recovery_header_root_correlates_global_value_type_and_projects_variable() {
    let object = unique_path("c-correlated-global", "o");
    let root = unique_path("c-correlated-global-root", "headers");
    std::fs::create_dir(&root).expect("create header root");
    std::fs::write(
        root.join("globals.h"),
        "extern unsigned long global_count;\n",
    )
    .expect("write correlated header");
    std::fs::write(
        &object,
        macho_test_support::thin64_x86_64_with_data_symbols(&[macho_test_support::SymbolFixture {
            name: "_global_count",
            external: true,
            defined: true,
        }]),
    )
    .expect("write object");

    let header_root = format!("fixture={}", root.display());
    let output = run_cli([
        "c",
        "--view",
        "header",
        "--header-root",
        &header_root,
        object.to_str().expect("UTF-8 path"),
    ]);

    assert!(
        output.status.success(),
        "C global projection failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 header");
    assert!(
        stdout.contains("extern unsigned long global_count;"),
        "{stdout}"
    );

    let _ = std::fs::remove_file(&object);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn image_header_is_reported_as_runtime_artifact() {
    let object = unique_path("c-runtime-artifact", "o");
    std::fs::write(
        &object,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_mh_execute_header",
            external: true,
            defined: true,
        }]),
    )
    .expect("write object");
    let output = run_cli([
        "c",
        "--format",
        "json",
        object.to_str().expect("UTF-8 path"),
    ]);
    let _ = std::fs::remove_file(&object);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        json["data"]["slices"][0]["entities"][0]["role"]["value"],
        "runtime_artifact"
    );
}

#[test]
fn unknown_kind_filter_does_not_expand_to_all_kinds() {
    let object = unique_path("c-unknown-kind", "o");
    std::fs::write(
        &object,
        macho_test_support::thin64_x86_64_with_symbols(&[
            macho_test_support::SymbolFixture {
                name: "_defined_function",
                external: true,
                defined: true,
            },
            macho_test_support::SymbolFixture {
                name: "_imported_unknown",
                external: true,
                defined: false,
            },
        ]),
    )
    .expect("write object");
    let output = run_cli([
        "c",
        "--scope",
        "all",
        "--kind",
        "unknown",
        "--format",
        "json",
        object.to_str().expect("UTF-8 path"),
    ]);
    let _ = std::fs::remove_file(&object);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let slice = &json["data"]["slices"][0];
    assert_eq!(
        slice["resolved_plan"]["selected_entity_ids"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    let selected = slice["resolved_plan"]["selected_entity_ids"][0]
        .as_str()
        .unwrap();
    let entity = slice["entities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entity| entity["id"] == selected)
        .unwrap();
    assert_eq!(entity["role"]["value"], "unknown");
}

#[test]
fn no_dwarf_fallback_does_not_guess_undefined_imports_as_functions() {
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_local_sum",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_printf",
            external: true,
            defined: false,
        },
    ]);
    let container = macho::parse(&bytes).expect("parse object");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");
    let analysis = analyze_headers(macho, &CReconstructionPlan::default()).expect("analyze");
    let header = render_header(&analysis);

    assert!(header.contains("local_sum"));
    assert!(!header.contains("printf("));
}

#[test]
fn header_output_skips_internal_static_symbols() {
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_internal_helper",
            external: false,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_exported_value",
            external: true,
            defined: true,
        },
    ]);
    let container = macho::parse(&bytes).expect("parse object");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");
    let analysis = analyze_headers(macho, &CReconstructionPlan::default()).expect("analyze");
    let header = render_header(&analysis);

    assert!(header.contains("exported_value"));
    assert!(!header.contains("internal_helper"));
}
