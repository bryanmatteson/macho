mod support;

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::analysis::reconstruct::c::{CReconstructionPlan, analyze_headers, render_header};
use macho_cli::adapters::validate_c_header;
use support::run_cli;

fn unique_path(stem: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{stem}-{nanos}.{ext}"))
}

fn compile_c_fixture(name: &str, source: &str) -> std::path::PathBuf {
    let c_path = unique_path(name, "c");
    let out_path = unique_path(name, "o");
    std::fs::write(&c_path, source).expect("write source");

    let output = Command::new("clang")
        .arg("-g")
        .arg("-c")
        .arg(&c_path)
        .arg("-o")
        .arg(&out_path)
        .output()
        .expect("run clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_file(&c_path);
    out_path
}

#[test]
#[ignore = "real clang and DWARF smoke test"]
fn dwarf_analysis_recovers_c_surface() {
    let object = compile_c_fixture(
        "c-dwarf-surface",
        r#"
        typedef struct Widget {
            int count;
            const char *name;
        } Widget;

        enum Mode {
            MODE_IDLE = 0,
            MODE_BUSY = 1,
        };

        int shared_value = 7;
        enum Mode current_mode = MODE_BUSY;

        int widget_sum(Widget *widget, int extra) {
            return widget->count + extra + current_mode;
        }
        "#,
    );

    let bytes = std::fs::read(&object).expect("read object");
    let container = macho::parse(&bytes).expect("parse object");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let analysis = analyze_headers(macho, &CReconstructionPlan::default()).expect("analyze");
    let header = render_header(&analysis);

    assert!(header.contains("struct Widget"));
    assert!(header.contains("typedef struct Widget Widget;"));
    assert!(header.contains("enum Mode"));
    assert!(header.contains("int widget_sum"));
    validate_c_header(&header).expect("validate header");

    let _ = std::fs::remove_file(&object);
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
    let data = json["data"].clone();
    let payload = if data.get("functions").is_some() {
        data
    } else {
        data.as_object()
            .and_then(|map| map.values().next())
            .cloned()
            .expect("single-arch payload")
    };
    assert!(payload["functions"].is_array());

    let _ = std::fs::remove_file(&object);
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
