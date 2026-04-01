mod support;

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::c::{CAnalysisOptions, analyze_headers, render_header, validate_header_syntax};
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

        int widget_sum(Widget *widget, int extra) {
            return widget->count + extra;
        }
        "#,
    );

    let bytes = std::fs::read(&object).expect("read object");
    let container = macho::parse(&bytes).expect("parse object");
    let mach = container.first_mach();

    let analysis = analyze_headers(mach, &CAnalysisOptions::default()).expect("analyze");
    let header = render_header(&analysis);

    assert!(header.contains("struct Widget"));
    assert!(header.contains("typedef struct Widget Widget;"));
    assert!(header.contains("enum Mode"));
    assert!(header.contains("int widget_sum"));
    validate_header_syntax(&header).expect("validate header");

    let _ = std::fs::remove_file(&object);
}

#[test]
fn header_correlation_marks_matches() {
    let header_root = unique_path("c-header-root", "dir");
    std::fs::create_dir_all(&header_root).expect("create header root");
    std::fs::write(
        header_root.join("fixture.h"),
        "typedef struct Widget Widget;\nint widget_sum(Widget *widget, int extra);\n",
    )
    .expect("write header");

    let object = compile_c_fixture(
        "c-header-correlation",
        r#"
        typedef struct Widget {
            int count;
        } Widget;
        int widget_sum(Widget *widget, int extra) { return widget->count + extra; }
        "#,
    );

    let bytes = std::fs::read(&object).expect("read object");
    let container = macho::parse(&bytes).expect("parse object");
    let mach = container.first_mach();

    let analysis = analyze_headers(
        mach,
        &CAnalysisOptions {
            header_root: Some(header_root.clone()),
        },
    )
    .expect("analyze");

    assert!(
        analysis
            .correlated_headers
            .iter()
            .any(|item| item.symbol == "widget_sum")
    );

    let _ = std::fs::remove_file(&object);
    let _ = std::fs::remove_dir_all(&header_root);
}

#[test]
fn c_command_outputs_json() {
    let object = compile_c_fixture(
        "c-cli-json",
        r#"
        int shared_counter;
        int increment(int value) { return value + 1; }
        "#,
    );

    let output = run_cli(["c", "--json", object.to_str().expect("utf8 path")]);

    assert!(
        output.status.success(),
        "c command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let payload = if json.get("functions").is_some() {
        json
    } else {
        json.as_object()
            .and_then(|map| map.values().next())
            .cloned()
            .expect("single-arch payload")
    };
    assert!(payload["functions"].is_array());

    let _ = std::fs::remove_file(&object);
}
