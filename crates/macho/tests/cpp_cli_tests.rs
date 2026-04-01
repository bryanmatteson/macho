mod support;

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_path(stem: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{stem}-{nanos}.{ext}"))
}

fn compile_cpp_fixture(name: &str) -> Option<PathBuf> {
    let compiler_available = Command::new("xcrun")
        .arg("clang++")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !compiler_available {
        eprintln!("skipping: xcrun clang++ not available");
        return None;
    }

    let source_path = unique_path(name, "cpp");
    let binary_path = unique_path(name, "bin");
    std::fs::write(
        &source_path,
        r#"
struct Demo {
    virtual ~Demo();
    virtual int run(int value) const;
};

Demo::~Demo() {}
int Demo::run(int value) const { return value; }

int main() {
    Demo demo;
    return demo.run(4);
}
"#,
    )
    .expect("write fixture");

    let output = Command::new("xcrun")
        .arg("clang++")
        .arg("-std=c++17")
        .arg("-O0")
        .arg("-fno-inline")
        .arg(&source_path)
        .arg("-o")
        .arg(&binary_path)
        .output()
        .expect("invoke clang++");
    assert!(
        output.status.success(),
        "clang++ failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    Some(binary_path)
}

#[test]
fn cpp_cli_json_emits_recovered_classes() {
    let Some(path) = compile_cpp_fixture("cpp-cli-json") else {
        return;
    };
    let output = support::run_cli(["extract", "rtti", path.to_str().unwrap(), "--json"]);
    assert!(output.status.success(), "cpp CLI failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"classes\""));
    assert!(stdout.contains("\"Demo\""));
}

#[test]
fn cpp_cli_headers_emit_class_declaration() {
    let Some(path) = compile_cpp_fixture("cpp-cli-headers") else {
        return;
    };
    let output = support::run_cli(["extract", "rtti", path.to_str().unwrap(), "--headers"]);
    assert!(output.status.success(), "cpp CLI failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("class Demo"));
    assert!(stdout.contains("virtual"));
}
