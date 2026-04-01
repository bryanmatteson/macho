mod support;

use std::path::PathBuf;
use std::process::Command;

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

    let source_path = support::temp_file_path(&format!("{name}.cpp"));
    let binary_path = support::temp_file_path(name);
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
    let output = support::run_cli(["cpp", path.to_str().unwrap(), "--json"]);
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
    let output = support::run_cli(["cpp", path.to_str().unwrap(), "--headers"]);
    assert!(output.status.success(), "cpp CLI failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("class Demo"));
    assert!(stdout.contains("virtual"));
}
