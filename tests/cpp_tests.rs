mod support;

use macho::cpp::{build_headers_for_mach, build_image_index, unify_images, validate_header_syntax};
use std::path::{Path, PathBuf};
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
    let source = r#"
struct Base {
    virtual ~Base();
    virtual int foo(int value) const;
};

struct Derived : Base {
    Derived();
    ~Derived() override;
    int foo(int value) const override;
    virtual const char* bar() const;
};

struct Left {
    virtual ~Left();
    virtual void left();
};

struct Right {
    virtual ~Right();
    virtual void right();
};

struct Multi : Left, Right {
    ~Multi() override;
    void left() override;
    void right() override;
    virtual int mix() const;
};

Base::~Base() {}
int Base::foo(int value) const { return value + 1; }
Derived::Derived() {}
Derived::~Derived() {}
int Derived::foo(int value) const { return value + 2; }
const char* Derived::bar() const { return "bar"; }
Left::~Left() {}
void Left::left() {}
Right::~Right() {}
void Right::right() {}
Multi::~Multi() {}
void Multi::left() {}
void Multi::right() {}
int Multi::mix() const { return 7; }

int free_function(Derived* value, int x) {
    return value ? value->foo(x) : 0;
}

int main() {
    Derived derived;
    Multi multi;
    return free_function(&derived, multi.mix());
}
"#;

    std::fs::write(&source_path, source).expect("write C++ fixture");
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
    if !output.status.success() {
        panic!(
            "failed to compile C++ fixture:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Some(binary_path)
}

#[test]
fn cpp_index_recovers_classes_bases_and_functions() {
    let Some(path) = compile_cpp_fixture("cpp-recovery") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let container = macho::parse(&bytes).expect("parse");
    let mach = container.first_mach();

    let index = build_image_index(mach).expect("build C++ image index");
    assert!(index.classes.contains_key("Base"));
    assert!(index.classes.contains_key("Derived"));
    assert!(index.classes.contains_key("Multi"));

    let derived = index.classes.get("Derived").expect("Derived class");
    assert!(
        derived.bases.iter().any(|base| base.name == "Base"),
        "Derived should inherit from Base"
    );
    assert!(
        derived
            .methods
            .iter()
            .any(|method| method.name.leaf() == Some("foo")),
        "Derived should recover foo"
    );

    let multi = index.classes.get("Multi").expect("Multi class");
    assert!(
        multi.bases.iter().any(|base| base.name == "Left"),
        "Multi should recover Left base"
    );
    assert!(
        multi.bases.iter().any(|base| base.name == "Right"),
        "Multi should recover Right base"
    );

    assert!(
        index
            .free_functions
            .iter()
            .any(|function| function.name.leaf() == Some("free_function")),
        "free_function should be recovered"
    );
}

#[test]
fn cpp_header_renders_and_validates() {
    let Some(path) = compile_cpp_fixture("cpp-header") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let container = macho::parse(&bytes).expect("parse");
    let mach = container.first_mach();

    let header = build_headers_for_mach(mach).expect("render header");
    assert!(header.contains("class Derived"));
    assert!(header.contains("virtual"));

    let header_path = support::temp_file_path("cpp-header.hpp");
    std::fs::write(&header_path, header).expect("write header");
    validate_header_syntax(Path::new(&header_path)).expect("clang++ validates emitted header");
}

#[test]
fn cpp_unification_merges_duplicate_images() {
    let Some(path) = compile_cpp_fixture("cpp-unify") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let container = macho::parse(&bytes).expect("parse");
    let mach = container.first_mach();

    let index = build_image_index(mach).expect("build image index");
    let unified = unify_images(&[index.clone(), index]);
    assert!(unified.classes.contains_key("Derived"));
    assert!(
        unified
            .free_functions
            .iter()
            .any(|function| function.name.leaf() == Some("free_function"))
    );
}
