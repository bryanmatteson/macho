mod support;

use macho::extract::cpp::{
    build_headers_for_mach, build_image_index, unify_images, validate_header_syntax,
};
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
    int overload();
    int overload() const;
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

namespace scoped {
struct Plain {
    Plain();
    int ping() const;
};

struct Widget {
    Widget();
    ~Widget();
    virtual int run(int value) const;
};
}

Base::~Base() {}
int Base::foo(int value) const { return value + 1; }
Derived::Derived() {}
Derived::~Derived() {}
int Derived::foo(int value) const { return value + 2; }
const char* Derived::bar() const { return "bar"; }
int Derived::overload() { return 1; }
int Derived::overload() const { return 2; }
Left::~Left() {}
void Left::left() {}
Right::~Right() {}
void Right::right() {}
Multi::~Multi() {}
void Multi::left() {}
void Multi::right() {}
int Multi::mix() const { return 7; }
scoped::Plain::Plain() {}
int scoped::Plain::ping() const { return 11; }
scoped::Widget::Widget() {}
scoped::Widget::~Widget() {}
int scoped::Widget::run(int value) const { return value + 3; }

int free_function(Derived* value, int x) {
    return value ? value->foo(x) : 0;
}

namespace scoped {
int helper(Widget* widget) {
    return widget ? widget->run(5) : 0;
}
}

int main() {
    Derived derived;
    Multi multi;
    scoped::Widget widget;
    return free_function(&derived, multi.mix()) + scoped::helper(&widget);
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
    let macho = container.first_mach();

    let index = build_image_index(macho).expect("build C++ image index");
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
    assert!(
        derived
            .methods
            .iter()
            .any(|method| method.name.leaf() == Some("foo") && method.is_virtual),
        "Derived::foo should be marked virtual from vtable evidence"
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
    assert!(
        index.classes.contains_key("scoped::Widget"),
        "namespaced class should preserve its full qualified name"
    );
    assert!(
        index.classes.contains_key("scoped::Plain"),
        "non-polymorphic namespaced class should be discovered via ctor ownership"
    );
    assert!(
        index
            .classes
            .get("scoped::Widget")
            .is_some_and(|class| class
                .methods
                .iter()
                .any(|method| method.name.as_string() == "scoped::Widget::run")),
        "scoped::Widget::run should stay attached to the namespaced class"
    );
    assert!(
        index
            .free_functions
            .iter()
            .any(|function| function.name.as_string() == "scoped::helper"),
        "scoped::helper should remain a free function"
    );
}

#[test]
fn cpp_header_renders_and_validates() {
    let Some(path) = compile_cpp_fixture("cpp-header") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let container = macho::parse(&bytes).expect("parse");
    let macho = container.first_mach();

    let header = build_headers_for_mach(macho).expect("render header");
    assert!(header.contains("class Derived"));
    assert!(header.contains("virtual"));
    assert!(header.contains("namespace scoped {"));
    assert!(header.contains("class Widget;"));
    assert!(header.contains("class Plain;"));
    assert!(
        header.contains("__macho::unknown_return helper(Widget* arg0);")
            || header.contains("__macho::unknown_return helper(scoped::Widget* arg0);")
    );
    assert!(!header.contains("scoped::helper("));
    assert!(header.contains("class Widget {"));
    assert!(header.contains("__macho::unknown_return overload();"));
    assert!(header.contains("__macho::unknown_return overload() const;"));

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
    let macho = container.first_mach();

    let index = build_image_index(macho).expect("build image index");
    let unified = unify_images(&[index.clone(), index]);
    assert!(unified.classes.contains_key("Derived"));
    assert!(
        unified
            .free_functions
            .iter()
            .any(|function| function.name.leaf() == Some("free_function"))
    );
}

#[test]
fn cpp_unification_propagates_virtuality_from_vtables() {
    let Some(path) = compile_cpp_fixture("cpp-unify-virtual") else {
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let container = macho::parse(&bytes).expect("parse");
    let macho = container.first_mach();

    let index = build_image_index(macho).expect("build image index");
    let mut methods_only = index.clone();
    methods_only
        .classes
        .values_mut()
        .for_each(|class| class.vtables.clear());
    let mut vtables_only = index;
    vtables_only
        .classes
        .values_mut()
        .for_each(|class| class.methods.clear());

    let unified = unify_images(&[methods_only, vtables_only]);
    let derived = unified.classes.get("Derived").expect("Derived class");
    assert!(
        derived
            .methods
            .iter()
            .any(|method| method.name.leaf() == Some("foo") && method.is_virtual),
        "vtable evidence from one image should mark the merged method virtual"
    );
}
