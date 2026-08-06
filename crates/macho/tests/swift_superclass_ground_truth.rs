#![cfg(feature = "cli")]

//! Recovered Swift inheritance, checked against source we compiled ourselves.
//!
//! Every other Swift test asserts against metadata whose original source nobody
//! in the loop has seen, so a wrong ABI offset would produce a plausible name
//! and pass. Here the class hierarchy is written in this file, compiled with the
//! host `swiftc`, and recovered — so the assertion compares the projection to a
//! declaration that is known rather than inferred.
//!
//! The superclass reference sits at class-descriptor + 20, the first word after
//! the prefix every type context descriptor shares. A struct or enum stores a
//! field count at that same offset, which is why the two non-class cases below
//! matter as much as the class ones: reading the offset without gating on kind
//! reports a small integer as a superclass name.

mod support;

#[cfg(target_os = "macos")]
use support::{run_cli, temp_file_path};

#[cfg(target_os = "macos")]
const SOURCE: &str = r#"
import Foundation

public class RootBase { public var a: Int = 0 }
public class MiddleDerived: RootBase { public var b: String = "" }
public class LeafDerived: MiddleDerived { public var c: Double = 0 }
public class ObjCDerived: NSObject { public var d: Bool = false }
public class GenericBox<T> { public var boxed: T? = nil }
public class GenericDerived: GenericBox<Int> { public var e: Int = 0 }
public struct PlainStruct { public var f: Int = 0 }
public enum PlainEnum { case one, two(Int) }
"#;

/// Compile `SOURCE` into a dylib, returning `None` when no usable `swiftc` is
/// present so a host without the toolchain skips rather than fails.
#[cfg(target_os = "macos")]
fn compile_fixture() -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let source_path = temp_file_path("swift-hierarchy-src").with_extension("swift");
    let library_path = temp_file_path("swift-hierarchy-lib").with_extension("dylib");
    std::fs::write(&source_path, SOURCE).expect("write Swift source");

    let compiled = std::process::Command::new("swiftc")
        .arg("-emit-library")
        .arg("-module-name")
        .arg("hier")
        .arg("-o")
        .arg(&library_path)
        .arg(&source_path)
        .output();

    match compiled {
        Ok(output) if output.status.success() && library_path.exists() => {
            Some((source_path, library_path))
        }
        _ => {
            let _ = std::fs::remove_file(&source_path);
            let _ = std::fs::remove_file(&library_path);
            None
        }
    }
}

#[test]
#[cfg(target_os = "macos")]
fn recovered_swift_inheritance_matches_the_source_it_was_compiled_from() {
    let Some((source_path, library_path)) = compile_fixture() else {
        eprintln!("skipping: no usable swiftc on this host");
        return;
    };

    let output = run_cli([
        "swift",
        library_path.to_str().expect("utf8 path"),
        "--headers",
        "--format",
        "json",
    ]);
    let status = output.status;
    let stdout = output.stdout.clone();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = std::fs::remove_file(&source_path);
    let _ = std::fs::remove_file(&library_path);

    assert!(status.success(), "swift --headers failed: {stderr}");
    let envelope: serde_json::Value = serde_json::from_slice(&stdout).expect("valid JSON output");
    let declarations = envelope["data"]["slices"][0]["header"]["declarations"]
        .as_array()
        .expect("projected declarations")
        .clone();

    let superclass_of = |name: &str| -> Option<String> {
        declarations
            .iter()
            .find(|declaration| declaration["name"] == serde_json::json!(name))
            .unwrap_or_else(|| panic!("no declaration for {name}: {declarations:#?}"))["superclass"]
            .as_str()
            .map(str::to_owned)
    };

    // Declared inheritance, recovered from the class descriptor.
    assert_eq!(
        superclass_of("hier.MiddleDerived").as_deref(),
        Some("hier.RootBase")
    );
    assert_eq!(
        superclass_of("hier.LeafDerived").as_deref(),
        Some("hier.MiddleDerived")
    );
    assert_eq!(
        superclass_of("hier.ObjCDerived").as_deref(),
        Some("__C.NSObject"),
        "an Objective-C base resolves through the imported-declaration module"
    );
    // The generic argument is not carried by the superclass reference, which
    // names the nominal type; `GenericBox<Int>` recovers as `GenericBox`.
    assert_eq!(
        superclass_of("hier.GenericDerived").as_deref(),
        Some("hier.GenericBox")
    );

    // A native Swift class inherits from nothing unless it says so.
    assert_eq!(superclass_of("hier.RootBase"), None);
    assert_eq!(superclass_of("hier.GenericBox"), None);

    // The offset a class uses for its superclass holds a field count on these
    // two, so a missing kind gate shows up here as an invented base type.
    assert_eq!(superclass_of("hier.PlainStruct"), None);
    assert_eq!(superclass_of("hier.PlainEnum"), None);
}

#[test]
#[cfg(target_os = "macos")]
fn rendered_swift_source_spells_the_recovered_inheritance() {
    let Some((source_path, library_path)) = compile_fixture() else {
        eprintln!("skipping: no usable swiftc on this host");
        return;
    };

    let output = run_cli([
        "swift",
        library_path.to_str().expect("utf8 path"),
        "--headers",
    ]);
    let status = output.status;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let _ = std::fs::remove_file(&source_path);
    let _ = std::fs::remove_file(&library_path);

    assert!(status.success(), "swift --headers failed: {stderr}");
    for expected in [
        "class MiddleDerived: hier.RootBase {",
        "class LeafDerived: hier.MiddleDerived {",
        "class ObjCDerived: __C.NSObject {",
        "class RootBase {",
        "struct PlainStruct {",
        "enum PlainEnum {",
    ] {
        assert!(
            stdout.contains(expected),
            "missing {expected:?} in rendered source:\n{stdout}"
        );
    }
    // The generic parameter clause comes from the field types, and the base from
    // the descriptor; both must land on the same declaration.
    assert!(
        stdout.contains("class GenericBox<A> {"),
        "expected a recovered generic clause:\n{stdout}"
    );
}
