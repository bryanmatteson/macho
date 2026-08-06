#![cfg(feature = "cli")]

//! The Objective-C and Swift reports must survive their own JSON.
//!
//! Both schemas use `deny_unknown_fields`, so every field the recovery emits has
//! to be one the schema also accepts. These tests run the CLI exactly as a user
//! would and feed the emitted bytes straight back into the typed report, which
//! is the only check that covers the wire surface end to end.

mod support;

#[cfg(target_os = "macos")]
use support::{copy_macho_fixture, run_cli};

/// A binary carrying both Objective-C and Swift metadata.
#[cfg(target_os = "macos")]
const FIXTURE_SOURCE: &str = "/usr/bin/plutil";

#[cfg(target_os = "macos")]
fn report_payload(command: &str, extra: &[&str]) -> serde_json::Value {
    let fixture = copy_macho_fixture(FIXTURE_SOURCE, &format!("{command}-wire"));
    let path = fixture.path().to_str().expect("utf8 path");
    let mut args = vec![command, path, "--format", "json"];
    args.extend_from_slice(extra);

    let output = run_cli(args);
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("CLI emits JSON");
    assert_eq!(envelope["ok"], serde_json::Value::Bool(true));
    envelope["data"].clone()
}

#[test]
#[cfg(target_os = "macos")]
fn objc_report_survives_its_own_json() {
    let payload = report_payload("objc", &[]);
    let report: macho::analysis::report::ObjCReport =
        serde_json::from_value(payload.clone()).expect("objc report deserializes");
    let reserialized = serde_json::to_value(&report).expect("objc report serializes");
    assert_eq!(
        reserialized, payload,
        "objc report is not stable across JSON"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn objc_header_projection_survives_its_own_json() {
    // `--headers` is the path that populates the projection, so it exercises
    // fields the plain surface never emits.
    let payload = report_payload("objc", &["--arch", "x86_64", "--headers"]);
    let report: macho::analysis::report::ObjCReport =
        serde_json::from_value(payload.clone()).expect("projected objc report deserializes");
    assert!(
        report
            .slices
            .as_slice()
            .iter()
            .all(|slice| slice.header.is_some()),
        "every projected slice carries a header"
    );
    let reserialized = serde_json::to_value(&report).expect("projected objc report serializes");
    assert_eq!(reserialized, payload);
}

#[test]
#[cfg(target_os = "macos")]
fn swift_report_survives_its_own_json() {
    let payload = report_payload("swift", &[]);
    let report: macho::analysis::report::SwiftReport =
        serde_json::from_value(payload.clone()).expect("swift report deserializes");
    let reserialized = serde_json::to_value(&report).expect("swift report serializes");
    assert_eq!(
        reserialized, payload,
        "swift report is not stable across JSON"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn swift_header_projection_survives_its_own_json() {
    let payload = report_payload("swift", &["--arch", "x86_64", "--headers"]);
    let report: macho::analysis::report::SwiftReport =
        serde_json::from_value(payload.clone()).expect("projected swift report deserializes");
    assert!(
        report
            .slices
            .as_slice()
            .iter()
            .all(|slice| slice.header.is_some()),
        "every projected slice carries a header"
    );
    let reserialized = serde_json::to_value(&report).expect("projected swift report serializes");
    assert_eq!(reserialized, payload);
}
