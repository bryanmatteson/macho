use macho_cli::adapters::{XcrunSdkLocator, XcrunSwiftDemangler};
use macho_cli::header_infer::{CapabilityError, HeaderLanguage, SdkLocator};
use macho_cli::swift::{SwiftDemangler, SwiftError};

#[derive(Debug)]
struct FakeDemangler {
    response: Option<String>,
}

impl SwiftDemangler for FakeDemangler {
    fn demangle(&self, _symbol: &str) -> Result<Option<String>, SwiftError> {
        Ok(self.response.clone())
    }
}

#[test]
fn fake_demangler_returns_deterministic_tool_response() {
    let adapter = FakeDemangler {
        response: Some("Demo.Widget".into()),
    };
    assert_eq!(
        adapter.demangle("$s4Demo6WidgetC").expect("fake works"),
        Some("Demo.Widget".into())
    );
}

#[test]
fn unavailable_and_malformed_capabilities_remain_typed() {
    let unavailable = CapabilityError::Unavailable {
        capability: "fake compiler",
    };
    let malformed = CapabilityError::Malformed {
        capability: "fake compiler",
        detail: "invalid response".into(),
    };
    assert!(matches!(unavailable, CapabilityError::Unavailable { .. }));
    assert!(matches!(malformed, CapabilityError::Malformed { .. }));
}

#[test]
#[ignore = "requires the macOS developer toolchain"]
fn real_xcrun_sdk_locator_smoke() {
    let roots = XcrunSdkLocator
        .include_roots(HeaderLanguage::C)
        .expect("xcrun SDK is available");
    assert!(!roots.is_empty());
}

#[test]
#[ignore = "requires the macOS Swift toolchain"]
fn real_xcrun_swift_demangler_smoke() {
    let result = XcrunSwiftDemangler
        .demangle("$s4Demo6WidgetC")
        .expect("swift-demangle is available");
    assert!(result.is_some());
}
