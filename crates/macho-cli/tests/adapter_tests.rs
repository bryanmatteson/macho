use macho_cli::header_infer::{
    HeaderLanguage, HeaderValidator, InProcessHeaderValidator, ValidationError, ValidationRequest,
};
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
fn in_process_validation_failures_remain_typed() {
    let error = ValidationError::Parse("invalid declaration".into());
    assert!(matches!(error, ValidationError::Parse(_)));
}

#[test]
fn in_process_header_validator_needs_no_sdk_or_host_process() {
    let outcome = InProcessHeaderValidator
        .validate(&ValidationRequest {
            language: HeaderLanguage::C,
            source: "int answer(void);",
        })
        .expect("validator is always locally available");
    assert!(outcome.accepted, "{:?}", outcome.diagnostics);
}
