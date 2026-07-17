use macho_core::format::{ParseMode, ParseOptions};
use macho_core::{ContextFrame, ParseErrorKind};

#[test]
fn forensic_mode_retains_safe_validation_diagnostics() {
    let warning = macho_test_support::warning_bearing_image();
    let strict = macho_core::parse(&warning).expect("warnings do not reject strict parsing");
    assert!(strict.first_macho().is_some());
    let outcome = macho_core::parse_with_options(
        &warning,
        &ParseOptions {
            mode: ParseMode::Forensic,
            ..ParseOptions::default()
        },
    )
    .expect("forensic warning image");
    assert!(
        outcome
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code.0 == "parse.validation.protection_mismatch" })
    );

    let recoverable_error = macho_test_support::validation_error_image();
    let strict_error = macho_core::parse(&recoverable_error).expect_err("strict validation fails");
    assert_eq!(strict_error.kind, ParseErrorKind::Validation);
    let forensic = macho_core::parse_with_options(
        &recoverable_error,
        &ParseOptions {
            mode: ParseMode::Forensic,
            ..ParseOptions::default()
        },
    )
    .expect("forensic mode retains representable model");
    assert!(
        forensic
            .diagnostics
            .iter()
            .any(|diagnostic| { diagnostic.code.0 == "parse.validation.segment_bounds" })
    );
}

#[test]
fn hard_bounds_fail_in_both_modes_with_command_context() {
    let bytes = macho_test_support::truncated_load_command_image();
    for mode in [ParseMode::Strict, ParseMode::Forensic] {
        let error = match macho_core::parse_with_options(
            &bytes,
            &ParseOptions {
                mode,
                ..ParseOptions::default()
            },
        ) {
            Ok(_) => panic!("truncated command is always a hard failure"),
            Err(error) => error,
        };
        assert_eq!(error.kind, ParseErrorKind::InvalidLoadCommand);
        assert_eq!(error.code(), "parse.load_command.invalid");
        assert_eq!(error.location.expect("command span").offset, 32);
        assert!(matches!(
            error.context.as_slice(),
            [ContextFrame::LoadCommand { index: 0 }]
        ));
    }
}

#[test]
fn nested_fat_error_preserves_slice_command_and_span() {
    let thin = macho_test_support::truncated_load_command_image();
    let fat = macho_test_support::fat32(&[(macho_test_support::CPU_TYPE_X86_64, 3, thin)]);
    let error = macho_core::parse(&fat).expect_err("nested command is malformed");
    assert_eq!(error.code(), "parse.load_command.invalid");
    assert_eq!(error.location.expect("nested command span").offset, 32);
    assert!(matches!(
        error.context.as_slice(),
        [
            ContextFrame::LoadCommand { index: 0 },
            ContextFrame::FatArchitecture { index: 0 }
        ]
    ));
}

#[test]
fn unknown_load_command_is_bounded_and_preserved() {
    let bytes = macho_test_support::unknown_load_command_image();
    let container = macho_core::parse(&bytes).expect("unknown command is structurally valid");
    let macho = container.first_macho().expect("one image");
    assert!(matches!(
        macho.load_commands()[0].kind(),
        macho_core::model::load_command::LoadCommand::Unknown(command)
            if command.cmd == 0x1234_5678
    ));
}
