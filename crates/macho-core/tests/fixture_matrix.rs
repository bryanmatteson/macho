use macho_core::{ParseErrorKind, ParseLimits, ParseMode, ParseOptions};
use macho_test_support::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};

fn forensic_with(mut limits: ParseLimits, bytes: &[u8]) -> Result<(), macho_core::ParseError> {
    limits.max_sections = limits.max_sections.max(1);
    macho_core::parse_with_options(
        bytes,
        &ParseOptions {
            mode: ParseMode::Forensic,
            limits,
        },
    )
    .map(|_| ())
}

fn parse_error(bytes: &[u8]) -> macho_core::ParseError {
    match macho_core::parse(bytes) {
        Ok(_) => panic!("fixture unexpectedly parsed"),
        Err(error) => error,
    }
}

#[test]
fn thin_and_multi_arch_fat_fixtures_parse() {
    let arm = macho_test_support::thin64_arm64(2);
    let x86 = macho_test_support::thin64_x86_64(2);
    macho_core::parse(&arm).expect("valid thin fixture");
    let fat = macho_test_support::fat32(&[(CPU_TYPE_ARM64, 0, arm), (CPU_TYPE_X86_64, 0, x86)]);
    let parsed = macho_core::parse(&fat).expect("valid multi-arch fixture");
    assert_eq!(parsed.macho_files().count(), 2);
}

#[test]
fn invalid_fat_fixture_matrix_is_typed() {
    for (name, bytes, kind) in [
        (
            "zero architecture",
            macho_test_support::zero_arch_fat(),
            ParseErrorKind::InvalidFormat,
        ),
        (
            "overlapping slices",
            macho_test_support::overlapping_fat_slices(),
            ParseErrorKind::InvalidFormat,
        ),
        (
            "truncated slice",
            macho_test_support::truncated_fat_slice(),
            ParseErrorKind::InvalidFormat,
        ),
    ] {
        let error = parse_error(&bytes);
        assert_eq!(error.kind, kind, "{name}");
    }
}

#[test]
fn fat_and_load_command_limits_fail_before_input_derived_allocation() {
    let fat = macho_test_support::fat32(&[
        (CPU_TYPE_ARM64, 0, macho_test_support::thin64_arm64(2)),
        (CPU_TYPE_X86_64, 0, macho_test_support::thin64_x86_64(2)),
    ]);
    let error = forensic_with(
        ParseLimits {
            max_fat_arches: 1,
            ..ParseLimits::default()
        },
        &fat,
    )
    .expect_err("fat architecture limit");
    assert_eq!(error.kind, ParseErrorKind::LimitExceeded);

    let command = macho_test_support::unknown_load_command_image();
    let error = forensic_with(
        ParseLimits {
            max_load_commands: 0,
            ..ParseLimits::default()
        },
        &command,
    )
    .expect_err("load-command limit");
    assert_eq!(error.kind, ParseErrorKind::LimitExceeded);
}

#[test]
fn known_unknown_truncated_and_impossible_load_commands_are_distinct() {
    let known = macho_test_support::thin64_x86_64_with_symbols(&[]);
    macho_core::parse(&known).expect("bounded known load commands");

    let unknown_bytes = macho_test_support::unknown_load_command_image();
    let unknown = macho_core::parse(&unknown_bytes).expect("bounded unknown command is preserved");
    assert_eq!(
        unknown
            .first_macho()
            .expect("thin image")
            .load_commands()
            .len(),
        1
    );

    for bytes in [
        macho_test_support::truncated_load_command_image(),
        macho_test_support::invalid_cmdsize_image(),
    ] {
        let error = parse_error(&bytes);
        assert_eq!(error.kind, ParseErrorKind::InvalidLoadCommand);
        assert!(matches!(
            error.context.last(),
            Some(macho_core::ContextFrame::LoadCommand { index: 0 })
        ));
    }
}

#[test]
fn invalid_fileset_entries_are_rejected() {
    macho_core::parse(&macho_test_support::fileset64_arm64()).expect("valid fileset");
    for bytes in [
        macho_test_support::fileset64_truncated_command(),
        macho_test_support::fileset64_out_of_bounds(),
    ] {
        assert!(macho_core::parse(&bytes).is_err());
    }
}
