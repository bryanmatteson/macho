use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

fn run_process(args: &[OsString]) -> (u8, Vec<u8>, Vec<u8>) {
    let output = Command::new(env!("CARGO_BIN_EXE_macho"))
        .args(args)
        .output()
        .expect("run production binary");
    (
        output.status.code().expect("ordinary exit") as u8,
        output.stdout,
        output.stderr,
    )
}

fn assert_process_matches_injected(args: Vec<OsString>) -> macho_cli::CapturedRun {
    let process = run_process(&args);
    let injected = macho_cli::run_captured(args.clone());
    assert_eq!(process.0, injected.code, "status differs for {args:?}");
    assert_eq!(process.1, injected.stdout, "stdout differs for {args:?}");
    assert_eq!(process.2, injected.stderr, "stderr differs for {args:?}");
    injected
}

fn fixture_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("macho-io-parity-{}-{name}", std::process::id()))
}

#[test]
fn production_and_injected_io_are_byte_identical() {
    let old = fixture_path("old");
    let new = fixture_path("new");
    let invalid = fixture_path("invalid");
    std::fs::write(&old, macho_test_support::thin64_arm64(2)).expect("write old fixture");
    std::fs::write(&new, macho_test_support::thin64_arm64(6)).expect("write new fixture");
    std::fs::write(&invalid, [0xcf, 0xfa, 0xed]).expect("write invalid fixture");

    for args in [
        vec![OsString::from("info"), old.clone().into_os_string()],
        vec![
            OsString::from("snapshot"),
            OsString::from("--format"),
            OsString::from("json"),
            old.clone().into_os_string(),
        ],
        vec![
            OsString::from("audit"),
            OsString::from("--format"),
            OsString::from("sarif"),
            old.clone().into_os_string(),
        ],
        vec![
            OsString::from("--format"),
            OsString::from("json"),
            OsString::from("not-a-command"),
        ],
    ] {
        assert_process_matches_injected(args);
    }

    let policy = assert_process_matches_injected(vec![
        OsString::from("diff"),
        OsString::from("--format"),
        OsString::from("json"),
        old.clone().into_os_string(),
        new.clone().into_os_string(),
        OsString::from("--fail-on"),
        OsString::from("info"),
    ]);
    assert_eq!(policy.code, 3);
    assert!(!policy.stdout.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&policy.stdout).expect("report envelope");
    assert_eq!(report["ok"], true);
    let diagnostic: serde_json::Value =
        serde_json::from_slice(&policy.stderr).expect("policy diagnostic envelope");
    assert_eq!(diagnostic["ok"], false);
    assert_eq!(diagnostic["diagnostics"][0]["code"], "cli.policy.threshold");

    let parse_failure = assert_process_matches_injected(vec![
        OsString::from("info"),
        OsString::from("--format"),
        OsString::from("json"),
        invalid.clone().into_os_string(),
    ]);
    assert_eq!(parse_failure.code, 1);
    assert!(parse_failure.stdout.is_empty());
    let parse_diagnostic: serde_json::Value =
        serde_json::from_slice(&parse_failure.stderr).expect("parse diagnostic envelope");
    assert_eq!(parse_diagnostic["ok"], false);
    assert_eq!(
        parse_diagnostic["diagnostics"][0]["code"],
        "cli.input.failed"
    );

    let missing = fixture_path("missing");
    let _ = std::fs::remove_file(&missing);
    let missing_failure = assert_process_matches_injected(vec![
        OsString::from("info"),
        OsString::from("--format"),
        OsString::from("json"),
        missing.into_os_string(),
    ]);
    assert_eq!(missing_failure.code, 1);
    assert!(missing_failure.stdout.is_empty());
    let missing_diagnostic: serde_json::Value =
        serde_json::from_slice(&missing_failure.stderr).expect("missing-input envelope");
    assert_eq!(
        missing_diagnostic["diagnostics"][0]["code"],
        "cli.input.failed"
    );

    let selection_failure = assert_process_matches_injected(vec![
        OsString::from("info"),
        OsString::from("--format"),
        OsString::from("json"),
        old.clone().into_os_string(),
        OsString::from("--arch"),
        OsString::from("x86_64"),
    ]);
    assert_eq!(selection_failure.code, 1);
    assert!(selection_failure.stdout.is_empty());
    let selection_diagnostic: serde_json::Value =
        serde_json::from_slice(&selection_failure.stderr).expect("selection envelope");
    assert_eq!(
        selection_diagnostic["diagnostics"][0]["code"],
        "cli.input.failed"
    );

    let semantic_usage = assert_process_matches_injected(vec![
        OsString::from("patch"),
        OsString::from("--format"),
        OsString::from("json"),
        old.clone().into_os_string(),
        OsString::from("--dry-run"),
    ]);
    assert_eq!(semantic_usage.code, 2);
    assert!(semantic_usage.stdout.is_empty());
    let usage_diagnostic: serde_json::Value =
        serde_json::from_slice(&semantic_usage.stderr).expect("usage envelope");
    assert_eq!(
        usage_diagnostic["diagnostics"][0]["code"],
        "cli.usage.invalid_arguments"
    );

    let unwritable_output = fixture_path("unwritable-output");
    std::fs::create_dir_all(&unwritable_output).expect("create directory output obstacle");
    let output_failure = assert_process_matches_injected(vec![
        OsString::from("patch"),
        OsString::from("--format"),
        OsString::from("json"),
        old.clone().into_os_string(),
        OsString::from("--bytes"),
        OsString::from("0x1c:01000000"),
        OsString::from("--output"),
        unwritable_output.clone().into_os_string(),
    ]);
    assert_eq!(output_failure.code, 1);
    assert!(output_failure.stdout.is_empty());
    let output_diagnostic: serde_json::Value =
        serde_json::from_slice(&output_failure.stderr).expect("output failure envelope");
    assert_eq!(
        output_diagnostic["diagnostics"][0]["code"],
        "cli.execution.failed"
    );
    assert!(unwritable_output.is_dir());

    let output = fixture_path("written");
    let patch_args = vec![
        OsString::from("patch"),
        OsString::from("--format"),
        OsString::from("json"),
        old.clone().into_os_string(),
        OsString::from("--bytes"),
        OsString::from("0x1c:01000000"),
        OsString::from("--output"),
        output.clone().into_os_string(),
    ];
    let process = run_process(&patch_args);
    let process_file = std::fs::read(&output).expect("process file output");
    std::fs::remove_file(&output).expect("reset output path");
    let injected = macho_cli::run_captured(patch_args);
    let injected_file = std::fs::read(&output).expect("injected file output");
    assert_eq!(process.0, injected.code);
    assert_eq!(process.1, injected.stdout);
    assert_eq!(process.2, injected.stderr);
    assert_eq!(process_file, injected_file);
    serde_json::from_slice::<serde_json::Value>(&injected.stdout)
        .expect("file-output report envelope");

    let _ = std::fs::remove_file(old);
    let _ = std::fs::remove_file(new);
    let _ = std::fs::remove_file(invalid);
    let _ = std::fs::remove_file(output);
    let _ = std::fs::remove_dir(unwritable_output);
}
