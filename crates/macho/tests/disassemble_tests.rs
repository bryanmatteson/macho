#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture_path(name: &str, bytes: &[u8]) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("macho-disassemble-{name}-{nonce}"));
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

fn strip_ansi(text: &str) -> String {
    let mut plain = String::new();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.next_if_eq(&'[').is_some() {
            for sequence_character in characters.by_ref() {
                if sequence_character == 'm' {
                    break;
                }
            }
        } else {
            plain.push(character);
        }
    }
    plain
}

/// Parse the disassemble NDJSON stream: one complete JSON object per non-empty
/// line, in emission order.
fn ndjson(stdout: &[u8]) -> Vec<serde_json::Value> {
    stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("each NDJSON line is one JSON object"))
        .collect()
}

/// Borrow every line whose `event` tag equals `event`, in emission order.
fn events<'a>(lines: &'a [serde_json::Value], event: &str) -> Vec<&'a serde_json::Value> {
    lines.iter().filter(|line| line["event"] == event).collect()
}

fn assert_json_error(path: &str, extra: &[&str], expected_code: &str, expected_exit: u8) {
    let mut args = vec!["disassemble", path];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--format", "json", "--color", "never"]);
    let result = macho::cli::run_captured(args);
    assert_eq!(
        result.code,
        expected_exit,
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(diagnostic["diagnostics"][0]["code"], expected_code);
}

#[test]
fn help_is_canonical_and_documents_defaults_and_examples() {
    let output = Command::new(env!("CARGO_BIN_EXE_macho"))
        .args(["disassemble", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        include_str!("goldens/disassemble-help.txt").as_bytes()
    );
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("Usage: macho disassemble [OPTIONS] <PATH>"));
    assert!(help.contains("[default: 67108864]"));
    assert!(help.contains("[default: 1000000]"));
    assert!(help.contains("SARIF output is supported only by the audit command."));
    assert!(help.contains("macho disassemble app --arch arm64e --symbol _main"));
    assert!(!help.contains("\n  disasm "));
}

#[test]
fn thin_x86_64_default_selection_has_text_and_gap_json_goldens() {
    let path = fixture_path(
        "thin-x86-default",
        &macho_test_support::disassembly_x86_64(),
    );
    let output =
        macho::cli::run_captured(["disassemble", path.to_str().unwrap(), "--color", "never"]);
    assert_eq!(
        output.code,
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        include_str!("goldens/disassemble-thin-x86-default.txt").as_bytes()
    );
    let json = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(json.code, 0, "{}", String::from_utf8_lossy(&json.stderr));
    assert!(json.stderr.is_empty());
    assert_eq!(
        json.stdout,
        include_str!("goldens/disassemble-thin-x86-default.json").as_bytes()
    );
    let lines = ndjson(&json.stdout);
    let gap = events(&lines, "record")
        .into_iter()
        .map(|line| &line["record"])
        .find(|record| record["record_type"] == "gap")
        .expect("recovering output must retain the invalid trailing byte as a gap");
    assert_eq!(gap["bytes"], "0f");
    assert_eq!(gap["code"], "insn.decode.invalid");
    assert_eq!(gap["message"], "decode: invalid instruction");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn empty_executable_selection_has_a_complete_machine_and_text_shape() {
    let path = fixture_path("empty", &macho_test_support::thin64_x86_64(2));
    let text =
        macho::cli::run_captured(["disassemble", path.to_str().unwrap(), "--color", "never"]);
    assert_eq!(text.code, 0);
    assert_eq!(text.stdout, b"No executable sections found.\n");
    let json = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    let lines = ndjson(&json.stdout);
    assert_eq!(json.code, 0);
    let slice_ends = events(&lines, "slice_end");
    assert_eq!(slice_ends.len(), 1);
    assert_eq!(slice_ends[0]["status"], "complete");
    // No executable sections means the slice carries no region and no record.
    assert!(events(&lines, "region").is_empty());
    assert!(events(&lines, "record").is_empty());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn command_parses_with_canonical_selectors_and_no_alias() {
    macho::cli::commands::parse_only(["macho", "disassemble", "fixture"]).unwrap();
    macho::cli::commands::parse_only([
        "macho",
        "disassemble",
        "fixture",
        "--section",
        "__TEXT,__text",
        "--section",
        "__TEXT,__stubs",
    ])
    .unwrap();
    assert!(macho::cli::commands::parse_only(["macho", "disasm", "fixture"]).is_err());
    assert!(
        macho::cli::commands::parse_only([
            "macho",
            "disassemble",
            "fixture",
            "--address",
            "1000",
            "--length",
            "4",
            "--count",
            "1",
        ])
        .is_err()
    );
    macho::cli::commands::parse_only([
        "macho",
        "disassemble",
        "fixture",
        "--address",
        "1000",
        "--end-address",
        "1010",
        "--no-addresses",
        "--no-bytes",
        "--no-labels",
        "--no-targets",
    ])
    .unwrap();
    assert!(
        macho::cli::commands::parse_only([
            "macho",
            "disassemble",
            "fixture",
            "--end-address",
            "1010",
        ])
        .is_err()
    );
    assert!(
        macho::cli::commands::parse_only([
            "macho",
            "disassemble",
            "fixture",
            "--address",
            "1000",
            "--end-address",
            "1010",
            "--length",
            "4",
        ])
        .is_err()
    );
    assert!(
        macho::cli::commands::parse_only([
            "macho",
            "disassemble",
            "fixture",
            "--address",
            "1000",
            "--end-address",
            "1010",
            "--count",
            "1",
        ])
        .is_err()
    );
}

#[test]
fn end_address_selects_the_same_bytes_as_length() {
    let path = fixture_path("end-address", &macho_test_support::disassembly_x86_64());
    let path_text = path.to_str().unwrap();
    let ranged = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--end-address",
        "0x100000104",
        "--color",
        "never",
    ]);
    assert_eq!(
        ranged.code,
        0,
        "{}",
        String::from_utf8_lossy(&ranged.stderr)
    );
    let length = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--length",
        "4",
        "--color",
        "never",
    ]);
    assert_eq!(length.code, 0);
    assert_eq!(ranged.stdout, length.stdout);

    let inverted = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000104",
        "--end-address",
        "100000104",
        "--color",
        "never",
    ]);
    assert_eq!(inverted.code, 2);
    assert!(inverted.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&inverted.stderr)
            .contains("--end-address must be greater than --address")
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn text_display_suppression_flags_remove_requested_columns_and_annotations() {
    let path = fixture_path("no-columns", &macho_test_support::disassembly_x86_64());
    let path_text = path.to_str().unwrap();
    let reduced = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--count",
        "2",
        "--no-addresses",
        "--no-bytes",
        "--color",
        "never",
    ]);
    assert_eq!(
        reduced.code,
        0,
        "{}",
        String::from_utf8_lossy(&reduced.stderr)
    );
    let reduced = String::from_utf8(reduced.stdout).unwrap();
    assert!(reduced.contains("_main:"));
    assert!(reduced.contains("\n  jmp 0x100000104  ; _helper\n"));
    assert!(reduced.contains("\n  nop\n"));
    // The region header keeps its extent; record lines drop both columns.
    assert!(reduced.lines().all(|line| !line.starts_with("  0x")));
    assert!(!reduced.contains("eb02"));

    let instruction_only = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--count",
        "2",
        "--no-labels",
        "--no-targets",
        "--color",
        "never",
    ]);
    assert_eq!(instruction_only.code, 0);
    let instruction_only = String::from_utf8(instruction_only.stdout).unwrap();
    assert!(!instruction_only.contains("_main:"));
    assert!(!instruction_only.contains("; _helper"));
    assert!(instruction_only.contains("jmp 0x100000104"));
    assert!(instruction_only.contains("nop"));
    std::fs::remove_file(path).unwrap();
}

#[test]
fn section_symbol_and_address_failures_keep_exact_codes_and_channels() {
    let x86_path = fixture_path("negative-x86", &macho_test_support::disassembly_x86_64());
    let x86 = x86_path.to_str().unwrap();

    let repeated = macho::cli::run_captured([
        "disassemble",
        x86,
        "--section",
        "__TEXT,__text",
        "--section",
        "__TEXT,__text",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(repeated.code, 0);
    let lines = ndjson(&repeated.stdout);
    assert_eq!(events(&lines, "region").len(), 1);

    let repeated_symbols = macho::cli::run_captured([
        "disassemble",
        x86,
        "--symbol",
        "_helper",
        "--symbol",
        "_main",
        "--symbol",
        "_main",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(repeated_symbols.code, 0);
    let lines = ndjson(&repeated_symbols.stdout);
    let header = events(&lines, "header");
    assert_eq!(
        header[0]["request"]["selection"]["names"],
        serde_json::json!(["_helper", "_main"])
    );
    assert_eq!(events(&lines, "region").len(), 2);

    assert_json_error(
        x86,
        &["--section", "__TEXT,__missing"],
        "analysis.disassembly.section.missing",
        1,
    );
    assert_json_error(
        x86,
        &["--symbol", "_missing"],
        "analysis.disassembly.symbol.missing",
        1,
    );
    assert_json_error(
        x86,
        &["--address", "100001000"],
        "analysis.disassembly.address.unmapped",
        1,
    );
    assert_json_error(
        x86,
        &["--address", "10000013f", "--length", "2"],
        "analysis.disassembly.address.cross_section",
        1,
    );

    let malformed = macho::cli::run_captured([
        "disassemble",
        x86,
        "--section",
        "__TEXT",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(malformed.code, 2);
    assert!(malformed.stdout.is_empty());

    let over_budget = macho::cli::run_captured([
        "disassemble",
        x86,
        "--symbol",
        "_main",
        "--symbol",
        "_helper",
        "--max-ranges",
        "1",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(over_budget.code, 2);
    assert!(over_budget.stdout.is_empty());

    let ambiguous_bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_same",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_same",
            external: true,
            defined: true,
        },
    ]);
    let ambiguous_path = fixture_path("ambiguous", &ambiguous_bytes);
    assert_json_error(
        ambiguous_path.to_str().unwrap(),
        &["--symbol", "_same"],
        "analysis.disassembly.symbol.ambiguous",
        1,
    );

    let data_bytes =
        macho_test_support::thin64_x86_64_with_data_symbols(&[macho_test_support::SymbolFixture {
            name: "_data",
            external: true,
            defined: true,
        }]);
    let data_path = fixture_path("data", &data_bytes);
    assert_json_error(
        data_path.to_str().unwrap(),
        &["--symbol", "_data"],
        "analysis.disassembly.symbol.non_code",
        1,
    );

    std::fs::remove_file(x86_path).unwrap();
    std::fs::remove_file(ambiguous_path).unwrap();
    std::fs::remove_file(data_path).unwrap();
}

#[test]
fn recovering_text_json_and_color_share_one_report() {
    let path = fixture_path("x86", &macho_test_support::disassembly_x86_64());
    let path_text = path.to_str().unwrap();
    let plain = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--count",
        "2",
        "--color",
        "never",
    ]);
    assert_eq!(plain.code, 0, "{}", String::from_utf8_lossy(&plain.stderr));
    assert!(plain.stderr.is_empty());
    assert_eq!(
        plain.stdout,
        include_str!("goldens/disassemble-address-count2.txt").as_bytes()
    );
    let colored = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--count",
        "2",
        "--color",
        "always",
    ]);
    assert_eq!(colored.code, 0);
    assert_eq!(
        strip_ansi(&String::from_utf8(colored.stdout).unwrap()),
        String::from_utf8(plain.stdout).unwrap()
    );

    let json = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--count",
        "2",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    let lines = ndjson(&json.stdout);
    // D1: the enveloped `{command, ok, data}` document is gone; success is a
    // zero exit with a clean stderr and a well-formed NDJSON stream whose header
    // carries the schema version the old `data.schema_version` asserted.
    assert_eq!(json.code, 0);
    assert!(json.stderr.is_empty());
    let header = events(&lines, "header");
    assert_eq!(header.len(), 1);
    assert_eq!(header[0]["schema_version"], 2);
    assert_eq!(events(&lines, "region")[0]["selection_source"], "address");
    assert_eq!(
        json.stdout,
        include_str!("goldens/disassemble-address-count2.json").as_bytes()
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn objc_boundary_parser_path_has_text_and_json_goldens() {
    let path = fixture_path(
        "objc-boundary",
        &macho_test_support::disassembly_objc_boundary(),
    );
    let text = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--symbol",
        "_main",
        "--color",
        "never",
    ]);
    let json = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--symbol",
        "_main",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(text.code, 0);
    assert_eq!(json.code, 0);
    assert_eq!(
        text.stdout,
        include_str!("goldens/disassemble-objc-boundary.txt").as_bytes()
    );
    assert_eq!(
        json.stdout,
        include_str!("goldens/disassemble-objc-boundary.json").as_bytes()
    );
    let lines = ndjson(&json.stdout);
    assert_eq!(events(&lines, "region")[0]["end_source"], "objc_metadata");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn strict_failure_streams_a_typed_prefix_in_both_io_routes() {
    let path = fixture_path("strict", &macho_test_support::disassembly_x86_64());
    let args = [
        "disassemble",
        path.to_str().unwrap(),
        "--strict",
        "--format",
        "json",
        "--color",
        "never",
    ];
    let captured = macho::cli::run_captured(args);
    assert_eq!(captured.code, 1);
    // D3: a stream cannot retract already-written lines, so the records decoded
    // before the invalid byte precede the typed error on stdout. The prefix is
    // well-formed NDJSON and, because strict aborts instead of recovering, it
    // never contains the invalid byte as a gap record.
    assert!(!captured.stdout.is_empty());
    let lines = ndjson(&captured.stdout);
    assert!(!events(&lines, "record").is_empty());
    assert!(
        !events(&lines, "record")
            .iter()
            .any(|line| line["record"]["record_type"] == "gap"),
        "strict mode must abort on the invalid byte, not emit it as a gap"
    );
    let diagnostic: serde_json::Value = serde_json::from_slice(&captured.stderr).unwrap();
    assert_eq!(diagnostic["diagnostics"][0]["code"], "insn.decode.invalid");

    let process = Command::new(env!("CARGO_BIN_EXE_macho"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(process.status.code(), Some(captured.code as i32));
    assert_eq!(process.stdout, captured.stdout);
    assert_eq!(process.stderr, captured.stderr);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn disassembly_output_policy_is_centralized() {
    let path = fixture_path("policy", &macho_test_support::disassembly_arm64());
    let sarif = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--format",
        "sarif",
        "--color",
        "never",
    ]);
    assert_eq!(sarif.code, 2);
    assert!(sarif.stdout.is_empty());
    assert_eq!(
        String::from_utf8(sarif.stderr).unwrap(),
        "Error: SARIF output is supported only by the audit command\n"
    );

    let color = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--format",
        "json",
        "--color",
        "always",
    ]);
    assert_eq!(color.code, 2);
    assert!(color.stdout.is_empty());
    let diagnostic: serde_json::Value = serde_json::from_slice(&color.stderr).unwrap();
    assert_eq!(
        diagnostic["diagnostics"][0]["code"],
        "cli.usage.color_machine"
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn fat_requires_arch_for_addresses_and_raw_tuple_selects_exactly() {
    let path = fixture_path("fat", &macho_test_support::disassembly_fat());
    let without_arch = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--address",
        "100000100",
    ]);
    assert_eq!(without_arch.code, 2);
    assert!(without_arch.stdout.is_empty());

    let selected = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--arch",
        "0x0100000c:0x00000002",
        "--address",
        "100000100",
        "--count",
        "1",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(
        selected.code,
        0,
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let lines = ndjson(&selected.stdout);
    let slices = events(&lines, "slice");
    assert_eq!(slices.len(), 1);
    assert_eq!(
        slices[0]["identity"]["image"]["architecture"]["cpu_subtype"],
        2
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn fat_all_slice_json_order_offsets_and_process_route_are_stable() {
    let path = fixture_path("fat-all", &macho_test_support::disassembly_fat());
    let args = [
        "disassemble",
        path.to_str().unwrap(),
        "--max-decoded-bytes",
        "4",
        "--format",
        "json",
        "--color",
        "never",
    ];
    let captured = macho::cli::run_captured(args);
    assert_eq!(
        captured.code,
        0,
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    let lines = ndjson(&captured.stdout);
    assert_eq!(
        captured.stdout,
        include_str!("goldens/disassemble-fat-all.json").as_bytes()
    );
    let slices = events(&lines, "slice");
    assert_eq!(slices.len(), 2);
    assert_eq!(
        slices[0]["identity"]["image"]["architecture"]["cpu_type"],
        0x0100_0007
    );
    assert_eq!(
        slices[1]["identity"]["image"]["architecture"]["cpu_type"],
        0x0100_000c
    );
    // Walk the ordered stream: every record's container_file_offset equals its
    // owning slice's container_offset plus its thin_file_offset.
    let mut container_offset: Option<u64> = None;
    let mut records_checked = 0usize;
    for line in &lines {
        match line["event"].as_str().unwrap() {
            "slice" => container_offset = Some(line["container_offset"].as_u64().unwrap()),
            "record" => {
                let base = container_offset.expect("a slice precedes every record");
                let record = &line["record"];
                assert_eq!(
                    record["container_file_offset"].as_u64().unwrap(),
                    base + record["thin_file_offset"].as_u64().unwrap()
                );
                records_checked += 1;
            }
            _ => {}
        }
    }
    assert!(
        records_checked >= slices.len(),
        "both slices must contribute at least one checked record"
    );
    let process = Command::new(env!("CARGO_BIN_EXE_macho"))
        .args(args)
        .output()
        .unwrap();
    assert_eq!(process.status.code(), Some(0));
    assert_eq!(process.stdout, captured.stdout);
    assert_eq!(process.stderr, captured.stderr);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn family_architecture_selection_retains_colliding_subtypes_and_raw_selection_is_exact() {
    let collision_path = fixture_path(
        "arch-collision",
        &macho_test_support::disassembly_fat_x86_subtypes(),
    );
    let collision = collision_path.to_str().unwrap();
    let family = macho::cli::run_captured([
        "disassemble",
        collision,
        "--arch",
        "x86_64",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(family.code, 0);
    let family = ndjson(&family.stdout);
    assert_eq!(
        events(&family, "slice")
            .iter()
            .map(|slice| {
                slice["identity"]["image"]["architecture"]["cpu_subtype"]
                    .as_i64()
                    .unwrap()
            })
            .collect::<Vec<_>>(),
        [3, 8],
        "the CPU-family selector must retain both subtype slices"
    );

    let selected = macho::cli::run_captured([
        "disassemble",
        collision,
        "--arch",
        "0x01000007:0x00000008",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(selected.code, 0);
    let lines = ndjson(&selected.stdout);
    assert_eq!(
        events(&lines, "slice")[0]["identity"]["image"]["architecture"]["cpu_subtype"],
        8
    );

    let malformed_tuple = macho::cli::run_captured([
        "disassemble",
        collision,
        "--arch",
        "0x1:0x2",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert_eq!(malformed_tuple.code, 2);
    assert!(malformed_tuple.stdout.is_empty());

    let mixed = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_X86_64,
            3,
            macho_test_support::disassembly_x86_64(),
        ),
        (
            macho_test_support::CPU_TYPE_UNKNOWN_64,
            0,
            macho_test_support::thin64_unknown_cpu(2),
        ),
    ]);
    let mixed_path = fixture_path("mixed-unsupported", &mixed);
    assert_json_error(
        mixed_path.to_str().unwrap(),
        &[],
        "analysis.disassembly.arch.unsupported",
        1,
    );

    std::fs::remove_file(collision_path).unwrap();
    std::fs::remove_file(mixed_path).unwrap();
}

#[test]
fn text_reserves_the_full_x86_instruction_byte_column() {
    let path = fixture_path("x86-columns", &macho_test_support::disassembly_x86_64());
    let result = macho::cli::run_captured([
        "disassemble",
        path.to_str().unwrap(),
        "--address",
        "100000100",
        "--count",
        "2",
        "--color",
        "never",
    ]);
    assert_eq!(result.code, 0);
    let text = String::from_utf8(result.stdout).unwrap();
    let rows = text
        .lines()
        .filter(|line| line.trim_start().starts_with("0x"))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    let instruction_columns = rows
        .iter()
        .map(|line| line.find("jmp").or_else(|| line.find("nop")).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(instruction_columns[0], instruction_columns[1]);
    assert!(instruction_columns[0] >= 2 + 18 + 2 + 30 + 2);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn captured_and_process_routes_match_core_disassembly_cases() {
    let path = fixture_path("parity", &macho_test_support::disassembly_x86_64());
    let path = path.to_str().unwrap().to_owned();
    let cases = vec![
        vec![
            "disassemble".to_owned(),
            path.clone(),
            "--address".to_owned(),
            "100000100".to_owned(),
            "--count".to_owned(),
            "1".to_owned(),
            "--color".to_owned(),
            "never".to_owned(),
        ],
        vec![
            "disassemble".to_owned(),
            path.clone(),
            "--symbol".to_owned(),
            "_main".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--color".to_owned(),
            "never".to_owned(),
        ],
        vec![
            "disassemble".to_owned(),
            path.clone(),
            "--count".to_owned(),
            "0".to_owned(),
        ],
        vec![
            "disassemble".to_owned(),
            path.clone(),
            "--strict".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--color".to_owned(),
            "never".to_owned(),
        ],
        vec![
            "disassemble".to_owned(),
            path.clone(),
            "--max-decoded-bytes".to_owned(),
            "4".to_owned(),
            "--format".to_owned(),
            "json".to_owned(),
            "--color".to_owned(),
            "never".to_owned(),
        ],
    ];
    for args in cases {
        let captured = macho::cli::run_captured(args.clone());
        let process = Command::new(env!("CARGO_BIN_EXE_macho"))
            .args(args.iter())
            .output()
            .unwrap();
        assert_eq!(
            process.status.code(),
            Some(captured.code as i32),
            "{args:?}"
        );
        assert_eq!(process.stdout, captured.stdout, "{args:?}");
        assert_eq!(process.stderr, captured.stderr, "{args:?}");
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn colored_disassembly_styles_tokens_without_changing_plain_text() {
    let path = fixture_path("colorized", &macho_test_support::disassembly_x86_64());
    let path_text = path.to_str().unwrap();
    let plain = macho::cli::run_captured(["disassemble", path_text, "--color", "never"]);
    let colored = macho::cli::run_captured(["disassemble", path_text, "--color", "always"]);
    assert_eq!(plain.code, 0, "{}", String::from_utf8_lossy(&plain.stderr));
    assert_eq!(colored.code, 0);

    // Colour is presentation only: the styled stream must carry ANSI, and
    // stripping it must reproduce the plain stream byte for byte.
    assert!(colored.stdout.contains(&0x1b));
    assert!(!plain.stdout.contains(&0x1b));
    let plain_text = String::from_utf8(plain.stdout).expect("UTF-8 plain output");
    let colored_text = String::from_utf8(colored.stdout).expect("UTF-8 colored output");
    assert_eq!(strip_ansi(&colored_text), plain_text);

    // The mnemonic, the raw-byte column, and the branch comment each carry
    // their own styling rather than inheriting one line-wide colour.
    let record = colored_text
        .lines()
        .find(|line| strip_ansi(line).contains("jmp 0x"))
        .expect("a branch record");
    assert!(record.contains("\u{1b}[1;34mjmp\u{1b}[0m"), "{record:?}");
    assert!(record.contains("\u{1b}[2meb02\u{1b}[0m"), "{record:?}");
    assert!(
        record.contains("\u{1b}[32m; _helper\u{1b}[0m"),
        "{record:?}"
    );

    // The invalid trailing byte keeps its diagnostic styling.
    let gap = colored_text
        .lines()
        .find(|line| strip_ansi(line).contains("insn.decode.invalid"))
        .expect("a gap record");
    assert!(
        gap.contains("\u{1b}[1;33m<insn.decode.invalid>\u{1b}[0m"),
        "{gap:?}"
    );

    std::fs::remove_file(path).unwrap();
}

#[test]
fn colored_and_plain_records_keep_the_same_instruction_column() {
    let path = fixture_path(
        "colorized-columns",
        &macho_test_support::disassembly_x86_64(),
    );
    let path_text = path.to_str().unwrap();
    let colored = macho::cli::run_captured([
        "disassemble",
        path_text,
        "--address",
        "100000100",
        "--count",
        "2",
        "--color",
        "always",
    ]);
    assert_eq!(colored.code, 0);
    let colored_text = String::from_utf8(colored.stdout).expect("UTF-8 colored output");

    // Styling the byte column must not disturb alignment: padding is computed
    // from the unstyled width, so every stripped record shares one column.
    let columns = colored_text
        .lines()
        .map(strip_ansi)
        .filter(|line| line.trim_start().starts_with("0x"))
        .map(|line| {
            line.find("jmp")
                .or_else(|| line.find("nop"))
                .expect("an instruction column")
        })
        .collect::<Vec<_>>();
    assert_eq!(columns.len(), 2);
    assert_eq!(columns[0], columns[1]);

    std::fs::remove_file(path).unwrap();
}
