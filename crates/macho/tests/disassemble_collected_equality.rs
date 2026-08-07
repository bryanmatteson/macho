#![cfg(feature = "cli")]

//! The NDJSON contract is an instruction projection, not a serialized
//! `DisassemblyReport`. Every output line must correspond one-for-one with a
//! decoded instruction from the materialized API; report framing and recovery
//! gaps are intentionally absent.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::cli::analysis::disassembly::{
    AddressExtent, DecodeMode, DisassemblyRequest, DisassemblySelection, NonEmpty, SectionSelector,
    SliceSelection, disassemble,
};
use macho::cli::analysis::report::Architecture;
use macho::cli::analysis::report::disassembly::DisassemblyRecord;
use macho::cli::model::addr::Va;

fn fixture_path(name: &str, bytes: &[u8]) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("macho-instruction-stream-{name}-{nonce}"));
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

fn default_max_decoded_bytes() -> NonZeroUsize {
    NonZeroUsize::new(67_108_864).unwrap()
}

fn default_max_ranges() -> NonZeroUsize {
    NonZeroUsize::new(1_000_000).unwrap()
}

fn symbols(names: &[&str]) -> DisassemblySelection {
    DisassemblySelection::Symbols(
        NonEmpty::try_from_vec(names.iter().map(|name| (*name).to_owned()).collect()).unwrap(),
    )
}

fn sections(pairs: &[(&str, &str)]) -> DisassemblySelection {
    DisassemblySelection::Sections(
        NonEmpty::try_from_vec(
            pairs
                .iter()
                .map(|(segment, section)| SectionSelector::new(*segment, *section).unwrap())
                .collect(),
        )
        .unwrap(),
    )
}

struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    extra_args: Vec<&'static str>,
    request: DisassemblyRequest,
}

fn cases() -> Vec<Case> {
    let request = |arches, selection, max_decoded: NonZeroUsize| {
        DisassemblyRequest::new(
            arches,
            selection,
            DecodeMode::Recovering,
            false,
            max_decoded,
            default_max_ranges(),
        )
        .unwrap()
    };
    vec![
        Case {
            name: "x86-default",
            bytes: macho_test_support::disassembly_x86_64(),
            extra_args: vec![],
            request: request(
                SliceSelection::All,
                DisassemblySelection::ExecutableSections,
                default_max_decoded_bytes(),
            ),
        },
        Case {
            name: "x86-address-count",
            bytes: macho_test_support::disassembly_x86_64(),
            extra_args: vec!["--address", "100000100", "--count", "2"],
            request: request(
                SliceSelection::All,
                DisassemblySelection::Address {
                    start: Va(0x1_0000_0100),
                    extent: AddressExtent::InstructionCount(NonZeroUsize::new(2).unwrap()),
                },
                default_max_decoded_bytes(),
            ),
        },
        Case {
            name: "x86-section",
            bytes: macho_test_support::disassembly_x86_64(),
            extra_args: vec!["--section", "__TEXT,__text"],
            request: request(
                SliceSelection::All,
                sections(&[("__TEXT", "__text")]),
                default_max_decoded_bytes(),
            ),
        },
        Case {
            name: "objc-symbol",
            bytes: macho_test_support::disassembly_objc_boundary(),
            extra_args: vec!["--symbol", "_main"],
            request: request(
                SliceSelection::All,
                symbols(&["_main"]),
                default_max_decoded_bytes(),
            ),
        },
        Case {
            name: "arm64-default",
            bytes: macho_test_support::disassembly_arm64(),
            extra_args: vec![],
            request: request(
                SliceSelection::All,
                DisassemblySelection::ExecutableSections,
                default_max_decoded_bytes(),
            ),
        },
        Case {
            name: "fat-all-truncated",
            bytes: macho_test_support::disassembly_fat(),
            extra_args: vec!["--max-decoded-bytes", "4"],
            request: request(
                SliceSelection::All,
                DisassemblySelection::ExecutableSections,
                NonZeroUsize::new(4).unwrap(),
            ),
        },
        Case {
            name: "fat-arch-address",
            bytes: macho_test_support::disassembly_fat(),
            extra_args: vec![
                "--arch",
                "0x0100000c:0x00000002",
                "--address",
                "100000100",
                "--count",
                "1",
            ],
            request: request(
                SliceSelection::One {
                    architecture: Architecture {
                        cpu_type: 0x0100_000c,
                        cpu_subtype: 2,
                    },
                },
                DisassemblySelection::Address {
                    start: Va(0x1_0000_0100),
                    extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
                },
                default_max_decoded_bytes(),
            ),
        },
    ]
}

#[test]
fn ndjson_stream_is_a_one_line_per_instruction_projection() {
    for case in cases() {
        let path = fixture_path(case.name, &case.bytes);
        let mut args = vec!["disassemble".to_owned(), path.to_str().unwrap().to_owned()];
        args.extend(case.extra_args.iter().map(|arg| (*arg).to_owned()));
        args.extend(
            ["--format", "json", "--color", "never"]
                .iter()
                .map(|arg| (*arg).to_owned()),
        );
        let output = macho::cli::run_captured(args);
        assert_eq!(
            output.code,
            0,
            "{}: {}",
            case.name,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{}: unexpected stderr", case.name);

        let lines = output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();

        let container = macho::cli::parse(&case.bytes).expect("fixture parses");
        let report = disassemble(&container, &case.request).expect("materialized disassembly");
        let expected = report
            .slices
            .iter()
            .flat_map(|slice| &slice.regions)
            .flat_map(|region| {
                region
                    .records
                    .iter()
                    .filter_map(move |record| match record {
                        DisassemblyRecord::Instruction { .. } => Some((region, record)),
                        DisassemblyRecord::Gap { .. } => None,
                    })
            })
            .collect::<Vec<_>>();

        assert_eq!(lines.len(), expected.len(), "{}", case.name);
        for (line, (region, record)) in lines.iter().zip(expected) {
            let DisassemblyRecord::Instruction {
                va,
                thin_file_offset,
                container_file_offset,
                size,
                bytes,
                kind,
                direct_target,
                ..
            } = record
            else {
                unreachable!()
            };

            assert_eq!(line["schema_version"], 1);
            assert!(line.get("event").is_none(), "{}", case.name);
            assert!(line.get("text").is_none(), "{}", case.name);
            assert_eq!(line["va"], *va);
            assert_eq!(line["thin_file_offset"], *thin_file_offset);
            assert_eq!(line["container_file_offset"], *container_file_offset);
            assert_eq!(line["size"], *size);
            assert_eq!(line["bytes"], bytes.as_str());
            assert_eq!(line["kind"], serde_json::to_value(kind).unwrap());
            assert!(
                line["mnemonic"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            );
            assert!(line["operands"].is_array());
            assert!(line["architecture"]["name"].is_string());
            assert!(line["architecture"]["cpu_type"].is_i64());
            assert!(line["architecture"]["cpu_subtype"].is_i64());
            assert_eq!(line["metadata"]["segment"], region.segment);
            assert_eq!(line["metadata"]["section"], region.section);
            assert_eq!(
                line["metadata"].get("target"),
                direct_target
                    .as_ref()
                    .map(|target| serde_json::to_value(target).unwrap())
                    .as_ref()
            );
        }

        std::fs::remove_file(path).unwrap();
    }
}
