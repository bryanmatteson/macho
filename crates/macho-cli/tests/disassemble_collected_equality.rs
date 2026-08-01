//! F1 collected-equality: the NDJSON stream the CLI writes under `--format json`
//! losslessly encodes the materialized `DisassemblyReport`. For every fixture and
//! request used by the suite, reassembling the report from the stream lines must
//! equal `macho::analysis::disassembly::disassemble(&container, &request)` for
//! the same request.

use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use macho_cli::analysis::disassembly::{
    AddressExtent, DecodeMode, DisassemblyRequest, DisassemblySelection, NonEmpty, SectionSelector,
    SliceSelection, disassemble,
};
use macho_cli::analysis::report::disassembly::{
    DisassemblyIssue, DisassemblyLabel, DisassemblyRecord, DisassemblyRegion, DisassemblyReport,
    DisassemblyReportRequest, DisassemblySchemaVersion, DisassemblySlice, DisassemblyStatus,
    InstructionFlags, RangeEndSource, SelectionSource, SymbolSource,
};
use macho_cli::analysis::report::{Architecture, ReportContainerIdentity, ReportSliceIdentity};
use macho_cli::model::addr::Va;
use serde::Deserialize;

fn fixture_path(name: &str, bytes: &[u8]) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved forward")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("macho-collected-{name}-{nonce}"));
    std::fs::write(&path, bytes).expect("write fixture");
    path
}

/// The default per-slice examined-byte limit the CLI applies (`--max-decoded-bytes`).
fn default_max_decoded_bytes() -> NonZeroUsize {
    NonZeroUsize::new(67_108_864).unwrap()
}

/// The default per-slice symbol-observation limit the CLI applies (`--max-ranges`).
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

/// One fixture, the CLI arguments that select it, and the equivalent request the
/// materialized API receives. The two must stay in lockstep; drift surfaces as a
/// report inequality, never as a silent pass.
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

/// One decoded NDJSON stream line. Mirrors the CLI emitter so the payload of each
/// event deserializes straight into the real report DTOs.
#[derive(Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum StreamLine {
    Header {
        schema_version: DisassemblySchemaVersion,
        container: ReportContainerIdentity,
        request: DisassemblyReportRequest,
    },
    Slice {
        identity: ReportSliceIdentity,
        container_offset: u64,
        slice_size: u64,
    },
    Region {
        segment: String,
        section: String,
        selection_source: SelectionSource,
        range_source: Option<SymbolSource>,
        end_source: Option<RangeEndSource>,
        start_va: u64,
        requested_end_va: Option<u64>,
        requested_instruction_count: Option<u64>,
        instruction_flags: InstructionFlags,
    },
    Record {
        record: DisassemblyRecord,
    },
    Label {
        label: DisassemblyLabel,
    },
    RegionEnd {
        emitted_instruction_count: u64,
        examined_end_va: u64,
        next_unexamined_va: Option<u64>,
    },
    SliceEnd {
        status: DisassemblyStatus,
        decoded_bytes: u64,
        decoded_bytes_truncated: bool,
        symbol_ranges_truncated: bool,
    },
    Issue {
        issue: DisassemblyIssue,
    },
}

/// Region header fields carried until the matching `region_end` completes them.
struct RegionParts {
    segment: String,
    section: String,
    selection_source: SelectionSource,
    range_source: Option<SymbolSource>,
    end_source: Option<RangeEndSource>,
    start_va: u64,
    requested_end_va: Option<u64>,
    requested_instruction_count: Option<u64>,
    instruction_flags: InstructionFlags,
    labels: Vec<DisassemblyLabel>,
    records: Vec<DisassemblyRecord>,
}

/// Reassemble a `DisassemblyReport` purely from the ordered NDJSON stream.
fn reassemble(stdout: &[u8]) -> DisassemblyReport {
    let mut schema_version: Option<DisassemblySchemaVersion> = None;
    let mut container: Option<ReportContainerIdentity> = None;
    let mut request: Option<DisassemblyReportRequest> = None;
    let mut slices: Vec<DisassemblySlice> = Vec::new();

    let mut slice_identity: Option<(ReportSliceIdentity, u64, u64)> = None;
    let mut slice_regions: Vec<DisassemblyRegion> = Vec::new();
    let mut region: Option<RegionParts> = None;

    for raw in stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match serde_json::from_slice::<StreamLine>(raw).expect("each line is a valid stream event")
        {
            StreamLine::Header {
                schema_version: version,
                container: identity,
                request: echoed,
            } => {
                schema_version = Some(version);
                container = Some(identity);
                request = Some(echoed);
            }
            StreamLine::Slice {
                identity,
                container_offset,
                slice_size,
            } => {
                slice_identity = Some((identity, container_offset, slice_size));
                slice_regions = Vec::new();
            }
            StreamLine::Region {
                segment,
                section,
                selection_source,
                range_source,
                end_source,
                start_va,
                requested_end_va,
                requested_instruction_count,
                instruction_flags,
            } => {
                region = Some(RegionParts {
                    segment,
                    section,
                    selection_source,
                    range_source,
                    end_source,
                    start_va,
                    requested_end_va,
                    requested_instruction_count,
                    instruction_flags,
                    labels: Vec::new(),
                    records: Vec::new(),
                });
            }
            StreamLine::Record { record: value } => {
                region
                    .as_mut()
                    .expect("a region precedes every record")
                    .records
                    .push(value);
            }
            StreamLine::Label { label } => {
                region
                    .as_mut()
                    .expect("a region precedes every label")
                    .labels
                    .push(label);
            }
            StreamLine::RegionEnd {
                emitted_instruction_count,
                examined_end_va,
                next_unexamined_va,
            } => {
                let parts = region.take().expect("a region precedes region_end");
                slice_regions.push(DisassemblyRegion {
                    segment: parts.segment,
                    section: parts.section,
                    selection_source: parts.selection_source,
                    range_source: parts.range_source,
                    end_source: parts.end_source,
                    start_va: parts.start_va,
                    requested_end_va: parts.requested_end_va,
                    requested_instruction_count: parts.requested_instruction_count,
                    emitted_instruction_count,
                    examined_end_va,
                    next_unexamined_va,
                    instruction_flags: parts.instruction_flags,
                    labels: parts.labels,
                    records: parts.records,
                });
            }
            StreamLine::SliceEnd {
                status,
                decoded_bytes,
                decoded_bytes_truncated,
                symbol_ranges_truncated,
            } => {
                let (identity, container_offset, slice_size) =
                    slice_identity.take().expect("a slice precedes slice_end");
                slices.push(DisassemblySlice {
                    identity,
                    container_offset,
                    slice_size,
                    status,
                    decoded_bytes,
                    decoded_bytes_truncated,
                    symbol_ranges_truncated,
                    regions: std::mem::take(&mut slice_regions),
                    issues: Vec::new(),
                });
            }
            StreamLine::Issue { issue } => {
                slices
                    .last_mut()
                    .expect("slice_end precedes its issues")
                    .issues
                    .push(issue);
            }
        }
    }

    DisassemblyReport {
        schema_version: schema_version.expect("the stream begins with a header"),
        container: container.expect("the stream begins with a header"),
        request: request.expect("the stream begins with a header"),
        slices,
    }
}

#[test]
fn ndjson_stream_reassembles_to_the_materialized_report() {
    for case in cases() {
        let path = fixture_path(case.name, &case.bytes);
        let mut args = vec!["disassemble".to_owned(), path.to_str().unwrap().to_owned()];
        args.extend(case.extra_args.iter().map(|arg| (*arg).to_owned()));
        args.extend(
            ["--format", "json", "--color", "never"]
                .iter()
                .map(|arg| (*arg).to_owned()),
        );
        let output = macho_cli::run_captured(args);
        assert_eq!(
            output.code,
            0,
            "{}: {}",
            case.name,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "{}: unexpected stderr", case.name);

        let streamed = reassemble(&output.stdout);

        let container = macho_cli::parse(&case.bytes).expect("fixture parses");
        let materialized =
            disassemble(&container, &case.request).expect("materialized disassembly succeeds");

        assert_eq!(
            streamed, materialized,
            "{}: the NDJSON stream must reassemble to the materialized report",
            case.name
        );

        std::fs::remove_file(&path).unwrap();
    }
}
