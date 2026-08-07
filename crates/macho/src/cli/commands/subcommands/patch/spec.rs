use crate::cli::commands::usage_message;
use crate::cli::mutate::PatchOp;
use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;

use crate::analysis::pac::PacDetourAssessment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(super) enum PacPolicy {
    /// Do not assess arm64e detours.
    Off,
    /// Report PAC findings without rejecting the patch.
    Report,
    /// Require a compatible PAC assessment.
    Require,
}

#[derive(Debug)]
pub(super) enum PatchRequest {
    Operation(PatchOp<'static>),
    RawBytes {
        offset: u64,
        expected: Vec<u8>,
        replacement: Vec<u8>,
    },
    FileSection {
        segment: String,
        section: String,
        alignment: u32,
        path: PathBuf,
        payload: Vec<u8>,
    },
    ZeroFillSection {
        segment: String,
        section: String,
        alignment: u32,
        size: u64,
    },
    Detour {
        entry_va: u64,
        destination_va: u64,
        overwrite_len: usize,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum OperationDetail {
    RawBytes {
        offset: u64,
        expected_bytes: String,
        replacement_bytes: String,
    },
    Section {
        segment: String,
        section: String,
        content: &'static str,
        source: Option<PathBuf>,
        address: u64,
        file_offset: Option<u64>,
        size: u64,
        section_type: String,
        alignment_exponent: u32,
    },
    Detour {
        arch: String,
        entry_va: u64,
        entry_offset: usize,
        destination_va: u64,
        overwrite_len: usize,
        instruction_count: usize,
        encoding: &'static str,
        original_bytes: String,
        replacement_bytes: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pac: Option<PacDetourAssessment>,
    },
}

pub(super) fn parse_offset(s: &str) -> Result<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .map_err(|error| usage_message(format!("invalid hex offset {s}: {error}")))
    } else {
        s.parse::<u64>()
            .map_err(|error| usage_message(format!("invalid offset {s}: {error}")))
    }
}

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(usage_message(format!(
            "hex string must have even length, got {}",
            hex.len()
        )));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|error| {
                usage_message(format!(
                    "invalid hex byte at position {i} ({:?}): {error}",
                    &hex[i..i + 2]
                ))
            })
        })
        .collect()
}

pub(super) fn parse_patch_bytes_spec(spec: &str) -> Result<(u64, Vec<u8>, Vec<u8>)> {
    let fields = spec.split(',').collect::<Vec<_>>();
    let [offset, expected, replacement] = fields.as_slice() else {
        return Err(usage_message(format!(
            "invalid --bytes spec '{spec}', expected OFFSET,EXPECTED_HEX,REPLACEMENT_HEX"
        )));
    };
    let expected = parse_hex_bytes(expected)?;
    let replacement = parse_hex_bytes(replacement)?;
    if expected.len() != replacement.len() {
        return Err(usage_message(format!(
            "--bytes expected and replacement lengths differ ({} versus {})",
            expected.len(),
            replacement.len()
        )));
    }
    if replacement.is_empty() {
        return Err(usage_message("--bytes replacement must not be empty"));
    }
    Ok((parse_offset(offset)?, expected, replacement))
}

fn split_spec<'a>(spec: &'a str, option: &str) -> Result<[&'a str; 4]> {
    let fields = spec.splitn(4, ',').collect::<Vec<_>>();
    let [a, b, c, d] = fields.as_slice() else {
        return Err(usage_message(format!(
            "invalid {option} spec '{spec}', expected four comma-separated fields"
        )));
    };
    if fields.iter().any(|field| field.is_empty()) {
        return Err(usage_message(format!(
            "invalid {option} spec '{spec}': fields must not be empty"
        )));
    }
    Ok([a, b, c, d])
}

fn parse_u32(s: &str, field: &str) -> Result<u32> {
    let value = parse_offset(s)?;
    u32::try_from(value).map_err(|_| usage_message(format!("{field} exceeds u32: {s}")))
}

pub(super) fn parse_file_section_spec(spec: &str) -> Result<(String, String, u32, PathBuf)> {
    let [segment, section, alignment, path] = split_spec(spec, "--add-section")?;
    Ok((
        segment.to_owned(),
        section.to_owned(),
        parse_u32(alignment, "alignment exponent")?,
        PathBuf::from(path),
    ))
}

pub(super) fn parse_zerofill_section_spec(spec: &str) -> Result<(String, String, u32, u64)> {
    let [segment, section, alignment, size] = split_spec(spec, "--add-zerofill-section")?;
    let size = parse_offset(size)?;
    if size == 0 {
        return Err(usage_message("zero-fill section size must be non-zero"));
    }
    Ok((
        segment.to_owned(),
        section.to_owned(),
        parse_u32(alignment, "alignment exponent")?,
        size,
    ))
}

pub(super) fn parse_detour_spec(spec: &str) -> Result<(u64, u64, usize)> {
    let fields = spec.split(',').collect::<Vec<_>>();
    let [entry, destination, overwrite] = fields.as_slice() else {
        return Err(usage_message(format!(
            "invalid --detour spec '{spec}', expected ENTRY_VA,DESTINATION_VA,OVERWRITE_LEN"
        )));
    };
    let overwrite = parse_offset(overwrite)?;
    let overwrite = usize::try_from(overwrite)
        .map_err(|_| usage_message("detour overwrite length exceeds usize"))?;
    Ok((parse_offset(entry)?, parse_offset(destination)?, overwrite))
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub(super) fn format_operation_detail(detail: &OperationDetail) -> String {
    match detail {
        OperationDetail::RawBytes {
            offset,
            expected_bytes,
            replacement_bytes,
        } => format!("    precondition at {offset:#x}: {expected_bytes} -> {replacement_bytes}\n"),
        OperationDetail::Section {
            segment,
            section,
            content,
            address,
            file_offset,
            size,
            section_type,
            alignment_exponent,
            ..
        } => format!(
            "    placed {segment},{section}: {content}, address {address:#x}, file offset {}, size {size:#x}, type {section_type}, alignment 2^{alignment_exponent}\n",
            file_offset.map_or_else(|| "none".to_owned(), |offset| format!("{offset:#x}"))
        ),
        OperationDetail::Detour {
            arch,
            entry_va,
            entry_offset,
            destination_va,
            overwrite_len,
            instruction_count,
            encoding,
            original_bytes,
            replacement_bytes,
            pac,
        } => format!(
            "    detour {arch} {entry_va:#x} (offset {entry_offset:#x}) -> {destination_va:#x}, {overwrite_len} bytes across {instruction_count} complete instruction(s), {encoding}: {original_bytes} -> {replacement_bytes}\n{}",
            pac.as_ref().map_or_else(String::new, |assessment| {
                let mut rendered = format!("      PAC: {:?}\n", assessment.verdict);
                for finding in &assessment.findings {
                    rendered.push_str(&format!("        [{}] {}\n", finding.code, finding.message));
                }
                rendered
            })
        ),
    }
}
