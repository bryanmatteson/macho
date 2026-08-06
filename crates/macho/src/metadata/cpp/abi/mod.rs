//! C++ function body analysis for ABI heuristics.
//!
//! Uses `macho::insn` to decode function prologues and infer:
//! - Whether the function is a stub, thunk, or standard body
//! - Return channel (GPR, FP/SIMD, aggregate-indirect, void)
//! - Estimated parameter count from register saves
//! - `this` adjustment for thunks

use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::{Symbol, SymbolTable};
use crate::insn::{Arch, BranchTarget, Insn, InsnKind, Operand, RegClass};
use crate::metadata::cpp::VtableIndex;
use crate::metadata::cpp::{
    ArgumentTypeHint, CppBodyAnalysis, CppBodyKind, CppConfidence, CppEvidence, CppEvidenceKind,
    CppReturnChannel,
};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum bytes to read from a function body. Bounded at 16 KiB to cover
/// essentially any real function while avoiding pathological allocations.
const MAX_BODY_BYTES: usize = 16384;

/// Maximum instructions to decode. A 16 KiB function is at most ~4000 ARM64
/// instructions or ~16000 x86_64 instructions; 4000 is a safe ceiling.
const MAX_INSNS: usize = 4000;

/// How many prologue instructions to scan for register spills.
const PROLOGUE_WINDOW: usize = 25;

/// How many instructions before RET to examine for return channel evidence.
const EPILOGUE_WINDOW: usize = 10;

// ABI parameter register limits.
const ARM64_MAX_GPR_ARGS: u32 = 8; // x0-x7  (AAPCS64)
const ARM64_MAX_FP_ARGS: u32 = 8; // d0-d7  (AAPCS64)
const X86_64_MAX_GPR_ARGS: u32 = 6; // rdi,rsi,rdx,rcx,r8,r9 (SysV)
const X86_64_MAX_FP_ARGS: u32 = 8; // xmm0-xmm7             (SysV)

/// Analyze the body of a C++ symbol for ABI characteristics.
pub fn analyze_symbol_body(
    macho: &MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    symbol: &Symbol<'_>,
    vtable_index: Option<&VtableIndex>,
) -> Option<CppBodyAnalysis> {
    if !symbol.is_defined() || symbol.value == 0 {
        return None;
    }

    let bytes = symbol_bytes(macho, symtab, symbol, MAX_BODY_BYTES)?;
    let arch_name = macho.header().cpu_type().name().to_string();

    let (
        kind,
        return_channel,
        likely_wrapper,
        this_adjustment,
        param_counts,
        cfg,
        mut evidence_detail,
    ) = if arch_name.starts_with("arm64") {
        let arch = if arch_name == "arm64e" {
            Arch::Arm64e
        } else {
            Arch::Arm64
        };
        analyze_arm64(bytes, symbol.value, arch)
    } else if arch_name == "x86_64" {
        analyze_x86_64(bytes, symbol.value)
    } else {
        (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "unsupported architecture".to_string(),
        )
    };

    let param_count = param_counts.map(|pc| pc.total());

    // Argument type inference: runs on the CFG from the arch analysis.
    let argument_hints = if let (Some(cfg), Some(counts)) = (&cfg, param_counts) {
        let is_arm64 = arch_name.starts_with("arm64");
        infer_argument_types(cfg, counts, is_arm64, macho, symtab, vtable_index)
    } else {
        Vec::new()
    };

    let mut confidence = match kind {
        CppBodyKind::Thunk | CppBodyKind::Stub => CppConfidence::High,
        CppBodyKind::Standard => {
            if return_channel != CppReturnChannel::Unknown {
                CppConfidence::Medium
            } else {
                CppConfidence::Low
            }
        }
        CppBodyKind::Unknown => CppConfidence::Low,
    };
    if let Some(cfg) = &cfg {
        if !cfg.decode_gaps.is_empty() {
            confidence = CppConfidence::Low;
            evidence_detail.push_str(&format!(
                "; lossy decoding skipped {} invalid region(s)",
                cfg.decode_gaps.len()
            ));
        }
    }

    Some(CppBodyAnalysis {
        arch: arch_name,
        kind,
        return_channel,
        this_adjustment,
        likely_wrapper,
        param_count,
        argument_hints,
        evidence: vec![CppEvidence {
            kind: CppEvidenceKind::BodyAnalysis,
            confidence,
            detail: evidence_detail,
        }],
    })
}

fn symbol_bytes<'a>(
    macho: &'a MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    symbol: &Symbol<'_>,
    max_len: usize,
) -> Option<&'a [u8]> {
    let next_va = symtab
        .defined()
        .filter(|candidate| candidate.value > symbol.value)
        .map(|candidate| candidate.value)
        .min()
        .unwrap_or(symbol.value + max_len as u64);
    let len = (next_va - symbol.value).min(max_len as u64) as usize;
    macho.read_bytes_at_va(Va(symbol.value), len.max(1)).ok()
}

include!("cfg.rs");
include!("arm64.rs");
include!("x86_64.rs");
include!("arguments.rs");
include!("tests.rs");
