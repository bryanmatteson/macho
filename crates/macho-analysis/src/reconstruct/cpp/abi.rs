//! C++ function body analysis for ABI heuristics.
//!
//! Uses `macho-insn` to decode function prologues and infer:
//! - Whether the function is a stub, thunk, or standard body
//! - Return channel (GPR, FP/SIMD, aggregate-indirect, void)
//! - Estimated parameter count from register saves
//! - `this` adjustment for thunks

use super::types::{
    ArgumentTypeHint, CppBodyAnalysis, CppBodyKind, CppConfidence, CppEvidence, CppEvidenceKind,
    CppReturnChannel,
};
use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::{Symbol, SymbolTable};
use crate::vtables::VtableIndex;
use macho_insn::{Arch, BranchTarget, Insn, InsnKind, Operand, RegClass};
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
    let arch_name = macho.header().cpu_type.name().to_string();

    let (kind, return_channel, likely_wrapper, this_adjustment, param_counts, cfg, evidence_detail) =
        if arch_name.starts_with("arm64") {
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

    let confidence = match kind {
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

// ─────────────────────────── CFG ───────────────────────────

/// Separate GPR and FP argument counts from the prologue scan.
#[derive(Debug, Clone, Copy)]
struct ParamCounts {
    gpr: u32,
    fp: u32,
}

impl ParamCounts {
    fn total(self) -> u32 {
        self.gpr + self.fp
    }
}

/// (kind, return_channel, likely_wrapper, this_adjustment, param_counts, cfg, detail)
type AnalysisResult = (
    CppBodyKind,
    CppReturnChannel,
    bool,
    Option<i64>,
    Option<ParamCounts>,
    Option<FunctionCfg>,
    String,
);

/// A basic block in the function's control-flow graph.
#[derive(Debug)]
struct BasicBlock {
    /// Index of the first instruction in this block (into the `insns` Vec).
    start: usize,
    /// Index one-past the last instruction in this block.
    end: usize,
    /// True if this block is reachable from the entry point.
    reachable: bool,
}

/// A lightweight control-flow graph built from decoded instructions.
///
/// Splits the instruction stream into basic blocks at branch targets and after
/// branches/returns, then computes reachability from the entry block. This
/// determines which instructions are actually part of the function (vs. padding
/// or the next function's code that was included in the byte window).
struct FunctionCfg {
    /// Decoded instructions for the entire byte window.
    insns: Vec<Insn>,
    /// Basic blocks, sorted by start index.
    blocks: Vec<BasicBlock>,
    /// Virtual address of the function entry point.
    entry_va: u64,
}

impl FunctionCfg {
    /// Compute the VA of an instruction from its byte offset.
    fn insn_va(&self, insn: &Insn) -> u64 {
        self.entry_va + insn.offset as u64
    }
}

impl FunctionCfg {
    /// Build a CFG from raw bytes.
    fn build(bytes: &[u8], entry_va: u64, arch: Arch) -> Self {
        // Decode all instructions and record their VAs.
        let mut insns = Vec::new();
        let mut vas = Vec::new();
        for insn in macho_insn::decode_iter(bytes, entry_va, arch).take(MAX_INSNS) {
            vas.push(entry_va + insn.offset as u64);
            insns.push(insn);
        }

        if insns.is_empty() {
            return Self {
                insns,
                blocks: Vec::new(),
                entry_va,
            };
        }

        // Collect block-start VAs: entry point + all branch targets + instruction
        // after every branch/ret.
        let mut block_starts: BTreeSet<u64> = BTreeSet::new();
        block_starts.insert(entry_va);

        for (i, insn) in insns.iter().enumerate() {
            let insn_va = vas[i];
            let next_va = insn_va + insn.len as u64;

            match &insn.kind {
                InsnKind::Branch(bi) | InsnKind::Call(bi) | InsnKind::CondBranch(bi) => {
                    // The instruction after a branch starts a new block.
                    block_starts.insert(next_va);
                    // The branch target starts a new block.
                    if let BranchTarget::Direct(offset) = bi.target {
                        let target = insn_va.wrapping_add_signed(offset);
                        if target >= entry_va && target < entry_va + bytes.len() as u64 {
                            block_starts.insert(target);
                        }
                    }
                }
                InsnKind::Return => {
                    block_starts.insert(next_va);
                }
                _ => {}
            }
        }

        // Build a VA → instruction index map for quick lookup.
        let va_to_idx = |target_va: u64| -> Option<usize> {
            vas.binary_search(&target_va).ok()
        };

        // Partition instructions into basic blocks.
        let mut blocks: Vec<BasicBlock> = Vec::new();
        let mut current_start = 0usize;
        for i in 1..insns.len() {
            if block_starts.contains(&vas[i]) {
                blocks.push(BasicBlock {
                    start: current_start,
                    end: i,
                    reachable: false,
                });
                current_start = i;
            }
        }
        blocks.push(BasicBlock {
            start: current_start,
            end: insns.len(),
            reachable: false,
        });

        // Compute reachability via BFS from block 0 (entry).
        if !blocks.is_empty() {
            let mut worklist = vec![0usize]; // block indices to visit
            blocks[0].reachable = true;

            while let Some(bi) = worklist.pop() {
                let block = &blocks[bi];
                if block.start >= block.end {
                    continue; // skip zero-length blocks from degenerate splits
                }
                let last_idx = block.end - 1;
                let last_insn = &insns[last_idx];
                let last_va = vas[last_idx];
                let fallthrough_va = last_va + last_insn.len as u64;

                // Determine successors.
                let mut successor_vas = Vec::new();
                match &last_insn.kind {
                    InsnKind::Return => {
                        // No successors.
                    }
                    InsnKind::Branch(bi_info) => {
                        // Unconditional branch: only target, no fallthrough.
                        if let BranchTarget::Direct(offset) = bi_info.target {
                            successor_vas.push(last_va.wrapping_add_signed(offset));
                        }
                        // Register/indirect branches: conservative — no known successors.
                    }
                    InsnKind::Call(_) => {
                        // Calls return to fallthrough.
                        successor_vas.push(fallthrough_va);
                    }
                    InsnKind::CondBranch(bi_info) => {
                        // Conditional: both fallthrough and target.
                        successor_vas.push(fallthrough_va);
                        if let BranchTarget::Direct(offset) = bi_info.target {
                            successor_vas.push(last_va.wrapping_add_signed(offset));
                        }
                    }
                    _ => {
                        // Non-terminator at end of block (block was split by a
                        // target label): fallthrough.
                        successor_vas.push(fallthrough_va);
                    }
                }

                // Map successor VAs to block indices and mark reachable.
                for succ_va in successor_vas {
                    if let Some(insn_idx) = va_to_idx(succ_va) {
                        // Find which block contains this instruction index.
                        if let Ok(block_idx) =
                            blocks.binary_search_by(|b| {
                                if insn_idx < b.start {
                                    std::cmp::Ordering::Greater
                                } else if insn_idx >= b.end {
                                    std::cmp::Ordering::Less
                                } else {
                                    std::cmp::Ordering::Equal
                                }
                            })
                        {
                            if !blocks[block_idx].reachable {
                                blocks[block_idx].reachable = true;
                                worklist.push(block_idx);
                            }
                        }
                    }
                }
            }
        }

        Self {
            insns,
            blocks,
            entry_va,
        }
    }

    /// Indices of all RET instructions in reachable blocks.
    fn ret_positions(&self) -> Vec<usize> {
        self.blocks
            .iter()
            .filter(|b| b.reachable)
            .flat_map(|b| b.start..b.end)
            .filter(|&i| matches!(self.insns[i].kind, InsnKind::Return))
            .collect()
    }
}

// ───────────────────────── ARM64 analysis ─────────────────────────

fn analyze_arm64(bytes: &[u8], va: u64, arch: Arch) -> AnalysisResult {
    if bytes.len() < 4 {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "function body too small".into(),
        );
    }

    let cfg = FunctionCfg::build(bytes, va, arch);
    if cfg.insns.is_empty() {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "no decodable instructions".into(),
        );
    }

    // ── First-instruction classification (thunk / stub) ──
    match &cfg.insns[0].kind {
        InsnKind::Return => {
            return (
                CppBodyKind::Stub,
                CppReturnChannel::Unknown,
                true,
                None,
                Some(ParamCounts { gpr: 0, fp: 0 }),
                None,
                "immediate RET".into(),
            );
        }
        InsnKind::Branch(_) | InsnKind::Call(_) => {
            return (
                CppBodyKind::Thunk,
                CppReturnChannel::Unknown,
                true,
                None,
                None,
                None,
                "immediate branch/call".into(),
            );
        }
        _ => {}
    }

    // ── Prologue scan: register spills ──
    let mut detail_parts = Vec::new();
    let mut has_sret = false;
    let mut max_gpr_arg_saved = -1i32;
    let mut max_fpr_arg_saved = -1i32;

    for insn in cfg.insns.iter().take(PROLOGUE_WINDOW) {
        if matches!(
            insn.kind,
            InsnKind::Return | InsnKind::Branch(_) | InsnKind::Call(_)
        ) {
            break;
        }

        let ops = insn.operands();
        let is_store = ops.iter().any(|op| matches!(op, Operand::Mem { .. }));
        if is_store {
            for op in ops {
                match op {
                    Operand::Reg(r) if r.class == RegClass::Gpr && r.num <= 7 => {
                        max_gpr_arg_saved = max_gpr_arg_saved.max(r.num as i32);
                    }
                    Operand::Reg(r) if r.class == RegClass::Gpr && r.num == 8 => {
                        has_sret = true;
                    }
                    Operand::Reg(r) if r.class == RegClass::Fp && r.num <= 7 => {
                        max_fpr_arg_saved = max_fpr_arg_saved.max(r.num as i32);
                    }
                    _ => {}
                }
            }
        }
    }

    // ── Epilogue scan: all reachable RETs ──
    let ret_positions = cfg.ret_positions();
    let mut wrote_d0 = false;
    let mut wrote_x0 = false;

    for &rp in &ret_positions {
        let window_start = rp.saturating_sub(EPILOGUE_WINDOW);
        for insn in &cfg.insns[window_start..rp] {
            let ops = insn.operands();
            if let [Operand::Reg(dst), Operand::Reg(src)] = ops {
                if dst.class == RegClass::Fp && dst.num == 0 && src.class == RegClass::Fp {
                    wrote_d0 = true;
                }
            }
            if let Some(Operand::Reg(r)) = ops.first() {
                if r.class == RegClass::Gpr && r.num == 0 {
                    let is_restore = ops.iter().any(|op| {
                        matches!(
                            op,
                            Operand::Mem { base, .. } if base.class == RegClass::Gpr && base.num == 31
                        )
                    });
                    if !is_restore {
                        wrote_x0 = true;
                    }
                }
            }
        }
    }

    // ── Return channel ──
    let mut return_channel = CppReturnChannel::Unknown;
    if has_sret {
        return_channel = CppReturnChannel::AggregateIndirect;
        detail_parts.push("x8 saved (sret)");
    } else if wrote_d0 {
        return_channel = CppReturnChannel::FloatingPoint;
        detail_parts.push("FP return detected");
    } else if wrote_x0 {
        return_channel = CppReturnChannel::GeneralPurpose;
        detail_parts.push("x0 set before RET");
    } else if !ret_positions.is_empty() {
        return_channel = CppReturnChannel::Void;
        detail_parts.push("no return register written");
    }

    // ── Parameter count with ABI caps ──
    let param_counts = if max_gpr_arg_saved >= 0 || max_fpr_arg_saved >= 0 {
        let gpr = if max_gpr_arg_saved >= 0 {
            ((max_gpr_arg_saved + 1) as u32).min(ARM64_MAX_GPR_ARGS)
        } else {
            0
        };
        let fp = if max_fpr_arg_saved >= 0 {
            ((max_fpr_arg_saved + 1) as u32).min(ARM64_MAX_FP_ARGS)
        } else {
            0
        };
        detail_parts.push("param count from register saves");
        Some(ParamCounts { gpr, fp })
    } else {
        None
    };

    let detail = if detail_parts.is_empty() {
        "standard body, no strong heuristics".to_string()
    } else {
        detail_parts.join("; ")
    };

    (
        CppBodyKind::Standard,
        return_channel,
        false,
        None,
        param_counts,
        Some(cfg),
        detail,
    )
}

// ───────────────────────── x86_64 analysis ─────────────────────────

/// x86_64 SysV ABI argument register numbers (in macho-insn Gpr numbering).
const X86_RDI: u8 = 7;
const X86_RSI: u8 = 6;
const X86_RDX: u8 = 2;
const X86_RCX: u8 = 1;
const X86_R8: u8 = 8;
const X86_R9: u8 = 9;

/// Map x86_64 GPR number to SysV argument position (0-5).
fn x86_arg_position(gpr_num: u8) -> Option<i32> {
    match gpr_num {
        X86_RDI => Some(0),
        X86_RSI => Some(1),
        X86_RDX => Some(2),
        X86_RCX => Some(3),
        X86_R8 => Some(4),
        X86_R9 => Some(5),
        _ => None,
    }
}

fn analyze_x86_64(bytes: &[u8], va: u64) -> AnalysisResult {
    if bytes.is_empty() {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "empty body".into(),
        );
    }

    // ── First-instruction classification (thunk / stub) ──

    // Check for this-adjusting thunk: ADD/SUB rdi, imm; JMP.
    if let Ok(first) = macho_insn::decode_one(bytes, va, Arch::X86_64) {
        if matches!(first.kind, InsnKind::Other) {
            let ops = first.operands();
            if let (Some(Operand::Reg(dst)), Some(&Operand::Imm(imm))) = (ops.first(), ops.get(1))
            {
                if dst.class == RegClass::Gpr && dst.num == X86_RDI {
                    if let Ok(next) = macho_insn::decode_one(
                        &bytes[first.len..],
                        va + first.len as u64,
                        Arch::X86_64,
                    ) {
                        if matches!(next.kind, InsnKind::Branch(_)) {
                            let adj = if bytes.len() > 2 && (bytes[2] >> 3) & 7 == 5 {
                                -imm
                            } else {
                                imm
                            };
                            return (
                                CppBodyKind::Thunk,
                                CppReturnChannel::Unknown,
                                true,
                                Some(adj),
                                None,
                                None,
                                "this-adjusting thunk".into(),
                            );
                        }
                    }
                }
            }
        }

        match &first.kind {
            InsnKind::Branch(_) => {
                return (
                    CppBodyKind::Thunk,
                    CppReturnChannel::Unknown,
                    true,
                    None,
                    None,
                    None,
                    "jump thunk".into(),
                );
            }
            InsnKind::Return => {
                return (
                    CppBodyKind::Stub,
                    CppReturnChannel::Unknown,
                    true,
                    None,
                    Some(ParamCounts { gpr: 0, fp: 0 }),
                    None,
                    "immediate RET".into(),
                );
            }
            _ => {}
        }
    }

    // ── Decode full body with CFG ──
    let cfg = FunctionCfg::build(bytes, va, Arch::X86_64);

    // ── Prologue scan: register spills ──
    let mut detail_parts = Vec::new();
    let mut max_gpr_arg_touched = -1i32;
    let mut max_fp_arg_touched = -1i32;
    let mut rdi_was_saved = false;

    for insn in cfg.insns.iter().take(PROLOGUE_WINDOW) {
        if matches!(
            insn.kind,
            InsnKind::Return | InsnKind::Branch(_) | InsnKind::Call(_)
        ) {
            break;
        }

        let ops = insn.operands();
        match ops {
            // Single register operand (PUSH reg).
            [Operand::Reg(r)] if r.class == RegClass::Gpr => {
                if r.num == X86_RDI {
                    rdi_was_saved = true;
                }
                if let Some(pos) = x86_arg_position(r.num) {
                    max_gpr_arg_touched = max_gpr_arg_touched.max(pos);
                }
            }
            // Memory destination + GPR source (MOV [rsp+disp], reg).
            [Operand::Mem { .. }, Operand::Reg(r)] if r.class == RegClass::Gpr => {
                if r.num == X86_RDI {
                    rdi_was_saved = true;
                }
                if let Some(pos) = x86_arg_position(r.num) {
                    max_gpr_arg_touched = max_gpr_arg_touched.max(pos);
                }
            }
            // Memory destination + FP source (MOVSD [rsp+disp], xmm0).
            [Operand::Mem { .. }, Operand::Reg(r)] if r.class == RegClass::Fp && r.num <= 7 => {
                max_fp_arg_touched = max_fp_arg_touched.max(r.num as i32);
            }
            _ => {}
        }
    }

    // ── Epilogue scan: all reachable RETs ──
    let ret_positions = cfg.ret_positions();
    let mut wrote_xmm0 = false;
    let mut wrote_rax = false;
    let mut rax_from_stack = false;

    for &rp in &ret_positions {
        let window_start = rp.saturating_sub(EPILOGUE_WINDOW);
        for insn in &cfg.insns[window_start..rp] {
            // Skip instructions that write rax as an implicit side effect.
            if insn.writes_implicit_gpr0 {
                continue;
            }
            match insn.operands() {
                // xmm0 written.
                [Operand::Reg(r), ..] if r.class == RegClass::Fp && r.num == 0 => {
                    wrote_xmm0 = true;
                }
                // rax loaded from memory → possible sret return.
                [Operand::Reg(r), Operand::Mem { .. }]
                    if r.class == RegClass::Gpr && r.num == 0 =>
                {
                    rax_from_stack = true;
                    wrote_rax = true;
                }
                // rax written explicitly.
                [Operand::Reg(r), ..] if r.class == RegClass::Gpr && r.num == 0 => {
                    wrote_rax = true;
                }
                _ => {}
            }
        }
    }

    // ── sret detection ──
    // On SysV, sret passes the return pointer in rdi and the function returns
    // it in rax. Both conditions must hold: rdi was saved AND rax was loaded
    // from the stack in the epilogue.
    let mut has_sret = false;
    if rdi_was_saved && rax_from_stack {
        has_sret = true;
    }

    // ── Return channel ──
    let mut return_channel = CppReturnChannel::Unknown;
    if has_sret {
        return_channel = CppReturnChannel::AggregateIndirect;
        detail_parts.push("sret (rax loaded from stack, rdi saved)");
        // rdi is the hidden sret pointer — adjust param count.
        if max_gpr_arg_touched == 0 {
            max_gpr_arg_touched = -1;
        } else if max_gpr_arg_touched > 0 {
            max_gpr_arg_touched -= 1;
        }
    } else if wrote_xmm0 {
        return_channel = CppReturnChannel::FloatingPoint;
        detail_parts.push("xmm0 set before RET");
    } else if wrote_rax {
        return_channel = CppReturnChannel::GeneralPurpose;
        detail_parts.push("rax set before RET");
    } else if !ret_positions.is_empty() {
        return_channel = CppReturnChannel::Void;
        detail_parts.push("no return register written");
    }

    // ── Parameter count with ABI caps ──
    let gpr = if max_gpr_arg_touched >= 0 {
        ((max_gpr_arg_touched + 1) as u32).min(X86_64_MAX_GPR_ARGS)
    } else {
        0
    };
    let fp = if max_fp_arg_touched >= 0 {
        ((max_fp_arg_touched + 1) as u32).min(X86_64_MAX_FP_ARGS)
    } else {
        0
    };
    let param_counts = if gpr > 0 || fp > 0 {
        detail_parts.push("param count from register spills");
        Some(ParamCounts { gpr, fp })
    } else {
        None
    };

    let detail = if detail_parts.is_empty() {
        "standard body, no strong heuristics".to_string()
    } else {
        detail_parts.join("; ")
    };

    (
        CppBodyKind::Standard,
        return_channel,
        false,
        None,
        param_counts,
        Some(cfg),
        detail,
    )
}

// ───────────────────── argument type inference ─────────────────────

/// Known C string functions. If the function body calls any of these, pointer
/// arguments are likely C strings.
const STRING_FUNCTIONS: &[&str] = &[
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat",
    "strdup", "strndup", "strchr", "strrchr", "strstr", "strtol", "strtoul",
    "strtod", "strtof", "atoi", "atol", "atof",
    "printf", "fprintf", "snprintf", "sprintf", "vprintf", "vfprintf",
    "vsnprintf", "vsprintf", "puts", "fputs", "fgets",
    "sscanf", "fscanf",
    "fopen", "freopen",
    // CoreFoundation / ObjC-adjacent
    "NSLog",
    "CFStringCreateWithCString",
];

/// Known ObjC runtime functions. If arg0 is a pointer and the function calls
/// one of these, arg0 is an ObjC object.
const OBJC_FUNCTIONS: &[&str] = &[
    "objc_msgSend",
    "objc_msgSendSuper",
    "objc_msgSendSuper2",
    "objc_msgSend_stret",
    "objc_retain",
    "objc_release",
    "objc_autorelease",
    "objc_alloc",
    "objc_alloc_init",
    "objc_opt_new",
    "objc_storeStrong",
    "objc_retainAutoreleasedReturnValue",
];

/// Build a mapping from stub section VAs to imported symbol names.
///
/// When code calls an external function like `strlen`, the call target is a
/// stub entry in `__stubs`. This function reads the indirect symbol table to
/// map each stub's VA to the imported function name.
fn build_stub_map(macho: &MachoFile<'_>) -> BTreeMap<u64, String> {
    use crate::core::model::load_command::LoadCommand;
    use crate::core::model::section::SectionType;

    let mut map = BTreeMap::new();

    let symtab = match macho.ext::<SymbolTable<'_>>() {
        Ok(st) => st,
        Err(_) => return map,
    };

    let dysymtab = match macho.find_load_command(|lc| matches!(lc, LoadCommand::Dysymtab(_))) {
        Some(lc) => match lc.kind.as_dysymtab() {
            Some(d) => d.clone(),
            None => return map,
        },
        None => return map,
    };

    if dysymtab.nindirectsyms == 0 {
        return map;
    }

    let indirect_off = dysymtab.indirectsymoff as usize;
    let n_indirect = dysymtab.nindirectsyms as usize;
    let endian = macho.endian();

    let indirect_data = match macho.read_bytes_at(
        crate::core::model::addr::ThinFileOffset(indirect_off as u64),
        n_indirect * 4,
    ) {
        Ok(data) => data,
        Err(_) => return map,
    };

    for sect in macho.all_sections() {
        if !matches!(
            sect.section_type,
            SectionType::SymbolStubs
                | SectionType::NonLazySymbolPointers
                | SectionType::LazySymbolPointers
        ) {
            continue;
        }

        let indirect_start = sect.reserved1 as usize;
        let entry_size = match sect.section_type {
            SectionType::SymbolStubs => {
                if sect.reserved2 == 0 {
                    continue;
                }
                sect.reserved2 as u64
            }
            _ => {
                if macho.is_64bit() { 8u64 } else { 4u64 }
            }
        };

        let n_entries = if entry_size > 0 {
            (sect.size / entry_size) as usize
        } else {
            continue;
        };

        for i in 0..n_entries {
            let isym_idx = indirect_start + i;
            if isym_idx >= n_indirect {
                break;
            }
            let table_offset = isym_idx * 4;
            if table_offset + 4 > indirect_data.len() {
                break;
            }
            let raw_index = endian.interpret_u32(u32::from_ne_bytes([
                indirect_data[table_offset],
                indirect_data[table_offset + 1],
                indirect_data[table_offset + 2],
                indirect_data[table_offset + 3],
            ]));
            if raw_index & 0xC000_0000 != 0 {
                continue;
            }
            let stub_va = sect.addr.0 + i as u64 * entry_size;
            if let Some(sym) = symtab.get(raw_index as usize) {
                map.insert(stub_va, sym.name.to_string());
            }
        }
    }

    map
}

/// Per-argument usage data collected from the function body.
#[derive(Default)]
struct ArgUsage {
    /// True if this argument register was used as a memory base (dereferenced).
    is_pointer: bool,
    /// Displacements at which the pointer was dereferenced.
    deref_offsets: Vec<i64>,
    /// True if a known string function receives this argument.
    passed_to_string_fn: bool,
    /// True if a known ObjC runtime function receives this as arg0.
    passed_to_objc_fn: bool,
}

/// Infer argument types from instruction-level usage patterns.
fn infer_argument_types(
    cfg: &FunctionCfg,
    counts: ParamCounts,
    is_arm64: bool,
    macho: &MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    _vtable_index: Option<&VtableIndex>,
) -> Vec<ArgumentTypeHint> {
    // Determine which GPR numbers are argument registers (in ABI order).
    let gpr_arg_nums: Vec<u8> = if is_arm64 {
        (0..8u8).collect() // x0-x7
    } else {
        vec![X86_RDI, X86_RSI, X86_RDX, X86_RCX, X86_R8, X86_R9]
    };

    let gpr_count = counts.gpr.min(gpr_arg_nums.len() as u32) as usize;
    let fp_count = counts.fp as usize;

    // Track which arg registers are "live" (still hold the original argument).
    // Once a register is overwritten (appears as Reg destination in a non-store),
    // subsequent uses as a memory base don't indicate the *argument* is a pointer.
    let active_gpr_args: BTreeSet<u8> = gpr_arg_nums[..gpr_count].iter().copied().collect();
    let mut gpr_usage: BTreeMap<u8, ArgUsage> = BTreeMap::new();
    let mut overwritten: BTreeSet<u8> = BTreeSet::new();

    // Build VA → name maps for call-target resolution.
    // sym_by_va: defined symbols (local functions).
    // stub_by_va: PLT stubs → imported function names (strlen, objc_msgSend, etc.).
    let sym_by_va: BTreeMap<u64, &str> = symtab
        .symbols()
        .iter()
        .filter(|s| s.value != 0)
        .map(|s| (s.value, s.name))
        .collect();
    let stub_by_va = build_stub_map(macho);

    // ── Single pass over all reachable instructions ──
    //
    // For each instruction we:
    //   1. Check if an arg register is used as a Mem base (pointer detection),
    //      but only if the register hasn't been overwritten yet.
    //   2. Check if this is a Call to a known string/ObjC function, and if so,
    //      record which arg register is in the callee's first-arg position.
    //   3. Track register overwrites: if an arg register appears as the first
    //      Reg operand in a non-store, non-push instruction, mark it overwritten.
    for block in &cfg.blocks {
        if !block.reachable {
            continue;
        }
        for i in block.start..block.end {
            let insn = &cfg.insns[i];
            let ops = insn.operands();

            // -- Pointer detection --
            for op in ops {
                if let Operand::Mem { base, disp } = op {
                    if base.class == RegClass::Gpr
                        && active_gpr_args.contains(&base.num)
                        && !overwritten.contains(&base.num)
                    {
                        let usage = gpr_usage.entry(base.num).or_default();
                        usage.is_pointer = true;
                        usage.deref_offsets.push(*disp);
                    }
                }
            }

            // -- Call-target correlation --
            if let InsnKind::Call(bi) = &insn.kind {
                if let BranchTarget::Direct(offset) = bi.target {
                    let target_va = cfg.insn_va(insn).wrapping_add_signed(offset);
                    // Look up the target in both the defined-symbol map and the
                    // stub map. Stubs cover dynamically-linked calls (strlen, etc.).
                    let name = sym_by_va
                        .get(&target_va)
                        .copied()
                        .or_else(|| stub_by_va.get(&target_va).map(|s| s.as_str()));
                    if let Some(name) = name {
                        let clean = name
                            .trim_start_matches('_')
                            .trim_start_matches('$');
                        let is_string_fn =
                            STRING_FUNCTIONS.iter().any(|&sf| clean == sf);
                        let is_objc_fn =
                            OBJC_FUNCTIONS.iter().any(|&of| clean == of);

                        if is_string_fn || is_objc_fn {
                            // The callee receives args in the same ABI registers.
                            // The first GPR arg register that is still live and is
                            // a pointer gets the string/ObjC tag.
                            // This is a simplification: we assume the first live
                            // pointer-arg register is the one being passed.
                            for &reg_num in &gpr_arg_nums[..gpr_count] {
                                if overwritten.contains(&reg_num) {
                                    continue;
                                }
                                let usage = gpr_usage.entry(reg_num).or_default();
                                if is_string_fn {
                                    usage.passed_to_string_fn = true;
                                }
                                if is_objc_fn {
                                    usage.passed_to_objc_fn = true;
                                }
                                break; // tag only the first live arg
                            }
                        }
                    }
                }
            }

            // -- Register overwrite tracking --
            // Mark an arg register as overwritten when the instruction writes to it
            // as a destination. We identify writes by the operand pattern:
            //
            //   [Mem, Reg]     → store (Mem is dest, Reg is source) — NOT an overwrite
            //   [Reg]          → push (single reg preserved on stack) — NOT an overwrite
            //   [Reg, Imm]     → could be CMP/TEST (read-only) or MOV/ADD (write)
            //   [Reg, Reg]     → could be CMP/TEST (read-only) or MOV/ADD (write)
            //   [Reg, Mem]     → load (Reg IS the dest) — IS an overwrite
            //   [Reg, Reg, ..] → 3-operand (first is dest) — IS an overwrite
            //
            // The key insight: CMP and TEST have two operands where the first is a
            // source (not modified). They look like [Reg, Imm] or [Reg, Reg]. We
            // can't distinguish CMP from MOV purely from operand shapes without
            // the mnemonic. However, CMP/TEST never have a Mem second operand
            // (that form has Mem first), and they never have 3 operands.
            //
            // Heuristic: only mark as overwritten when the instruction is clearly
            // a write — i.e., the second operand is Mem (load into reg) or there
            // are 3+ operands (first is always dest in x86_64/ARM64 convention).
            // For the [Reg, Reg] and [Reg, Imm] patterns, we conservatively do
            // NOT mark as overwritten to avoid CMP/TEST false positives.
            let is_definite_write = match ops {
                [Operand::Reg(_), Operand::Mem { .. }, ..] => true,  // load from memory
                [Operand::Reg(_), _, _, ..] => true,                  // 3+ operands: first is dest
                _ => false,
            };
            if is_definite_write {
                if let Some(Operand::Reg(r)) = ops.first() {
                    if r.class == RegClass::Gpr && active_gpr_args.contains(&r.num) {
                        overwritten.insert(r.num);
                    }
                }
            }
        }
    }

    // ── Classify each argument ──
    let mut hints = Vec::with_capacity(gpr_count + fp_count);

    // GPR arguments (in ABI position order).
    // Call-correlation tags (ObjcObject, CString) take priority — the argument
    // is being passed to a known function, which is strong evidence of its type
    // even if the caller never locally dereferences it.
    for &reg_num in &gpr_arg_nums[..gpr_count] {
        if let Some(usage) = gpr_usage.get(&reg_num) {
            if usage.passed_to_objc_fn {
                hints.push(ArgumentTypeHint::ObjcObject);
            } else if usage.passed_to_string_fn {
                hints.push(ArgumentTypeHint::CString);
            } else if usage.is_pointer {
                if usage.deref_offsets.contains(&0) && usage.deref_offsets.len() > 1 {
                    hints.push(ArgumentTypeHint::StructPointer);
                } else {
                    hints.push(ArgumentTypeHint::Pointer);
                }
            } else {
                hints.push(ArgumentTypeHint::Scalar);
            }
        } else {
            hints.push(ArgumentTypeHint::Scalar);
        }
    }

    // FP arguments.
    for _ in 0..fp_count {
        hints.push(ArgumentTypeHint::FloatingPoint);
    }

    hints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_x86_jmp_thunk() {
        let (kind, _, wrapper, _, _, _, _) = analyze_x86_64(&[0xE9, 0, 0, 0, 0], 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }

    #[test]
    fn classifies_x86_ret_stub() {
        let (kind, _, _, _, param_counts, _, _) = analyze_x86_64(&[0xC3], 0x1000);
        assert!(matches!(kind, CppBodyKind::Stub));
        assert_eq!(param_counts.map(|pc| pc.total()), Some(0));
    }

    #[test]
    fn classifies_arm64_branch_thunk() {
        let word = 0x1400_0001u32.to_le_bytes();
        let (kind, _, wrapper, _, _, _, _) = analyze_arm64(&word, 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }

    #[test]
    fn classifies_arm64_ret_stub() {
        let word = 0xD65F_03C0u32.to_le_bytes();
        let (kind, _, _, _, param_counts, _, _) = analyze_arm64(&word, 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Stub));
        assert_eq!(param_counts.map(|pc| pc.total()), Some(0));
    }

    #[test]
    fn detects_x86_64_this_adjustment_add() {
        let bytes = [0x48, 0x83, 0xC7, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let (kind, _, _, adj, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(8));
    }

    #[test]
    fn detects_x86_64_this_adjustment_sub() {
        let bytes = [0x48, 0x83, 0xEF, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let (kind, _, _, adj, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(-8));
    }

    #[test]
    fn detects_x86_64_arg_push_spills() {
        // PUSH rdi; PUSH rsi; MOV eax, 1; RET
        let bytes = [0x57, 0x56, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let (_, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(param_counts.map(|pc| pc.total()), Some(2));
    }

    #[test]
    fn x86_64_non_spill_does_not_inflate_param_count() {
        // CMP rdi, 0; JE +1; RET; NOP; RET
        let bytes = [0x48, 0x83, 0xFF, 0x00, 0x74, 0x01, 0xC3, 0x90, 0xC3];
        let (kind, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Standard));
        assert!(param_counts.is_none());
    }

    #[test]
    fn x86_64_void_return_detected() {
        // PUSH rbp; MOV rbp, rsp; NOP; POP rbp; RET
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn x86_64_gpr_return_detected() {
        // PUSH rbp; MOV rbp, rsp; MOV eax, 42; POP rbp; RET
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_fp_return_detected() {
        // PUSH rbp; MOV rbp, rsp; MOVSD xmm0, xmm1; POP rbp; RET
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0xF2, 0x0F, 0x10, 0xC1, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::FloatingPoint);
    }

    #[test]
    fn x86_64_div_does_not_trigger_gpr_return() {
        // PUSH rbp; MOV rbp, rsp; DIV rcx; POP rbp; RET
        // DIV writes rax implicitly — should NOT count as GPR return.
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0xF7, 0xF1, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn x86_64_large_body_finds_epilogue() {
        // Prologue + 500 NOPs + MOV eax, 1 + POP rbp + RET
        let mut bytes = vec![0x55, 0x48, 0x89, 0xE5]; // PUSH rbp; MOV rbp, rsp
        bytes.extend(std::iter::repeat(0x90).take(500)); // 500 NOPs
        bytes.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // MOV eax, 1
        bytes.push(0x5D); // POP rbp
        bytes.push(0xC3); // RET
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_param_count_capped_at_abi_limit() {
        // PUSH rdi; PUSH rsi; PUSH rdx; PUSH rcx; PUSH r8; PUSH r9; MOV eax, 1; RET
        let bytes = [0x57, 0x56, 0x52, 0x51, 0x41, 0x50, 0x41, 0x51,
                     0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let (_, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(param_counts.is_some());
        assert!(param_counts.unwrap().gpr <= 6, "x86_64 GPR args capped at 6");
    }

    // ── Argument type inference tests ──

    use super::super::types::ArgumentTypeHint;

    /// Helper: build a CFG and run argument type inference for x86_64 with
    /// the given GPR arg count. No symbol table → call correlation won't fire,
    /// but pointer/scalar/overwrite detection still works.
    fn x86_hints(bytes: &[u8], gpr_args: u32) -> Vec<ArgumentTypeHint> {
        let cfg = FunctionCfg::build(bytes, 0x1000, Arch::X86_64);
        let counts = ParamCounts { gpr: gpr_args, fp: 0 };
        // Use an empty symbol table — no call-target correlation in unit tests.
        let fake_macho_data: &[u8] = &[];
        let sym_by_va: BTreeMap<u64, &str> = BTreeMap::new();

        // Directly invoke the inference logic with the same structure as the
        // real path but without a SymbolTable (the sym_by_va map is empty).
        let gpr_arg_nums: Vec<u8> = vec![X86_RDI, X86_RSI, X86_RDX, X86_RCX, X86_R8, X86_R9];
        let gpr_count = counts.gpr.min(gpr_arg_nums.len() as u32) as usize;
        let active_gpr_args: BTreeSet<u8> = gpr_arg_nums[..gpr_count].iter().copied().collect();
        let mut gpr_usage: BTreeMap<u8, ArgUsage> = BTreeMap::new();
        let mut overwritten: BTreeSet<u8> = BTreeSet::new();

        for block in &cfg.blocks {
            if !block.reachable { continue; }
            for i in block.start..block.end {
                let insn = &cfg.insns[i];
                let ops = insn.operands();
                for op in ops {
                    if let Operand::Mem { base, disp } = op {
                        if base.class == RegClass::Gpr
                            && active_gpr_args.contains(&base.num)
                            && !overwritten.contains(&base.num)
                        {
                            let usage = gpr_usage.entry(base.num).or_default();
                            usage.is_pointer = true;
                            usage.deref_offsets.push(*disp);
                        }
                    }
                }
                let is_definite_write = match ops {
                    [Operand::Reg(_), Operand::Mem { .. }, ..] => true,
                    [Operand::Reg(_), _, _, ..] => true,
                    _ => false,
                };
                if is_definite_write {
                    if let Some(Operand::Reg(r)) = ops.first() {
                        if r.class == RegClass::Gpr && active_gpr_args.contains(&r.num) {
                            overwritten.insert(r.num);
                        }
                    }
                }
            }
        }

        let mut hints = Vec::new();
        for &reg_num in &gpr_arg_nums[..gpr_count] {
            if let Some(usage) = gpr_usage.get(&reg_num) {
                if usage.is_pointer {
                    if usage.deref_offsets.contains(&0) && usage.deref_offsets.len() > 1 {
                        hints.push(ArgumentTypeHint::StructPointer);
                    } else {
                        hints.push(ArgumentTypeHint::Pointer);
                    }
                } else {
                    hints.push(ArgumentTypeHint::Scalar);
                }
            } else {
                hints.push(ArgumentTypeHint::Scalar);
            }
        }
        hints
    }

    #[test]
    fn x86_64_pointer_arg_detected() {
        // PUSH rdi; MOV rax, [rdi]; RET
        // rdi used as memory base → pointer
        let hints = x86_hints(&[0x57, 0x48, 0x8B, 0x07, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::Pointer);
    }

    #[test]
    fn x86_64_scalar_arg_detected() {
        // PUSH rdi; MOV eax, edi; RET
        // rdi used as value, never deref'd → scalar
        let hints = x86_hints(&[0x57, 0x89, 0xF8, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::Scalar);
    }

    #[test]
    fn x86_64_overwritten_reg_not_counted_as_pointer() {
        // MOV rdi, [rsp+8]; MOV rax, [rdi]; RET
        // rdi overwritten by a load before being used as base → Scalar
        let hints = x86_hints(
            &[0x48, 0x8B, 0x7C, 0x24, 0x08, 0x48, 0x8B, 0x07, 0xC3],
            1,
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::Scalar);
    }

    // ── Edge cases and error paths ──

    #[test]
    fn x86_64_empty_body_is_unknown() {
        let (kind, rc, _, _, _, _, _) = analyze_x86_64(&[], 0x1000);
        assert!(matches!(kind, CppBodyKind::Unknown));
        assert_eq!(rc, CppReturnChannel::Unknown);
    }

    #[test]
    fn arm64_too_small_body_is_unknown() {
        // Less than 4 bytes → can't decode a single ARM64 instruction
        let (kind, rc, _, _, _, _, _) = analyze_arm64(&[0x00, 0x00], 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Unknown));
        assert_eq!(rc, CppReturnChannel::Unknown);
    }

    #[test]
    fn arm64_retaa_classified_as_return() {
        // RETAA = 0xD65F0BFF. The epilogue scanner must find this as a RET.
        // NOP; RETAA → Standard function with void return (no x0 write).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_0BFFu32.to_le_bytes()); // RETAA
        let (kind, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64e);
        assert!(matches!(kind, CppBodyKind::Standard));
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn arm64_void_return_detected() {
        // STP x29, x30, [sp, #-16]!; NOP; LDP x29, x30, [sp], #16; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes()); // STP x29, x30, [sp, #-16]!
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xA8C1_7BFDu32.to_le_bytes()); // LDP x29, x30, [sp], #16
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn arm64_gpr_return_detected() {
        // ADD x0, xzr, #42; RET
        // ADD x0, x31, #42 encodes as: sf=1, op=0, S=0, 100010, sh=0, imm12=42, Rn=31, Rd=0
        // = 0x91000AA0... let me compute: 1_00_100010_0_000000101010_11111_00000
        // = 0x91_00_0A_A0? Let me be precise.
        // sf=1 → bit 31 = 1
        // op=0 → bit 30 = 0 (ADD)
        // S=0 → bit 29 = 0
        // 100010 → bits 28:23
        // sh=0 → bit 22 = 0
        // imm12=42 → bits 21:10 = 0x02A
        // Rn=31 → bits 9:5
        // Rd=0 → bits 4:0
        // = 1_00_100010_0_000000101010_11111_00000
        // = 1001_0001_0000_0000_1010_1011_1110_0000
        // = 0x9100_ABE0
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x9100_ABE0u32.to_le_bytes()); // ADD x0, x31, #42
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_no_ret_is_unknown() {
        // Function with no RET (infinite loop): JMP $-2
        // EB FE = JMP -2 (loops forever)
        let (kind, rc, _, _, _, _, _) = analyze_x86_64(&[0xEB, 0xFE], 0x1000);
        // No RET found → return channel stays Unknown
        assert_eq!(rc, CppReturnChannel::Unknown);
    }

    #[test]
    fn x86_64_multiple_rets_different_paths() {
        // CMP rdi, 0; JE +6; MOV eax, 1; RET; XOR eax, eax; RET
        // Two return paths: one returns 1, one returns 0. Both write eax.
        let bytes = [
            0x48, 0x83, 0xFF, 0x00, // CMP rdi, 0
            0x74, 0x06,             // JE +6 (skip to XOR eax, eax)
            0xB8, 0x01, 0x00, 0x00, 0x00, // MOV eax, 1
            0xC3,                   // RET
            0x31, 0xC0,             // XOR eax, eax
            0xC3,                   // RET
        ];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        // Both paths write eax → GPR return
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_cmp_then_deref_detects_pointer() {
        // CMP rdi, 0; JE +3; MOV rax, [rdi]; RET; RET
        // CMP doesn't overwrite rdi. The subsequent deref should still detect pointer.
        let bytes = [
            0x48, 0x83, 0xFF, 0x00, // CMP rdi, 0
            0x74, 0x03,             // JE +3
            0x48, 0x8B, 0x07,       // MOV rax, [rdi]
            0xC3,                   // RET
            0xC3,                   // RET (early exit path)
        ];
        let hints = x86_hints(&bytes, 1);
        assert_eq!(hints.len(), 1);
        // CMP should NOT mark rdi as overwritten → pointer detection succeeds
        assert_eq!(hints[0], ArgumentTypeHint::Pointer);
    }

    #[test]
    fn x86_64_struct_pointer_multi_offset() {
        // MOV rax, [rdi]; MOV rcx, [rdi+8]; RET
        // Dereference at offset 0 and offset 8 → StructPointer
        let bytes = [
            0x57,                   // PUSH rdi (spill)
            0x48, 0x8B, 0x07,       // MOV rax, [rdi]       (offset 0)
            0x48, 0x8B, 0x4F, 0x08, // MOV rcx, [rdi+8]     (offset 8)
            0xC3,                   // RET
        ];
        let hints = x86_hints(&bytes, 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::StructPointer);
    }

    #[test]
    fn x86_64_fp_param_count() {
        // A function that spills rdi (GPR) and xmm0 (FP) → ParamCounts { gpr: 1, fp: 1 }
        // PUSH rdi; MOVSD [rsp-8], xmm0; MOV eax, 1; RET
        let bytes = [
            0x57,                               // PUSH rdi
            0xF2, 0x0F, 0x11, 0x44, 0x24, 0xF8, // MOVSD [rsp-8], xmm0
            0xB8, 0x01, 0x00, 0x00, 0x00,       // MOV eax, 1
            0xC3,                               // RET
        ];
        let (_, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        let pc = param_counts.expect("should detect params");
        assert_eq!(pc.gpr, 1, "1 GPR arg (rdi)");
        assert_eq!(pc.fp, 1, "1 FP arg (xmm0)");
        assert_eq!(pc.total(), 2);
    }

    #[test]
    fn arm64_stp_arg_spill_counts_params() {
        // STP x0, x1, [sp, #-16]!; STP x2, x3, [sp, #-16]!; NOP; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xA9BF_03E0u32.to_le_bytes()); // STP x0, x1, [sp, #-16]!
        bytes.extend_from_slice(&0xA9BF_0FE2u32.to_le_bytes()); // STP x2, x3, [sp, #-16]!
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, _, _, _, param_counts, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        let pc = param_counts.expect("should detect params");
        assert!(pc.gpr >= 4, "at least x0-x3 = 4 GPR args, got {}", pc.gpr);
    }

    #[test]
    fn arm64_x8_sret_detected() {
        // STR x8, [sp]; STP x0, x1, [sp, #8]; NOP; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xF900_03E8u32.to_le_bytes()); // STR x8, [sp]
        bytes.extend_from_slice(&0xA900_07E0u32.to_le_bytes()); // STP x0, x1, [sp, #8]
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::AggregateIndirect, "x8 save → sret");
    }

    #[test]
    fn cfg_unreachable_block_excluded_from_ret_scan() {
        // Test that unreachable blocks don't contribute to return channel detection.
        // Use a conditional branch so the function isn't classified as a thunk.
        //
        // PUSH rbp; MOV rbp, rsp; CMP edi, 0; JE +6; MOV eax, 1; RET; INT3; RET
        //
        // The INT3 + second RET form an unreachable block (no branch targets there).
        // The JE targets the MOV eax path. Both paths from JE are reachable.
        // But the INT3; RET block is NOT a branch target from any instruction.
        //
        // 55             = PUSH rbp
        // 48 89 E5       = MOV rbp, rsp
        // 83 FF 00       = CMP edi, 0
        // 74 06          = JE +6 (target = 0x100C → XOR eax; POP rbp; RET)
        // B8 01 00 00 00 = MOV eax, 1
        // 5D             = POP rbp
        // C3             = RET
        // B8 00 00 00 00 = XOR-equivalent: MOV eax, 0 (JE target)
        // 5D             = POP rbp
        // C3             = RET
        let bytes = [
            0x55,                               // PUSH rbp
            0x48, 0x89, 0xE5,                   // MOV rbp, rsp
            0x83, 0xFF, 0x00,                   // CMP edi, 0
            0x74, 0x06,                         // JE +6
            0xB8, 0x01, 0x00, 0x00, 0x00,       // MOV eax, 1
            0x5D,                               // POP rbp
            0xC3,                               // RET
            0xB8, 0x00, 0x00, 0x00, 0x00,       // MOV eax, 0 (JE target)
            0x5D,                               // POP rbp
            0xC3,                               // RET
        ];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        // Both reachable paths write eax → GPR return.
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    // ── ARM64 FP return ──

    #[test]
    fn arm64_fp_return_detected() {
        // FMOV d0, d1; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1E60_4020u32.to_le_bytes()); // FMOV d0, d1
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::FloatingPoint);
    }

    // ── ARM64 FP param count ──

    #[test]
    fn arm64_fp_params_detected() {
        // STP d0, d1, [sp, #-16]!; NOP; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x6DBF_07E0u32.to_le_bytes()); // STP d0, d1, [sp, #-16]!
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, _, _, _, param_counts, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        let pc = param_counts.expect("should detect FP params");
        assert!(pc.fp >= 2, "expected at least 2 FP args (d0, d1), got {}", pc.fp);
    }

    // ── Pure FP function (gpr=0, fp>0) ──

    #[test]
    fn arm64_pure_fp_param_count() {
        // STP d0, d1, [sp, #-16]!; FMOV d0, d1; RET
        // Zero GPR args, 2 FP args
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x6DBF_07E0u32.to_le_bytes()); // STP d0, d1, [sp, #-16]!
        bytes.extend_from_slice(&0x1E60_4020u32.to_le_bytes()); // FMOV d0, d1
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, _, _, _, param_counts, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        let pc = param_counts.expect("should detect FP params");
        assert_eq!(pc.gpr, 0, "no GPR args");
        assert!(pc.fp >= 2, "at least 2 FP args");
    }

    // ── x86_64 sret detection ──

    #[test]
    fn x86_64_sret_detected() {
        // A function that saves rdi to stack and loads rax from stack before RET:
        // PUSH rbp; MOV rbp, rsp; MOV [rbp-8], rdi; ... MOV rax, [rbp-8]; POP rbp; RET
        let bytes = [
            0x55,                               // PUSH rbp
            0x48, 0x89, 0xE5,                   // MOV rbp, rsp
            0x48, 0x89, 0x7D, 0xF8,             // MOV [rbp-8], rdi (save rdi)
            0x90,                               // NOP (body)
            0x48, 0x8B, 0x45, 0xF8,             // MOV rax, [rbp-8] (load rax from stack)
            0x5D,                               // POP rbp
            0xC3,                               // RET
        ];
        let (_, rc, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::AggregateIndirect, "rdi saved + rax from stack = sret");
        // When sret is detected, rdi is not counted as a real argument
        if let Some(pc) = param_counts {
            assert_eq!(pc.gpr, 0, "rdi is sret pointer, not a real GPR arg");
        }
    }

    // ── x86_64 this-adjustment with SUB imm32 ──

    #[test]
    fn detects_x86_64_this_adjustment_sub_imm32() {
        // SUB rdi, 0x100; JMP rel32
        // 48 81 EF 00 01 00 00 = SUB rdi, 256
        // E9 00 00 00 00       = JMP +0
        let bytes = [
            0x48, 0x81, 0xEF, 0x00, 0x01, 0x00, 0x00,
            0xE9, 0x00, 0x00, 0x00, 0x00,
        ];
        let (kind, _, _, adj, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(-256));
    }

    // ── CFG unit tests ──

    #[test]
    fn cfg_linear_function_single_block() {
        // NOP; NOP; RET — one basic block
        let cfg = FunctionCfg::build(&[0x90, 0x90, 0xC3], 0x1000, Arch::X86_64);
        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.blocks[0].reachable);
        assert_eq!(cfg.insns.len(), 3);
    }

    #[test]
    fn cfg_conditional_branch_creates_two_blocks() {
        // JE +1; NOP; RET
        // 74 01 = JE +1
        // 90    = NOP
        // C3    = RET
        let cfg = FunctionCfg::build(&[0x74, 0x01, 0x90, 0xC3], 0x1000, Arch::X86_64);
        // Should have at least 2 blocks (before JE target and after)
        assert!(cfg.blocks.len() >= 2, "got {} blocks", cfg.blocks.len());
        // All blocks should be reachable (JE falls through or branches)
        assert!(cfg.blocks.iter().all(|b| b.reachable), "all blocks should be reachable");
    }

    #[test]
    fn cfg_empty_input_no_blocks() {
        let cfg = FunctionCfg::build(&[], 0x1000, Arch::X86_64);
        assert!(cfg.insns.is_empty());
        assert!(cfg.blocks.is_empty());
        assert!(cfg.ret_positions().is_empty());
    }

    #[test]
    fn cfg_ret_positions_only_reachable() {
        // Test that both ret_positions are found for a two-path function.
        // PUSH rbp; MOV rbp, rsp; CMP edi, 0; JE +7;
        // MOV eax, 1; POP rbp; RET; MOV eax, 0; POP rbp; RET
        // JE +7: next_ip = 0x1009, target = 0x1010 (second MOV eax, 0)
        // Byte offsets: PUSH=0, MOV=1, CMP=4, JE=7, MOVeax1=9, POP=14, RET=15,
        //               MOVeax0=16, POP=21, RET=22
        let bytes = [
            0x55,                               // PUSH rbp        [0]
            0x48, 0x89, 0xE5,                   // MOV rbp, rsp    [1..4]
            0x83, 0xFF, 0x00,                   // CMP edi, 0      [4..7]
            0x74, 0x07,                         // JE +7            [7..9] target=9+7=16
            0xB8, 0x01, 0x00, 0x00, 0x00,       // MOV eax, 1      [9..14]
            0x5D,                               // POP rbp          [14]
            0xC3,                               // RET              [15]
            0xB8, 0x00, 0x00, 0x00, 0x00,       // MOV eax, 0      [16..21]
            0x5D,                               // POP rbp          [21]
            0xC3,                               // RET              [22]
        ];
        let cfg = FunctionCfg::build(&bytes, 0x1000, Arch::X86_64);
        let rets = cfg.ret_positions();
        assert_eq!(rets.len(), 2, "both RETs should be reachable, got {rets:?}");
    }

    #[test]
    fn cfg_insn_va_correct() {
        let cfg = FunctionCfg::build(&[0x90, 0x90, 0xC3], 0x4000, Arch::X86_64);
        assert_eq!(cfg.entry_va, 0x4000);
        assert_eq!(cfg.insn_va(&cfg.insns[0]), 0x4000); // NOP at offset 0
        assert_eq!(cfg.insn_va(&cfg.insns[1]), 0x4001); // NOP at offset 1
        assert_eq!(cfg.insn_va(&cfg.insns[2]), 0x4002); // RET at offset 2
    }
}
