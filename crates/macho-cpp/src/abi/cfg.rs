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
    /// Regions skipped by explicit heuristic recovery.
    decode_gaps: Vec<macho_insn::DecodeGap>,
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
        let report = macho_insn::decode_lossy(bytes, entry_va, arch);
        let insns: Vec<_> = report.instructions.into_iter().take(MAX_INSNS).collect();
        let mut vas = Vec::new();
        for insn in &insns {
            vas.push(entry_va + insn.offset as u64);
        }

        if insns.is_empty() {
            return Self {
                insns,
                blocks: Vec::new(),
                entry_va,
                decode_gaps: report.gaps,
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
        let va_to_idx = |target_va: u64| -> Option<usize> { vas.binary_search(&target_va).ok() };

        // Partition instructions into basic blocks.
        let mut blocks: Vec<BasicBlock> = Vec::new();
        let mut current_start = 0usize;
        for (i, va) in vas.iter().enumerate().take(insns.len()).skip(1) {
            if block_starts.contains(va) {
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
                        if let Ok(block_idx) = blocks.binary_search_by(|b| {
                            if insn_idx < b.start {
                                std::cmp::Ordering::Greater
                            } else if insn_idx >= b.end {
                                std::cmp::Ordering::Less
                            } else {
                                std::cmp::Ordering::Equal
                            }
                        }) {
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
            decode_gaps: report.gaps,
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
