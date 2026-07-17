/// Build a mapping from stub section VAs to imported symbol names.
///
/// When code calls an external function like `strlen`, the call target is a
/// stub entry in `__stubs`. This function reads the indirect symbol table to
/// map each stub's VA to the imported function name.
fn build_stub_map(macho: &MachoFile<'_>) -> BTreeMap<u64, String> {
    use macho_core::model::load_command::LoadCommand;
    use macho_core::model::section::SectionType;

    let mut map = BTreeMap::new();

    let symtab = match macho.ext::<SymbolTable<'_>>() {
        Ok(st) => st,
        Err(_) => return map,
    };

    let dysymtab = match macho.find_load_command(|lc| matches!(lc, LoadCommand::Dysymtab(_))) {
        Some(lc) => match lc.kind().as_dysymtab() {
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
        macho_core::model::addr::ThinFileOffset(indirect_off as u64),
        n_indirect * 4,
    ) {
        Ok(data) => data,
        Err(_) => return map,
    };

    for sect in macho.all_sections() {
        if !matches!(
            sect.section_type(),
            SectionType::SymbolStubs
                | SectionType::NonLazySymbolPointers
                | SectionType::LazySymbolPointers
        ) {
            continue;
        }

        let indirect_start = sect.reserved1() as usize;
        let entry_size = match sect.section_type() {
            SectionType::SymbolStubs => {
                if sect.reserved2() == 0 {
                    continue;
                }
                sect.reserved2() as u64
            }
            _ => {
                if macho.is_64bit() {
                    8u64
                } else {
                    4u64
                }
            }
        };

        let Some(n_entries) = sect
            .size()
            .checked_div(entry_size)
            .and_then(|count| usize::try_from(count).ok())
        else {
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
            let stub_va = sect.addr().0 + i as u64 * entry_size;
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
                        let clean = name.trim_start_matches('_').trim_start_matches('$');
                        let is_string_fn = STRING_FUNCTIONS.contains(&clean);
                        let is_objc_fn = OBJC_FUNCTIONS.contains(&clean);

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
            // Delegated to the decoder: `insn.writes_op0_reg` is ground truth
            // from iced (x86_64) / bad64-format decode (ARM64). It catches both
            // the destination-first conventions (`MOV rdi, …`, `LDR x0, …`) and
            // in-place arithmetic (`ADD rdi, rax`) that the previous
            // operand-shape heuristic missed, while still skipping `CMP`/`TEST`
            // and their ARM64 `CMP`/`CMN`/`TST` equivalents (which are
            // comparison flag-setters, not register writes to op0).
            if insn.writes_op0_reg {
                if let Some(r) = insn.op0_write_target() {
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
