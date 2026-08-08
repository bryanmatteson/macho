use crate::dyld_cache::family::*;

pub(super) fn completeness_for(
    family: &DyldCacheFamily<'_>,
    macho: &crate::core::model::MachoFile<'_>,
) -> ReconstructionCompleteness {
    use crate::core::model::LoadCommand;

    let has_linkedit = macho
        .segments()
        .iter()
        .any(|segment| segment.name() == "__LINKEDIT");
    let has_symbols = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::Symtab(data) if data.nsyms != 0));
    let has_exports = macho
        .load_commands()
        .iter()
        .any(|command| match command.kind() {
            LoadCommand::DyldExportsTrie(data) => data.data_size != 0,
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => data.export_size != 0,
            _ => false,
        });
    let has_imports = macho
        .load_commands()
        .iter()
        .any(|command| match command.kind() {
            LoadCommand::DyldChainedFixups(data) => data.data_size != 0,
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
                data.bind_size != 0 || data.weak_bind_size != 0 || data.lazy_bind_size != 0
            }
            _ => false,
        });
    let has_fixups = macho
        .load_commands()
        .iter()
        .any(|command| match command.kind() {
            LoadCommand::DyldChainedFixups(data) => data.data_size != 0,
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
                data.rebase_size != 0 || data.bind_size != 0
            }
            _ => false,
        });
    let has_code_signature = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::CodeSignature(_)));
    let local_symbol_store = family
        .members()
        .iter()
        .find_map(|member| member.cache().local_symbols.as_ref());
    let has_external_locals = local_symbol_store.is_some()
        || family
            .members()
            .iter()
            .any(|member| member.cache().header.symbol_file_uuid != [0; 16]);
    ReconstructionCompleteness {
        segments: complete("all file-backed segments were copied from exact family VA mappings"),
        linkedit: if has_linkedit {
            complete("__LINKEDIT file bytes and retained load-command coordinates reparse")
        } else {
            absent("image declares no __LINKEDIT segment")
        },
        symbols: if has_symbols {
            match crate::core::format::parse_symbol_table(macho) {
                Ok(symbols) => complete(format!(
                    "rebuilt LC_SYMTAB parsed successfully ({} symbols)",
                    symbols.len()
                )),
                Err(error) => unresolved(format!("rebuilt LC_SYMTAB did not parse: {error}")),
            }
        } else {
            absent("image declares no nonempty LC_SYMTAB")
        },
        exports: if has_exports {
            match crate::metadata::dyld::parse_exports(macho) {
                Ok(exports) => complete(format!(
                    "retained export metadata parsed successfully ({} exports)",
                    exports.len()
                )),
                Err(error) => {
                    unresolved(format!("retained export metadata did not parse: {error}"))
                }
            }
        } else {
            absent("image declares no export trie or export stream")
        },
        imports: if has_imports {
            match crate::metadata::dyld::collect_imports(macho) {
                Ok(imports) => complete(format!(
                    "retained import metadata parsed successfully ({} imports)",
                    imports.len()
                )),
                Err(error) => {
                    unresolved(format!("retained import metadata did not parse: {error}"))
                }
            }
        } else {
            absent("image declares no bind stream or chained-import table")
        },
        fixups: if has_fixups {
            let chained = macho.load_commands().iter().any(|command| {
                matches!(command.kind(), LoadCommand::DyldChainedFixups(data) if data.data_size != 0)
            });
            if chained {
                match crate::metadata::dyld::parse_chained_fixups(macho) {
                    Ok(fixups) => complete(format!(
                        "retained chained-fixup metadata parsed successfully ({} fixups)",
                        fixups.fixups.len()
                    )),
                    Err(error) => unresolved(format!(
                        "retained chained-fixup metadata did not parse: {error}"
                    )),
                }
            } else {
                match (
                    crate::metadata::dyld::parse_rebase_entries(macho),
                    crate::metadata::dyld::parse_bind_entries(macho),
                ) {
                    (Ok(rebases), Ok((regular, weak, lazy))) => complete(format!(
                        "retained legacy fixup streams parsed successfully ({} rebases, {} binds)",
                        rebases.len(),
                        regular.len() + weak.len() + lazy.len()
                    )),
                    (Err(error), _) | (_, Err(error)) => unresolved(format!(
                        "retained legacy fixup streams did not parse: {error}"
                    )),
                }
            }
        } else {
            absent("image declares no rebase stream or chained-fixup table")
        },
        local_symbols: if has_external_locals {
            unresolved(match local_symbol_store {
                Some(store) => format!(
                    "validated cache-level local-symbol store contains {} nlists across {} image entries; those locals were not projected into LC_SYMTAB",
                    store.nlist_count,
                    store.entries.len()
                ),
                None => "cache family declares local-symbol evidence, but no validated store was available for projection".to_owned(),
            })
        } else {
            absent("cache family declares no separate local-symbol store")
        },
        code_signature: if has_code_signature {
            rejected(
                "cache-resident image signature evidence is not claimed valid for the standalone artifact",
            )
        } else {
            absent("image declares no image-level code signature")
        },
    }
}

fn complete(detail: impl Into<String>) -> ComponentCompleteness {
    component(CompletenessState::Complete, detail)
}

fn absent(detail: impl Into<String>) -> ComponentCompleteness {
    component(CompletenessState::Absent, detail)
}

fn unresolved(detail: impl Into<String>) -> ComponentCompleteness {
    component(CompletenessState::Unresolved, detail)
}

fn rejected(detail: impl Into<String>) -> ComponentCompleteness {
    component(CompletenessState::Rejected, detail)
}

fn component(state: CompletenessState, detail: impl Into<String>) -> ComponentCompleteness {
    ComponentCompleteness {
        state,
        detail: detail.into(),
    }
}
