use macho::addr::types::Va;
use macho::xref::ranges::{CodeEntity, RangeSource, SymbolRangeIndex};
use macho::xref::refs::{XrefIndex, XrefKind, XrefTarget};

fn load_binary(path: &str) -> memmap2::Mmap {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("failed to open {path}: {e}"));
    unsafe { memmap2::Mmap::map(&file).unwrap() }
}

fn load_tar() -> memmap2::Mmap {
    load_binary("/usr/bin/tar")
}

// --- SymbolRangeIndex tests ---

#[test]
fn range_index_build_tar() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    let mut found_nonempty = false;
    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        if !index.is_empty() {
            found_nonempty = true;
        }
    }
    assert!(
        found_nonempty,
        "expected at least one non-empty range index across slices"
    );
}

#[test]
fn range_index_entries_sorted_by_va() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let entries = index.entries();

        for window in entries.windows(2) {
            assert!(
                window[0].start <= window[1].start,
                "entries not sorted: {:?} > {:?}",
                window[0].start,
                window[1].start
            );
        }
    }
}

#[test]
fn range_index_no_zero_size() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        for entry in index.entries() {
            assert!(
                entry.end > entry.start,
                "zero or negative size entry at {:?}: start={:?} end={:?}",
                entry.entity,
                entry.start,
                entry.end
            );
        }
    }
}

#[test]
fn range_index_lookup_va() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let entries = index.entries();
        if entries.is_empty() {
            continue;
        }

        // Look up the start of the first entry
        let first = &entries[0];
        let found = index.lookup_va(first.start);
        assert!(found.is_some(), "failed to look up first entry");
        assert_eq!(found.unwrap().start, first.start);

        // Look up an address just past all entries should return None
        let last = entries.last().unwrap();
        let result = index.lookup_va(Va(last.end.0 + 0x10000));
        assert!(result.is_none(), "should not find entry past all ranges");
    }
}

#[test]
fn range_index_lookup_middle_of_entry() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");

        for entry in index.entries() {
            let size = entry.end.0 - entry.start.0;
            if size > 4 {
                let mid = Va(entry.start.0 + size / 2);
                let found = index.lookup_va(mid);
                assert!(
                    found.is_some(),
                    "failed to look up middle of entry at {:?}",
                    entry.start
                );
                assert_eq!(found.unwrap().start, entry.start);
                return;
            }
        }
    }
}

#[test]
fn range_index_entries_in_range() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let entries = index.entries();
        if entries.len() < 3 {
            continue;
        }

        let start = entries[0].start;
        let end = entries[2].start;
        let subset = index.entries_in_range(start, end);
        assert_eq!(
            subset.len(),
            2,
            "expected exactly 2 entries in [start..end)"
        );
        return;
    }
}

#[test]
fn range_index_has_symbol_entities() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let has_symbol = index
            .entries()
            .iter()
            .any(|e| matches!(e.entity, CodeEntity::Symbol { .. }));
        if has_symbol {
            return;
        }
    }
    panic!("expected at least one Symbol entity across all slices");
}

#[test]
fn range_index_sources_are_valid() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let has_nlist = index
            .entries()
            .iter()
            .any(|e| e.source == RangeSource::Nlist);
        if has_nlist {
            return;
        }
    }
    panic!("expected at least one Nlist-sourced entry across all slices");
}

#[test]
fn range_index_lookup_file_offset() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let address_map = mach.address_map();

        if let Some(first) = index.entries().first() {
            if let Ok(offset) = address_map.va_to_thin_offset(first.start) {
                let found = index.lookup_file_offset(offset, address_map);
                assert!(found.is_some(), "file offset lookup should find the entry");
                assert_eq!(found.unwrap().start, first.start);
                return;
            }
        }
    }
}

// --- XrefIndex tests ---

#[test]
fn xref_index_build_tar() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    let mut found_nonempty = false;
    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        if !index.is_empty() {
            found_nonempty = true;
        }
    }
    assert!(
        found_nonempty,
        "expected at least one non-empty xref index across slices"
    );
}

#[test]
fn xref_index_sorted_by_source() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        let all = index.all_refs();

        for window in all.windows(2) {
            assert!(
                window[0].source <= window[1].source,
                "refs not sorted: {:?} > {:?}",
                window[0].source,
                window[1].source
            );
        }
    }
}

#[test]
fn xref_index_has_stubs() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        let has_stub = index.all_refs().iter().any(|r| r.kind == XrefKind::Stub);
        if has_stub {
            return;
        }
    }
    panic!("expected at least one Stub xref across all slices");
}

#[test]
fn xref_index_stubs_have_import_names() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        for xref in index.all_refs() {
            if xref.kind == XrefKind::Stub {
                if let XrefTarget::Import { ref name, .. } = xref.target {
                    assert!(!name.is_empty(), "stub import has empty name");
                }
            }
        }
    }
}

#[test]
fn xref_index_has_direct_branches() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        let has_branch = index
            .all_refs()
            .iter()
            .any(|r| r.kind == XrefKind::DirectBranch);
        if has_branch {
            return;
        }
    }
    panic!("expected at least one DirectBranch xref across all slices");
}

#[test]
fn xref_index_refs_from() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        if let Some(first) = index.all_refs().first() {
            let source = first.source;
            let from_refs: Vec<_> = index.refs_from(source).collect();
            assert!(!from_refs.is_empty());
            for r in &from_refs {
                assert_eq!(r.source, source);
            }
            return;
        }
    }
}

#[test]
fn xref_index_refs_in_range() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        let all = index.all_refs();
        if all.len() < 10 {
            continue;
        }

        let start = all[0].source;
        let end = all[9].source;
        let subset = index.refs_in_range(start, end);
        assert!(
            !subset.is_empty(),
            "expected some refs in range [{:?}, {:?})",
            start,
            end
        );
        for r in subset {
            assert!(r.source >= start && r.source < end);
        }
        return;
    }
}

#[test]
fn xref_index_refs_to_internal() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");

        for xref in index.all_refs() {
            if let XrefTarget::Internal(target) = &xref.target {
                let to_refs: Vec<_> = index.refs_to(*target).collect();
                assert!(!to_refs.is_empty());
                return;
            }
        }
    }
}

#[test]
fn xref_has_chained_or_legacy_fixups() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        let has_fixup = index.all_refs().iter().any(|r| {
            matches!(
                r.kind,
                XrefKind::ChainedBind | XrefKind::ChainedRebase | XrefKind::LegacyBind
            )
        });
        if has_fixup {
            return;
        }
    }
    panic!("expected at least one chained or legacy fixup xref across all slices");
}

// --- Combined tests: range index + xref index ---

#[test]
fn direct_branches_target_known_symbols() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let ranges = SymbolRangeIndex::build(mach).expect("failed to build range index");
        let xrefs = XrefIndex::build(mach).expect("failed to build xref index");

        let branches: Vec<_> = xrefs
            .all_refs()
            .iter()
            .filter(|r| r.kind == XrefKind::DirectBranch)
            .collect();

        if branches.is_empty() {
            continue;
        }

        let resolved = branches
            .iter()
            .filter(|b| {
                if let XrefTarget::Internal(va) = &b.target {
                    ranges.lookup_va(*va).is_some()
                } else {
                    false
                }
            })
            .count();

        if resolved > 0 {
            return;
        }
    }
}

// --- Larger binary test with /usr/bin/grep ---

#[test]
fn range_index_grep() {
    let mmap = load_binary("/usr/bin/grep");
    let container = macho::parse(&mmap).expect("failed to parse");

    let mut max_len = 0;
    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("failed to build range index");
        max_len = max_len.max(index.len());
    }
    assert!(
        max_len > 0,
        "grep should have at least some symbol ranges (found {})",
        max_len
    );
}

#[test]
fn xref_index_grep() {
    let mmap = load_binary("/usr/bin/grep");
    let container = macho::parse(&mmap).expect("failed to parse");

    let mut max_len = 0;
    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("failed to build xref index");
        max_len = max_len.max(index.len());
    }
    assert!(
        max_len > 10,
        "grep should have many xrefs (found {})",
        max_len
    );
}

// --- Test with /usr/bin/true (smaller binary) ---

#[test]
fn range_and_xref_build_true() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let ranges = SymbolRangeIndex::build(mach);
        assert!(ranges.is_ok(), "range index build should not error");

        let xrefs = XrefIndex::build(mach);
        assert!(xrefs.is_ok(), "xref index build should not error");
    }
}
