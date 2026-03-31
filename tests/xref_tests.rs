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

// --- Determinism test ---

#[test]
fn range_index_deterministic() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index1 = SymbolRangeIndex::build(mach).expect("build 1");
        let index2 = SymbolRangeIndex::build(mach).expect("build 2");

        assert_eq!(index1.len(), index2.len(), "lengths differ between runs");
        for (a, b) in index1.entries().iter().zip(index2.entries().iter()) {
            assert_eq!(a.start, b.start, "start VAs differ");
            assert_eq!(a.end, b.end, "end VAs differ");
            assert_eq!(a.source, b.source, "sources differ");
            assert_eq!(a.is_alt_entry, b.is_alt_entry, "alt-entry flags differ");
        }
    }
}

#[test]
fn xref_index_deterministic() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index1 = XrefIndex::build(mach).expect("build 1");
        let index2 = XrefIndex::build(mach).expect("build 2");

        assert_eq!(index1.len(), index2.len(), "lengths differ between runs");
        for (a, b) in index1.all_refs().iter().zip(index2.all_refs().iter()) {
            assert_eq!(a.source, b.source, "source VAs differ");
            assert_eq!(a.kind, b.kind, "kinds differ");
        }
    }
}

// --- Section boundary clamping ---

#[test]
fn range_entry_ends_do_not_exceed_section_boundaries() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("build");

        // Collect section boundaries
        let mut section_ranges: Vec<(Va, Va)> = Vec::new();
        for seg in mach.segments() {
            for sect in &seg.sections {
                if sect.size > 0 {
                    section_ranges.push((sect.addr, Va(sect.addr.0 + sect.size)));
                }
            }
        }

        for entry in index.entries() {
            // Find the section this entry starts in
            let containing = section_ranges
                .iter()
                .find(|&&(start, end)| entry.start >= start && entry.start < end);
            if let Some(&(_, sect_end)) = containing {
                assert!(
                    entry.end <= sect_end,
                    "entry at {:?} has end {:?} exceeding section end {:?}",
                    entry.start,
                    entry.end,
                    sect_end
                );
            }
        }
    }
}

// --- Lookup edge cases ---

#[test]
fn range_index_lookup_va_zero_returns_none() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("build");
        // VA 0 should never be a valid owned range (we skip value==0 symbols)
        assert!(
            index.lookup_va(Va(0)).is_none(),
            "VA 0 should not be in any range"
        );
    }
}

#[test]
fn range_index_lookup_va_u64_max_returns_none() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("build");
        assert!(
            index.lookup_va(Va(u64::MAX)).is_none(),
            "VA u64::MAX should not be in any range"
        );
    }
}

// --- Stub xref validity checks ---

#[test]
fn xref_stub_source_addresses_are_nonzero() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("build");
        for xref in index.all_refs() {
            if xref.kind == XrefKind::Stub {
                assert!(
                    xref.source.0 != 0,
                    "stub xref has zero source VA"
                );
            }
        }
    }
}

// --- Direct branch targets should be reasonable ---

#[test]
fn direct_branch_targets_are_plausible() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("build");

        // Get the overall VA range from segments
        let mut min_va = u64::MAX;
        let mut max_va = 0u64;
        for seg in mach.segments() {
            if seg.vm_size > 0 {
                min_va = min_va.min(seg.vm_addr.0);
                max_va = max_va.max(seg.vm_addr.0 + seg.vm_size);
            }
        }

        if min_va >= max_va {
            continue;
        }

        let branches: Vec<_> = index
            .all_refs()
            .iter()
            .filter(|r| r.kind == XrefKind::DirectBranch)
            .collect();

        if branches.is_empty() {
            continue;
        }

        // Most branch targets should fall within the image's VA range.
        // Allow some to be out-of-range (stub targets can jump outside).
        let in_range = branches
            .iter()
            .filter(|b| {
                if let XrefTarget::Internal(va) = &b.target {
                    va.0 >= min_va && va.0 < max_va
                } else {
                    false
                }
            })
            .count();

        let ratio = in_range as f64 / branches.len() as f64;
        assert!(
            ratio > 0.5,
            "only {:.1}% of direct branch targets fall within the image VA range \
             ({} of {}), expected >50%",
            ratio * 100.0,
            in_range,
            branches.len()
        );
        return;
    }
}

// --- Empty range queries ---

#[test]
fn entries_in_range_empty_query_returns_empty() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("build");
        // Query with start == end should return empty
        let result = index.entries_in_range(Va(0x1000), Va(0x1000));
        assert!(result.is_empty(), "equal start/end should yield empty slice");
    }
}

#[test]
fn refs_in_range_empty_query_returns_empty() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = XrefIndex::build(mach).expect("build");
        let result = index.refs_in_range(Va(0x1000), Va(0x1000));
        assert!(result.is_empty(), "equal start/end should yield empty slice");
    }
}

// --- No overlapping ranges ---

#[test]
fn range_entries_do_not_overlap() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("build");
        let entries = index.entries();

        for window in entries.windows(2) {
            assert!(
                window[0].end <= window[1].start,
                "overlapping entries: [{:?}, {:?}) and [{:?}, {:?})",
                window[0].start,
                window[0].end,
                window[1].start,
                window[1].end
            );
        }
    }
}

// --- /usr/bin/grep has both range and xref coverage ---

#[test]
fn grep_range_lookup_succeeds_for_first_entry() {
    let mmap = load_binary("/usr/bin/grep");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let index = SymbolRangeIndex::build(mach).expect("build");
        if let Some(first) = index.entries().first() {
            let found = index.lookup_va(first.start);
            assert!(found.is_some());
            assert_eq!(found.unwrap().start, first.start);
            return;
        }
    }
}
