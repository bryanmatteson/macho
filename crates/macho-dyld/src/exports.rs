use std::collections::HashSet;

use crate::dyld::types::{Export, ExportKind};
use crate::dyld::uleb::LebReader;
use crate::error::Result;
use crate::format::constants::*;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

/// Parse the exports trie from LC_DYLD_EXPORTS_TRIE or the export data in
/// LC_DYLD_INFO/LC_DYLD_INFO_ONLY.
pub fn parse_exports(macho: &MachoFile<'_>) -> Result<Vec<Export>> {
    fold_exports(macho, Vec::new(), |exports, export| {
        exports.push(export);
        Ok(())
    })
}

/// Fold exports in trie order without first materializing the complete export
/// set.
///
/// This performs one traversal pass over the export trie. The accumulator is
/// returned only after the complete trie has parsed successfully. If a later
/// node is malformed, the partially folded accumulator is dropped and only the
/// parse error is returned. The caller controls retained memory through the
/// accumulator and need not collect [`Export`] values.
pub fn fold_exports<State>(
    macho: &MachoFile<'_>,
    state: State,
    folder: impl FnMut(&mut State, Export) -> Result<()>,
) -> Result<State> {
    let trie_data = find_exports_data(macho)?;
    fold_export_trie(trie_data, state, folder)
}

/// Visit exports from LC_DYLD_EXPORTS_TRIE or LC_DYLD_INFO in trie order.
///
/// The complete trie is validated before the callback is invoked, so malformed
/// input returns an error without exposing a callback-visible successful
/// prefix. Callback errors are propagated immediately.
pub fn visit_exports(
    macho: &MachoFile<'_>,
    mut visitor: impl FnMut(Export) -> Result<()>,
) -> Result<()> {
    let trie_data = find_exports_data(macho)?;
    visit_export_trie(trie_data, &mut visitor)
}

/// Safety limits for trie traversal. A malformed or malicious trie can contain
/// cycles or extreme depth that would exhaust the stack; these bounds force a
/// bounded exit that surfaces as a typed error.
const MAX_TRIE_DEPTH: usize = 128;
const MAX_TRIE_NODES: usize = MAX_TRIE_DEPTH * MAX_TRIE_DEPTH;

/// Find a single export by name.
pub fn find_export(macho: &MachoFile<'_>, name: &str) -> Result<Option<Export>> {
    let trie_data = find_exports_data(macho)?;
    if trie_data.is_empty() {
        return Ok(None);
    }
    validate_export_trie(trie_data)?;
    lookup_trie(trie_data, name)
}

fn find_exports_data<'data>(macho: &MachoFile<'data>) -> Result<&'data [u8]> {
    // Prefer LC_DYLD_EXPORTS_TRIE (modern)
    if let Some(lc) = macho.find_load_command(|lc| matches!(lc, LoadCommand::DyldExportsTrie(_))) {
        if let Some(ld) = lc.kind().as_linkedit_data() {
            return Ok(macho.read_bytes_at(
                crate::model::addr::ThinFileOffset(ld.data_offset as u64),
                ld.data_size as usize,
            )?);
        }
    }

    // Fall back to LC_DYLD_INFO export data
    for lc in macho.load_commands() {
        match lc.kind() {
            LoadCommand::DyldInfo(d) | LoadCommand::DyldInfoOnly(d) if d.export_size > 0 => {
                return Ok(macho.read_bytes_at(
                    crate::model::addr::ThinFileOffset(d.export_off as u64),
                    d.export_size as usize,
                )?);
            }
            _ => {}
        }
    }

    Ok(&[])
}

fn visit_export_trie(data: &[u8], visitor: &mut impl FnMut(Export) -> Result<()>) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    // Validation is a separate pass. A single streaming pass cannot retract
    // callback side effects if a later node is malformed.
    validate_export_trie(data)?;

    fold_export_trie(data, (), |_state, export| visitor(export)).map(drop)
}

fn validate_export_trie(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    fold_export_trie(data, (), |_state, _export| Ok(())).map(drop)
}

fn fold_export_trie<State>(
    data: &[u8],
    mut state: State,
    mut folder: impl FnMut(&mut State, Export) -> Result<()>,
) -> Result<State> {
    if data.is_empty() {
        return Ok(state);
    }

    let mut prefix = String::new();
    let mut active_path = HashSet::new();
    let mut node_count = 0usize;
    walk_trie_node(
        data,
        0,
        &mut prefix,
        &mut state,
        &mut folder,
        &mut active_path,
        &mut node_count,
        0,
    )?;
    Ok(state)
}

#[allow(clippy::too_many_arguments)]
fn walk_trie_node<State>(
    data: &[u8],
    offset: usize,
    prefix: &mut String,
    state: &mut State,
    folder: &mut impl FnMut(&mut State, Export) -> Result<()>,
    active_path: &mut HashSet<usize>,
    node_count: &mut usize,
    depth: usize,
) -> Result<()> {
    if offset >= data.len() {
        return Err(crate::error::Error::format(format!(
            "export trie node offset {offset:#x} is out of bounds"
        )));
    }
    if depth > MAX_TRIE_DEPTH {
        return Err(crate::error::Error::format(
            "export trie depth exceeds safety limit",
        ));
    }
    if !active_path.insert(offset) {
        // Cycle in the trie — a well-formed trie never revisits a node.
        return Err(crate::error::Error::format(format!(
            "export trie cycle detected at offset {offset:#x}"
        )));
    }
    *node_count = node_count
        .checked_add(1)
        .ok_or_else(|| crate::error::Error::format("export trie node count overflow"))?;
    if *node_count > MAX_TRIE_NODES {
        return Err(crate::error::Error::format(
            "export trie node count exceeds safety limit",
        ));
    }

    let mut reader = LebReader::at(data, offset);

    let terminal_size = usize::try_from(reader.read_uleb128()?)
        .map_err(|_| crate::error::Error::format("export terminal size exceeds usize"))?;
    let term_start = reader.pos();
    let term_end = term_start
        .checked_add(terminal_size)
        .ok_or_else(|| crate::error::Error::format("export terminal range overflow"))?;
    if term_end > data.len() {
        return Err(crate::error::Error::format(format!(
            "export terminal at offset {term_start:#x} extends past trie data"
        )));
    }

    if terminal_size > 0 {
        let mut terminal_reader = LebReader::new(&data[term_start..term_end]);
        let flags = u32::try_from(terminal_reader.read_uleb128()?)
            .map_err(|_| crate::error::Error::format("export flags exceed u32"))?;
        let kind = decode_export_kind(&mut terminal_reader, flags)?;
        if !terminal_reader.is_empty() {
            return Err(crate::error::Error::format(
                "export terminal payload has trailing bytes",
            ));
        }
        folder(
            state,
            Export {
                name: prefix.clone(),
                flags,
                kind,
            },
        )?;
    }

    // Every node carries an edge count, including leaf nodes with zero edges.
    reader = LebReader::at(data, term_end);
    let edge_count = reader.read_u8()? as usize;
    for _ in 0..edge_count {
        let label = reader.read_string()?;
        if label.is_empty() {
            return Err(crate::error::Error::format(
                "export trie edge label cannot be empty",
            ));
        }
        let child_offset = usize::try_from(reader.read_uleb128()?)
            .map_err(|_| crate::error::Error::format("export child offset exceeds usize"))?;

        let prev_len = prefix.len();
        let next_len = prev_len
            .checked_add(label.len())
            .ok_or_else(|| crate::error::Error::format("export name length overflow"))?;
        if next_len > data.len() {
            return Err(crate::error::Error::format(
                "export name length exceeds trie data size",
            ));
        }
        prefix.push_str(label);
        walk_trie_node(
            data,
            child_offset,
            prefix,
            state,
            folder,
            active_path,
            node_count,
            depth + 1,
        )?;
        prefix.truncate(prev_len);
    }

    active_path.remove(&offset);
    Ok(())
}

fn lookup_trie(data: &[u8], name: &str) -> Result<Option<Export>> {
    let name_bytes = name.as_bytes();
    let mut offset = 0usize;
    let mut name_pos = 0usize;
    let mut visited = HashSet::new();

    loop {
        if offset >= data.len() {
            return Err(crate::error::Error::format(format!(
                "export trie node offset {offset:#x} is out of bounds"
            )));
        }
        if visited.len() > MAX_TRIE_DEPTH {
            return Err(crate::error::Error::format(
                "export trie lookup depth exceeds safety limit",
            ));
        }
        if !visited.insert(offset) {
            return Err(crate::error::Error::format(format!(
                "export trie cycle detected at offset {offset:#x}"
            )));
        }

        let mut reader = LebReader::at(data, offset);
        let terminal_size = usize::try_from(reader.read_uleb128()?)
            .map_err(|_| crate::error::Error::format("export terminal size exceeds usize"))?;
        let term_start = reader.pos();
        let term_end = term_start
            .checked_add(terminal_size)
            .ok_or_else(|| crate::error::Error::format("export terminal range overflow"))?;
        if term_end > data.len() {
            return Err(crate::error::Error::format(format!(
                "export terminal at offset {term_start:#x} extends past trie data"
            )));
        }

        if name_pos == name_bytes.len() && terminal_size > 0 {
            // We've matched the entire name and there's terminal info
            let mut terminal_reader = LebReader::new(&data[term_start..term_end]);
            let flags = u32::try_from(terminal_reader.read_uleb128()?)
                .map_err(|_| crate::error::Error::format("export flags exceed u32"))?;
            let kind = decode_export_kind(&mut terminal_reader, flags)?;
            if !terminal_reader.is_empty() {
                return Err(crate::error::Error::format(
                    "export terminal payload has trailing bytes",
                ));
            }
            return Ok(Some(Export {
                name: name.to_string(),
                flags,
                kind,
            }));
        }

        // Skip terminal info
        let mut reader = LebReader::at(data, term_end);
        let edge_count = reader.read_u8()? as usize;

        let mut matched_child = None;
        for _ in 0..edge_count {
            let label = reader.read_string()?;
            if label.is_empty() {
                return Err(crate::error::Error::format(
                    "export trie edge label cannot be empty",
                ));
            }
            let child_offset = usize::try_from(reader.read_uleb128()?)
                .map_err(|_| crate::error::Error::format("export child offset exceeds usize"))?;

            let label_bytes = label.as_bytes();
            if matched_child.is_none() && name_bytes[name_pos..].starts_with(label_bytes) {
                matched_child = Some((child_offset, label_bytes.len()));
            }
        }

        match matched_child {
            Some((child_offset, label_len)) => {
                name_pos += label_len;
                offset = child_offset;
            }
            None => return Ok(None),
        }
    }
}

fn decode_export_kind(reader: &mut LebReader<'_>, flags: u32) -> Result<ExportKind> {
    if flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0 {
        let ordinal = reader.read_uleb128()?;
        let name = reader.read_string()?;
        let name = if name.is_empty() {
            None
        } else {
            Some(name.to_string())
        };
        Ok(ExportKind::Reexport { ordinal, name })
    } else if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER != 0 {
        let stub_offset = reader.read_uleb128()?;
        let resolver_offset = reader.read_uleb128()?;
        Ok(ExportKind::StubAndResolver {
            stub_offset,
            resolver_offset,
        })
    } else {
        let address = reader.read_uleb128()?;
        let kind_bits = flags & EXPORT_SYMBOL_FLAGS_KIND_MASK;
        Ok(match kind_bits {
            EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL => ExportKind::ThreadLocal { address },
            EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE => ExportKind::Absolute { address },
            _ => ExportKind::Regular { address },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macho_with_exports_trie(trie: &[u8]) -> Vec<u8> {
        let data_offset = 32u32 + 16;
        let mut bytes = Vec::with_capacity(data_offset as usize + trie.len());

        // mach_header_64
        bytes.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        bytes.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        bytes.extend_from_slice(&CPU_SUBTYPE_X86_64_ALL.to_le_bytes());
        bytes.extend_from_slice(&MH_EXECUTE.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        // linkedit_data_command for LC_DYLD_EXPORTS_TRIE
        bytes.extend_from_slice(&LC_DYLD_EXPORTS_TRIE.to_le_bytes());
        bytes.extend_from_slice(&16u32.to_le_bytes());
        bytes.extend_from_slice(&data_offset.to_le_bytes());
        bytes.extend_from_slice(&(trie.len() as u32).to_le_bytes());
        bytes.extend_from_slice(trie);
        bytes
    }

    fn parse_fixture(bytes: &[u8]) -> MachoFile<'_> {
        crate::format::macho::parse_macho_file(bytes).unwrap()
    }

    #[test]
    fn streaming_and_collecting_exports_match_in_alias_order() {
        // Root edges `a` and `b` share one terminal node. They are aliases for
        // address 42 and must be emitted in edge order.
        let trie = [
            0, 2, b'a', 0, 8, b'b', 0, 8, // root
            2, 0, 42, 0, // shared regular-export terminal
        ];
        let bytes = macho_with_exports_trie(&trie);
        let macho = parse_fixture(&bytes);

        let mut streamed = Vec::new();
        visit_exports(&macho, |export| {
            streamed.push(export);
            Ok(())
        })
        .unwrap();
        let collected = parse_exports(&macho).unwrap();

        assert_eq!(streamed, collected);
        assert_eq!(
            streamed
                .iter()
                .map(|export| export.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(streamed.iter().all(|export| export.address() == Some(42)));
        assert_eq!(find_export(&macho, "a").unwrap(), Some(streamed[0].clone()));
        assert_eq!(find_export(&macho, "missing").unwrap(), None);
    }

    #[test]
    fn fold_exports_uses_trie_order_without_collecting_exports() {
        let trie = [
            0, 2, b'a', 0, 8, b'b', 0, 8, // root
            2, 0, 42, 0, // shared regular-export terminal
        ];
        let bytes = macho_with_exports_trie(&trie);
        let macho = parse_fixture(&bytes);

        let (count, address_sum, order_code) =
            fold_exports(&macho, (0usize, 0u64, 0u16), |summary, export| {
                summary.0 += 1;
                summary.1 += export.address().unwrap_or_default();
                summary.2 = (summary.2 << 8) | u16::from(export.name.as_bytes()[0]);
                Ok(())
            })
            .unwrap();

        assert_eq!(count, 2);
        assert_eq!(address_sum, 84);
        assert_eq!(order_code, 0x6162);
    }

    #[test]
    fn visitor_error_is_propagated_immediately() {
        let trie = [0, 1, b'a', 0, 5, 2, 0, 1, 0];
        let bytes = macho_with_exports_trie(&trie);
        let macho = parse_fixture(&bytes);
        let mut visits = 0;

        let error = visit_exports(&macho, |_export| {
            visits += 1;
            Err(crate::error::DyldError::format("visitor stopped"))
        })
        .unwrap_err();

        assert_eq!(visits, 1);
        assert_eq!(error.message(), "visitor stopped");
    }

    #[test]
    fn malformed_suffix_never_reaches_visitor_and_find_is_fail_closed() {
        // The first leaf is valid, but the second leaf contains a truncated
        // ULEB. Validation must fail before the caller sees export `a`.
        let trie = [
            0, 2, b'a', 0, 8, b'b', 0, 12, // root
            2, 0, 1, 0,    // valid leaf `a`
            0x80, // malformed leaf `b`
        ];
        let bytes = macho_with_exports_trie(&trie);
        let macho = parse_fixture(&bytes);
        let mut visits = 0;

        assert!(
            visit_exports(&macho, |_export| {
                visits += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(visits, 0);
        assert!(parse_exports(&macho).is_err());
        assert!(find_export(&macho, "a").is_err());
    }

    #[test]
    fn malformed_suffix_does_not_return_partially_folded_export_state() {
        let trie = [
            0, 2, b'a', 0, 8, b'b', 0, 12, // root
            2, 0, 1, 0,    // valid leaf `a`
            0x80, // malformed leaf `b`
        ];
        let bytes = macho_with_exports_trie(&trie);
        let macho = parse_fixture(&bytes);
        let mut folder_calls = 0usize;

        let result = fold_exports(&macho, 0usize, |count, _export| {
            folder_calls += 1;
            *count += 1;
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(folder_calls, 1);
    }

    #[test]
    fn malformed_trie_fields_are_errors() {
        let cases: &[(&str, &[u8])] = &[
            ("truncated terminal size", &[0x80]),
            ("missing edge count", &[0]),
            ("terminal payload past end", &[4, 0, 1]),
            ("terminal value crosses payload", &[1, 0, 0]),
            ("invalid label utf8", &[0, 1, 0xff, 0, 5, 0]),
            ("cycle", &[0, 1, b'a', 0, 0]),
            ("out of bounds child", &[0, 1, b'a', 0, 32]),
        ];

        for (name, trie) in cases {
            let bytes = macho_with_exports_trie(trie);
            let macho = parse_fixture(&bytes);
            assert!(parse_exports(&macho).is_err(), "case {name} succeeded");
        }
    }
}
