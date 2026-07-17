use crate::dyld::types::{Export, ExportKind};
use crate::dyld::uleb::LebReader;
use crate::error::Result;
use crate::format::constants::*;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

/// Parse the exports trie from LC_DYLD_EXPORTS_TRIE or the export data in
/// LC_DYLD_INFO/LC_DYLD_INFO_ONLY.
pub fn parse_exports(macho: &MachoFile<'_>) -> Result<Vec<Export>> {
    let trie_data = find_exports_data(macho)?;
    if trie_data.is_empty() {
        return Ok(Vec::new());
    }

    let mut exports = Vec::new();
    let mut prefix = String::new();
    let mut visited = std::collections::HashSet::new();
    walk_trie_node(trie_data, 0, &mut prefix, &mut exports, &mut visited)?;
    Ok(exports)
}

/// Safety limits for trie traversal. A malformed or malicious trie can contain
/// cycles or extreme depth that would exhaust the stack; these bounds force a
/// bounded exit that surfaces as a typed error.
const MAX_TRIE_DEPTH: usize = 128;

/// Find a single export by name.
pub fn find_export(macho: &MachoFile<'_>, name: &str) -> Result<Option<Export>> {
    let trie_data = find_exports_data(macho)?;
    if trie_data.is_empty() {
        return Ok(None);
    }
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

fn walk_trie_node(
    data: &[u8],
    offset: usize,
    prefix: &mut String,
    exports: &mut Vec<Export>,
    visited: &mut std::collections::HashSet<usize>,
) -> Result<()> {
    if offset >= data.len() {
        return Ok(());
    }
    if !visited.insert(offset) {
        // Cycle in the trie — a well-formed trie never revisits a node.
        return Err(crate::error::Error::format(format!(
            "export trie cycle detected at offset {offset:#x}"
        )));
    }
    if visited.len() > MAX_TRIE_DEPTH * MAX_TRIE_DEPTH {
        return Err(crate::error::Error::format(
            "export trie node count exceeds safety limit",
        ));
    }

    let mut reader = LebReader::at(data, offset);

    // Read terminal info size. If reading fails (e.g. truncated trie),
    // return gracefully with whatever we have so far.
    let terminal_size = match reader.read_uleb128() {
        Ok(v) => v as usize,
        Err(_) => return Ok(()),
    };
    if terminal_size > 0 {
        let term_start = reader.pos();
        let flags = reader.read_uleb128()? as u32;
        let kind = decode_export_kind(&mut reader, flags)?;
        exports.push(Export {
            name: prefix.clone(),
            flags,
            kind,
        });
        // Skip past terminal info to the edge list
        reader = LebReader::at(data, term_start + terminal_size);
    }

    // Read edges. If no more data, this node has no children.
    let edge_count = match reader.read_u8() {
        Ok(v) => v as usize,
        Err(_) => return Ok(()),
    };
    for _ in 0..edge_count {
        let label = reader.read_string()?;
        let child_offset = reader.read_uleb128()? as usize;

        let prev_len = prefix.len();
        prefix.push_str(label);
        walk_trie_node(data, child_offset, prefix, exports, visited)?;
        prefix.truncate(prev_len);
    }

    Ok(())
}

fn lookup_trie(data: &[u8], name: &str) -> Result<Option<Export>> {
    let name_bytes = name.as_bytes();
    let mut offset = 0usize;
    let mut name_pos = 0usize;
    let mut visited = std::collections::HashSet::new();

    loop {
        if offset >= data.len() {
            return Ok(None);
        }
        if !visited.insert(offset) {
            return Err(crate::error::Error::format(format!(
                "export trie cycle detected at offset {offset:#x}"
            )));
        }

        let mut reader = LebReader::at(data, offset);
        let terminal_size = reader.read_uleb128()? as usize;

        if name_pos == name_bytes.len() && terminal_size > 0 {
            // We've matched the entire name and there's terminal info
            let flags = reader.read_uleb128()? as u32;
            let kind = decode_export_kind(&mut reader, flags)?;
            return Ok(Some(Export {
                name: name.to_string(),
                flags,
                kind,
            }));
        }

        // Skip terminal info
        let edge_start = if terminal_size > 0 {
            let term_start = reader.pos();
            term_start + terminal_size
        } else {
            reader.pos()
        };

        let mut reader = LebReader::at(data, edge_start);
        let edge_count = reader.read_u8()? as usize;

        let mut found = false;
        for _ in 0..edge_count {
            let label = reader.read_string()?;
            let child_offset = reader.read_uleb128()? as usize;

            let label_bytes = label.as_bytes();
            if name_bytes[name_pos..].starts_with(label_bytes) {
                name_pos += label_bytes.len();
                offset = child_offset;
                found = true;
                break;
            }
        }

        if !found {
            return Ok(None);
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
