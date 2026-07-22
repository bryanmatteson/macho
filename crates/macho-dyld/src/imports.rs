use serde::{Deserialize, Serialize};

use crate::bind::parse_bind_entries;
use crate::chained::parse_chained_fixups;
use crate::error::Result;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::types::BindEntry;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// The ImportRecord type.
pub struct ImportRecord {
    /// The name field.
    pub name: String,
    /// The lib_ordinal field.
    pub lib_ordinal: i32,
    /// The weak field.
    pub weak: bool,
}

/// Performs collect_imports.
pub fn collect_imports(macho: &MachoFile<'_>) -> Result<Vec<ImportRecord>> {
    if !has_chained_fixups(macho) && !has_legacy_bind_info(macho) {
        return Ok(Vec::new());
    }

    if has_chained_fixups(macho) {
        let fixups = parse_chained_fixups(macho)?;
        return Ok(dedup_imports(
            fixups
                .imports
                .iter()
                .map(|imp| ImportRecord {
                    name: imp.name.to_string(),
                    lib_ordinal: imp.lib_ordinal,
                    weak: imp.weak,
                })
                .collect(),
        ));
    }

    let (regular, weak, lazy) = parse_bind_entries(macho)?;

    Ok(dedup_imports(
        regular
            .into_iter()
            .chain(weak)
            .chain(lazy)
            .map(into_record)
            .collect(),
    ))
}

/// Performs dedup_imports.
pub fn dedup_imports(mut imports: Vec<ImportRecord>) -> Vec<ImportRecord> {
    imports.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.lib_ordinal.cmp(&right.lib_ordinal))
            .then(left.weak.cmp(&right.weak))
    });
    imports.dedup_by(|left, right| {
        left.name == right.name && left.lib_ordinal == right.lib_ordinal && left.weak == right.weak
    });
    imports
}

fn into_record(bind: BindEntry) -> ImportRecord {
    ImportRecord {
        name: bind.symbol_name.to_string(),
        lib_ordinal: bind.lib_ordinal as i32,
        weak: bind.weak,
    }
}

fn has_chained_fixups(macho: &MachoFile<'_>) -> bool {
    macho
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind(), LoadCommand::DyldChainedFixups(_)))
}

fn has_legacy_bind_info(macho: &MachoFile<'_>) -> bool {
    macho.load_commands().iter().any(|lc| match lc.kind() {
        LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
            data.bind_size > 0 || data.weak_bind_size > 0 || data.lazy_bind_size > 0
        }
        _ => false,
    })
}
