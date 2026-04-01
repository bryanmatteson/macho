use serde::Serialize;

use crate::error::{Error, Result};
use crate::metadata::dyld::bind::parse_bind_entries;
use crate::metadata::dyld::chained::parse_chained_fixups;
use crate::metadata::dyld::types::BindEntry;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImportRecord {
    pub name: String,
    pub lib_ordinal: i32,
    pub weak: bool,
}

pub fn collect_imports(macho: &MachoFile<'_>) -> Result<Vec<ImportRecord>> {
    if !has_chained_fixups(macho) && !has_legacy_bind_info(macho) {
        return Ok(Vec::new());
    }

    if has_chained_fixups(macho) {
        let fixups = parse_chained_fixups(macho)
            .map_err(|err| Error::Format(format!("failed to parse chained fixups: {err}")))?;
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

    let (regular, weak, lazy) = parse_bind_entries(macho)
        .map_err(|err| Error::Format(format!("failed to parse legacy bind info: {err}")))?;

    Ok(dedup_imports(
        regular
            .into_iter()
            .chain(weak)
            .chain(lazy)
            .map(into_record)
            .collect(),
    ))
}

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
    macho.load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::DyldChainedFixups(_)))
}

fn has_legacy_bind_info(macho: &MachoFile<'_>) -> bool {
    macho.load_commands().iter().any(|lc| match &lc.kind {
        LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
            data.bind_size > 0 || data.weak_bind_size > 0 || data.lazy_bind_size > 0
        }
        _ => false,
    })
}
