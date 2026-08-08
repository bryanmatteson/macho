//! Image-bound inventory of nlist, export-trie, and dyld-import symbols.

use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::SymbolType;
use crate::metadata::dyld::ExportKind;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::{FunctionImageIdentity, FunctionIndex};

/// Explicit retention limits for one symbol inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRecoveryLimits {
    /// Maximum nlist records retained in physical table order.
    pub max_nlist_symbols: usize,
    /// Maximum export-trie records retained in canonical name order.
    pub max_exports: usize,
    /// Maximum canonical dyld import records retained.
    pub max_imports: usize,
    /// Maximum bytes retained in any symbol name.
    pub max_name_bytes: usize,
}

impl Default for SymbolRecoveryLimits {
    fn default() -> Self {
        Self {
            max_nlist_symbols: 4_000_000,
            max_exports: 4_000_000,
            max_imports: 4_000_000,
            max_name_bytes: 65_536,
        }
    }
}

impl SymbolRecoveryLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, SymbolRecoveryError> {
        if self.max_nlist_symbols == 0
            || self.max_exports == 0
            || self.max_imports == 0
            || self.max_name_bytes == 0
        {
            return Err(SymbolRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing symbol recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SymbolRecoveryError {
    /// At least one explicit limit is zero.
    #[error("symbol recovery limits must be non-zero")]
    InvalidLimits,
}

/// Mach-O authority that supplied one symbol record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolEvidenceSource {
    /// Physical `LC_SYMTAB` nlist entry.
    Nlist,
    /// Export-trie terminal.
    ExportTrie,
    /// Canonical import assembled from chained fixups or legacy bind opcodes.
    DyldImport,
}

/// Owned spelling of the Mach-O nlist type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NlistSymbolKind {
    /// Undefined symbol.
    Undefined,
    /// Absolute definition.
    Absolute,
    /// Section-backed definition.
    Section,
    /// Prebound undefined symbol.
    PreboundUndefined,
    /// Indirect symbol.
    Indirect,
    /// STAB debugging record with its exact type byte.
    Stab(u8),
    /// Unknown nlist type bits.
    Unknown(u8),
}

impl From<SymbolType> for NlistSymbolKind {
    fn from(value: SymbolType) -> Self {
        match value {
            SymbolType::Undefined => Self::Undefined,
            SymbolType::Absolute => Self::Absolute,
            SymbolType::Section => Self::Section,
            SymbolType::PreboundUndefined => Self::PreboundUndefined,
            SymbolType::Indirect => Self::Indirect,
            SymbolType::Stab(value) => Self::Stab(value),
            SymbolType::Unknown(value) => Self::Unknown(value),
        }
    }
}

/// Semantic kind and source-specific fields for one retained symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoveredSymbolKind {
    /// Exact nlist record.
    Nlist {
        /// Decoded nlist type.
        symbol_type: NlistSymbolKind,
        /// Whether `N_EXT` is present.
        external: bool,
        /// Whether `N_PEXT` is present.
        private_external: bool,
        /// One-based section ordinal, or zero when not section-backed.
        section_index: u8,
        /// Exact `n_desc` bits.
        description: u16,
    },
    /// Ordinary image-relative export.
    ExportRegular,
    /// Image-relative thread-local export.
    ExportThreadLocal,
    /// Absolute export.
    ExportAbsolute,
    /// Reexport from another dependency.
    Reexport {
        /// Export-trie library ordinal.
        library_ordinal: u64,
        /// Imported spelling when it differs from the exported name.
        imported_name: Option<String>,
    },
    /// Stub-and-resolver export.
    StubAndResolver {
        /// Resolver virtual address.
        resolver: u64,
    },
    /// Export kind introduced after this decoder's closed semantic registry.
    UnknownExport,
    /// Canonical dyld import.
    Import {
        /// Dynamic-library ordinal.
        library_ordinal: i32,
    },
}

/// One source-exact owned symbol record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredSymbol {
    /// Evidence source.
    pub source: SymbolEvidenceSource,
    /// Stable source-local ordinal.
    pub ordinal: u64,
    /// Exact symbol spelling, including an intentionally empty nlist name.
    pub name: String,
    /// Unslid virtual address when the record denotes a local definition.
    pub address: Option<u64>,
    /// Source-specific semantics.
    pub kind: RecoveredSymbolKind,
    /// Weak-definition or weak-reference state.
    pub weak: bool,
    /// Alternate-entry state from nlist.
    pub alternate_entry: bool,
}

/// Terminal state of one symbol collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolCollectorStatus {
    /// The image contains no corresponding source.
    Absent,
    /// Every parsed record was retained.
    Complete,
    /// The source was malformed and yielded no trustworthy prefix.
    Failed,
    /// At least one record was omitted by an explicit retention limit.
    Truncated,
}

/// Conservation receipt for one symbol source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolCollectorReceipt {
    /// Evidence source.
    pub source: SymbolEvidenceSource,
    /// Terminal state.
    pub status: SymbolCollectorStatus,
    /// Records examined successfully.
    pub examined: u64,
    /// Records retained.
    pub retained: u64,
    /// Records omitted by explicit limits.
    pub omitted: u64,
    /// Stable diagnostic code when incomplete.
    pub diagnostic: Option<String>,
}

/// Overall symbol-inventory status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolInventoryStatus {
    /// Every present source completed without omissions.
    Complete,
    /// At least one present source was malformed.
    Partial,
    /// At least one explicit limit omitted symbol evidence.
    Truncated,
}

/// Image-bound symbol inventory with source conservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolInventory {
    image: FunctionImageIdentity,
    limits: SymbolRecoveryLimits,
    symbols: Vec<RecoveredSymbol>,
    by_address: Vec<usize>,
    receipts: Vec<SymbolCollectorReceipt>,
    status: SymbolInventoryStatus,
}

impl SymbolInventory {
    /// Recover all nlist, export, and canonical dyld-import records.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: SymbolRecoveryLimits,
    ) -> Result<Self, SymbolRecoveryError> {
        let limits = limits.validate()?;
        let mut symbols = Vec::new();
        let mut receipts = Vec::new();
        collect_nlist(macho, limits, &mut symbols, &mut receipts);
        collect_exports(macho, limits, &mut symbols, &mut receipts);
        collect_imports(macho, limits, &mut symbols, &mut receipts);
        symbols.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.address.cmp(&right.address))
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        let mut by_address = symbols
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| symbol.address.map(|_| index))
            .collect::<Vec<_>>();
        by_address.sort_by(|left, right| {
            let left = &symbols[*left];
            let right = &symbols[*right];
            left.address
                .cmp(&right.address)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        let status = if receipts
            .iter()
            .any(|receipt| receipt.status == SymbolCollectorStatus::Truncated)
        {
            SymbolInventoryStatus::Truncated
        } else if receipts
            .iter()
            .any(|receipt| receipt.status == SymbolCollectorStatus::Failed)
        {
            SymbolInventoryStatus::Partial
        } else {
            SymbolInventoryStatus::Complete
        };
        Ok(Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            symbols,
            by_address,
            receipts,
            status,
        })
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact limits used for recovery.
    pub const fn limits(&self) -> SymbolRecoveryLimits {
        self.limits
    }

    /// All retained records in deterministic name/address/source order.
    pub fn symbols(&self) -> &[RecoveredSymbol] {
        &self.symbols
    }

    /// Per-source conservation receipts.
    pub fn receipts(&self) -> &[SymbolCollectorReceipt] {
        &self.receipts
    }

    /// Overall inventory status.
    pub const fn status(&self) -> SymbolInventoryStatus {
        self.status
    }

    /// Iterate all records with an exact spelling.
    pub fn by_name<'index>(
        &'index self,
        name: &'index str,
    ) -> impl Iterator<Item = &'index RecoveredSymbol> + 'index {
        let start = self
            .symbols
            .partition_point(|symbol| symbol.name.as_str() < name);
        let end = self
            .symbols
            .partition_point(|symbol| symbol.name.as_str() <= name);
        self.symbols[start..end].iter()
    }

    /// Iterate all records defining an exact address.
    pub fn at_address(&self, address: u64) -> impl Iterator<Item = &RecoveredSymbol> {
        let start = self
            .by_address
            .partition_point(|index| self.symbols[*index].address < Some(address));
        let end = self
            .by_address
            .partition_point(|index| self.symbols[*index].address <= Some(address));
        self.by_address[start..end]
            .iter()
            .map(|index| &self.symbols[*index])
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        let symbols_are_sorted = self.symbols.windows(2).all(|pair| {
            (
                &pair[0].name,
                pair[0].address,
                pair[0].source,
                pair[0].ordinal,
            ) < (
                &pair[1].name,
                pair[1].address,
                pair[1].source,
                pair[1].ordinal,
            )
        });
        let mut expected_by_address = self
            .symbols
            .iter()
            .enumerate()
            .filter_map(|(index, symbol)| symbol.address.map(|_| index))
            .collect::<Vec<_>>();
        expected_by_address.sort_by(|left, right| {
            let left = &self.symbols[*left];
            let right = &self.symbols[*right];
            left.address
                .cmp(&right.address)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        let sources_are_canonical = self.receipts.iter().map(|receipt| receipt.source).eq([
            SymbolEvidenceSource::Nlist,
            SymbolEvidenceSource::ExportTrie,
            SymbolEvidenceSource::DyldImport,
        ]);
        let receipts_are_valid = self.receipts.iter().all(|receipt| {
            let actual = self
                .symbols
                .iter()
                .filter(|symbol| symbol.source == receipt.source)
                .count() as u64;
            receipt.retained == actual
                && match receipt.status {
                    SymbolCollectorStatus::Absent => {
                        receipt.examined == 0
                            && receipt.retained == 0
                            && receipt.omitted == 0
                            && receipt.diagnostic.is_none()
                    }
                    SymbolCollectorStatus::Complete => {
                        receipt.examined == receipt.retained
                            && receipt.omitted == 0
                            && receipt.diagnostic.is_none()
                    }
                    SymbolCollectorStatus::Failed => {
                        let expected = match receipt.source {
                            SymbolEvidenceSource::Nlist => "symbols.nlist_malformed",
                            SymbolEvidenceSource::ExportTrie => "symbols.exports_malformed",
                            SymbolEvidenceSource::DyldImport => "symbols.imports_malformed",
                        };
                        receipt.retained == 0 && receipt.diagnostic.as_deref() == Some(expected)
                    }
                    SymbolCollectorStatus::Truncated => {
                        receipt.omitted != 0
                            && receipt.examined == receipt.retained.saturating_add(receipt.omitted)
                            && receipt.diagnostic.as_deref() == Some("symbols.retention_budget")
                    }
                }
        });
        let symbols_are_well_formed = self.symbols.iter().all(|symbol| {
            let kind_matches_source = matches!(
                (symbol.source, &symbol.kind),
                (
                    SymbolEvidenceSource::Nlist,
                    RecoveredSymbolKind::Nlist { .. }
                ) | (
                    SymbolEvidenceSource::ExportTrie,
                    RecoveredSymbolKind::ExportRegular
                        | RecoveredSymbolKind::ExportThreadLocal
                        | RecoveredSymbolKind::ExportAbsolute
                        | RecoveredSymbolKind::Reexport { .. }
                        | RecoveredSymbolKind::StubAndResolver { .. }
                        | RecoveredSymbolKind::UnknownExport
                ) | (
                    SymbolEvidenceSource::DyldImport,
                    RecoveredSymbolKind::Import { .. }
                )
            );
            let imported_name_is_bounded = match &symbol.kind {
                RecoveredSymbolKind::Reexport { imported_name, .. } => imported_name
                    .as_ref()
                    .is_none_or(|name| name.len() <= self.limits.max_name_bytes),
                _ => true,
            };
            symbol.name.len() <= self.limits.max_name_bytes
                && kind_matches_source
                && imported_name_is_bounded
                && (!matches!(symbol.kind, RecoveredSymbolKind::Import { .. })
                    || symbol.address.is_none())
                && (symbol.source == SymbolEvidenceSource::Nlist || !symbol.alternate_entry)
        });
        let source_ordinals_are_unique = self
            .symbols
            .iter()
            .map(|symbol| (symbol.source, symbol.ordinal))
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == self.symbols.len();
        let retained_for = |source| {
            self.symbols
                .iter()
                .filter(|symbol| symbol.source == source)
                .count()
        };
        let expected_status = if self
            .receipts
            .iter()
            .any(|receipt| receipt.status == SymbolCollectorStatus::Truncated)
        {
            SymbolInventoryStatus::Truncated
        } else if self
            .receipts
            .iter()
            .any(|receipt| receipt.status == SymbolCollectorStatus::Failed)
        {
            SymbolInventoryStatus::Partial
        } else {
            SymbolInventoryStatus::Complete
        };
        self.limits.validate().is_ok()
            && symbols_are_sorted
            && self.by_address == expected_by_address
            && sources_are_canonical
            && receipts_are_valid
            && symbols_are_well_formed
            && source_ordinals_are_unique
            && retained_for(SymbolEvidenceSource::Nlist) <= self.limits.max_nlist_symbols
            && retained_for(SymbolEvidenceSource::ExportTrie) <= self.limits.max_exports
            && retained_for(SymbolEvidenceSource::DyldImport) <= self.limits.max_imports
            && self.status == expected_status
    }

    /// Find the recovered function identity associated with one symbol record.
    pub fn function_for<'index>(
        &self,
        symbol: &RecoveredSymbol,
        functions: &'index FunctionIndex,
    ) -> Option<&'index crate::analysis::functions::RecoveredFunction> {
        (functions.image() == self.image())
            .then_some(symbol.address)
            .flatten()
            .and_then(|address| functions.by_entry(address))
    }
}

fn collect_nlist(
    macho: &MachoFile<'_>,
    limits: SymbolRecoveryLimits,
    symbols: &mut Vec<RecoveredSymbol>,
    receipts: &mut Vec<SymbolCollectorReceipt>,
) {
    let present = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::Symtab(_)));
    if !present {
        receipts.push(absent(SymbolEvidenceSource::Nlist));
        return;
    }
    let mut collected = Vec::new();
    let mut examined = 0_u64;
    let mut omitted = 0_u64;
    let result = crate::core::format::fold_symbols(macho, (), |_, symbol| {
        examined = examined.saturating_add(1);
        if symbol.name.len() > limits.max_name_bytes || examined as usize > limits.max_nlist_symbols
        {
            omitted = omitted.saturating_add(1);
            return Ok(());
        }
        collected.push(RecoveredSymbol {
            source: SymbolEvidenceSource::Nlist,
            ordinal: symbol.index as u64,
            name: symbol.name.to_owned(),
            address: symbol.is_defined().then_some(symbol.value),
            kind: RecoveredSymbolKind::Nlist {
                symbol_type: symbol.sym_type.into(),
                external: symbol.external,
                private_external: symbol.private_external,
                section_index: symbol.section_index,
                description: symbol.desc,
            },
            weak: symbol.is_weak_def() || symbol.is_weak_ref(),
            alternate_entry: symbol.is_alt_entry(),
        });
        Ok(())
    });
    let retained = if result.is_ok() {
        let retained = collected.len();
        symbols.extend(collected);
        retained
    } else {
        0
    };
    finish_receipt(
        SymbolEvidenceSource::Nlist,
        result.is_ok(),
        examined,
        retained,
        omitted,
        "symbols.nlist_malformed",
        receipts,
    );
}

fn collect_exports(
    macho: &MachoFile<'_>,
    limits: SymbolRecoveryLimits,
    symbols: &mut Vec<RecoveredSymbol>,
    receipts: &mut Vec<SymbolCollectorReceipt>,
) {
    let present = macho
        .load_commands()
        .iter()
        .any(|command| match command.kind() {
            LoadCommand::DyldExportsTrie(data) => data.data_size > 0,
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => data.export_size > 0,
            _ => false,
        });
    if !present {
        receipts.push(absent(SymbolEvidenceSource::ExportTrie));
        return;
    }
    let mut collected = Vec::new();
    let mut examined = 0_u64;
    let mut omitted = 0_u64;
    let image_base = macho.image_base().0;
    let result = crate::metadata::dyld::fold_exports(macho, (), |_, export| {
        let ordinal = examined;
        examined = examined.saturating_add(1);
        let imported_name_too_long = matches!(
            &export.kind,
            ExportKind::Reexport {
                name: Some(name),
                ..
            } if name.len() > limits.max_name_bytes
        );
        if export.name.len() > limits.max_name_bytes
            || imported_name_too_long
            || examined as usize > limits.max_exports
        {
            omitted = omitted.saturating_add(1);
            return Ok(());
        }
        let weak = export.is_weak();
        let (address, kind) = match export.kind {
            ExportKind::Regular { address } => (
                Some(image_base.checked_add(address).ok_or_else(|| {
                    crate::metadata::dyld::DyldError::address("export address overflows")
                })?),
                RecoveredSymbolKind::ExportRegular,
            ),
            ExportKind::ThreadLocal { address } => (
                Some(image_base.checked_add(address).ok_or_else(|| {
                    crate::metadata::dyld::DyldError::address(
                        "thread-local export address overflows",
                    )
                })?),
                RecoveredSymbolKind::ExportThreadLocal,
            ),
            ExportKind::Absolute { address } => {
                (Some(address), RecoveredSymbolKind::ExportAbsolute)
            }
            ExportKind::Reexport { ordinal, name } => (
                None,
                RecoveredSymbolKind::Reexport {
                    library_ordinal: ordinal,
                    imported_name: name,
                },
            ),
            ExportKind::StubAndResolver {
                stub_offset,
                resolver_offset,
            } => (
                Some(image_base.checked_add(stub_offset).ok_or_else(|| {
                    crate::metadata::dyld::DyldError::address("export stub address overflows")
                })?),
                RecoveredSymbolKind::StubAndResolver {
                    resolver: image_base.checked_add(resolver_offset).ok_or_else(|| {
                        crate::metadata::dyld::DyldError::address(
                            "export resolver address overflows",
                        )
                    })?,
                },
            ),
            _ => (None, RecoveredSymbolKind::UnknownExport),
        };
        collected.push(RecoveredSymbol {
            source: SymbolEvidenceSource::ExportTrie,
            ordinal,
            name: export.name,
            address,
            kind,
            weak,
            alternate_entry: false,
        });
        Ok(())
    });
    let retained = if result.is_ok() {
        let retained = collected.len();
        symbols.extend(collected);
        retained
    } else {
        0
    };
    finish_receipt(
        SymbolEvidenceSource::ExportTrie,
        result.is_ok(),
        examined,
        retained,
        omitted,
        "symbols.exports_malformed",
        receipts,
    );
}

fn collect_imports(
    macho: &MachoFile<'_>,
    limits: SymbolRecoveryLimits,
    symbols: &mut Vec<RecoveredSymbol>,
    receipts: &mut Vec<SymbolCollectorReceipt>,
) {
    let present = macho.load_commands().iter().any(|command| {
        matches!(
            command.kind(),
            LoadCommand::DyldChainedFixups(_)
                | LoadCommand::DyldInfo(_)
                | LoadCommand::DyldInfoOnly(_)
        )
    });
    if !present {
        receipts.push(absent(SymbolEvidenceSource::DyldImport));
        return;
    }
    let start = symbols.len();
    match crate::metadata::dyld::collect_imports(macho) {
        Ok(imports) => {
            let examined = imports.len() as u64;
            let mut omitted = 0_u64;
            for (ordinal, import) in imports.into_iter().enumerate() {
                if import.name.len() > limits.max_name_bytes || ordinal >= limits.max_imports {
                    omitted = omitted.saturating_add(1);
                    continue;
                }
                symbols.push(RecoveredSymbol {
                    source: SymbolEvidenceSource::DyldImport,
                    ordinal: ordinal as u64,
                    name: import.name,
                    address: None,
                    kind: RecoveredSymbolKind::Import {
                        library_ordinal: import.lib_ordinal,
                    },
                    weak: import.weak,
                    alternate_entry: false,
                });
            }
            finish_receipt(
                SymbolEvidenceSource::DyldImport,
                true,
                examined,
                symbols.len() - start,
                omitted,
                "symbols.imports_malformed",
                receipts,
            );
        }
        Err(_) => finish_receipt(
            SymbolEvidenceSource::DyldImport,
            false,
            0,
            0,
            0,
            "symbols.imports_malformed",
            receipts,
        ),
    }
}

fn absent(source: SymbolEvidenceSource) -> SymbolCollectorReceipt {
    SymbolCollectorReceipt {
        source,
        status: SymbolCollectorStatus::Absent,
        examined: 0,
        retained: 0,
        omitted: 0,
        diagnostic: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_receipt(
    source: SymbolEvidenceSource,
    succeeded: bool,
    examined: u64,
    retained: usize,
    omitted: u64,
    failure: &str,
    receipts: &mut Vec<SymbolCollectorReceipt>,
) {
    let status = if !succeeded {
        SymbolCollectorStatus::Failed
    } else if omitted != 0 {
        SymbolCollectorStatus::Truncated
    } else {
        SymbolCollectorStatus::Complete
    };
    receipts.push(SymbolCollectorReceipt {
        source,
        status,
        examined,
        retained: retained as u64,
        omitted,
        diagnostic: match status {
            SymbolCollectorStatus::Failed => Some(failure.to_owned()),
            SymbolCollectorStatus::Truncated => Some("symbols.retention_budget".to_owned()),
            SymbolCollectorStatus::Absent | SymbolCollectorStatus::Complete => None,
        },
    });
}

#[cfg(test)]
mod tests {
    use crate::core::model::container::MachoContainer;

    use super::*;

    fn image(bytes: &[u8]) -> MachoFile<'_> {
        match crate::core::parse(bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        }
    }

    fn reexport_fixture(imported_name: &str) -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        let exported_name = "_alias";
        let child_offset = 2 + exported_name.len() + 2;
        let mut payload = vec![0x08, 0x01];
        payload.extend_from_slice(imported_name.as_bytes());
        payload.push(0);
        let mut trie = vec![0, 1];
        trie.extend_from_slice(exported_name.as_bytes());
        trie.push(0);
        trie.push(child_offset as u8);
        trie.push(payload.len() as u8);
        trie.extend_from_slice(&payload);
        trie.push(0);

        let command_offset = 32 + 72 + 80 + 24;
        let trie_offset = bytes.len();
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x8000_0033_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(trie_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16]
            .copy_from_slice(&(trie.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&trie);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
        bytes
    }

    #[test]
    fn inventory_retains_nlist_and_reports_other_sources_absent() {
        let bytes = macho_test_support::disassembly_x86_64();
        let inventory =
            SymbolInventory::recover(&image(&bytes), SymbolRecoveryLimits::default()).unwrap();
        assert!(inventory.durable_invariants_hold());
        assert_eq!(inventory.receipts().len(), 3);
        assert_eq!(inventory.status(), SymbolInventoryStatus::Complete);
    }

    #[test]
    fn reexport_imported_name_obeys_the_per_name_limit() {
        let bytes = reexport_fixture("_an_imported_name_that_exceeds_the_limit");
        let inventory = SymbolInventory::recover(
            &image(&bytes),
            SymbolRecoveryLimits {
                max_name_bytes: 8,
                ..SymbolRecoveryLimits::default()
            },
        )
        .unwrap();
        assert!(inventory.durable_invariants_hold());
        assert_eq!(inventory.status(), SymbolInventoryStatus::Truncated);
        let receipt = inventory
            .receipts()
            .iter()
            .find(|receipt| receipt.source == SymbolEvidenceSource::ExportTrie)
            .unwrap();
        assert_eq!(receipt.omitted, 1);
        assert!(!inventory.symbols().iter().any(|symbol| {
            matches!(
                &symbol.kind,
                RecoveredSymbolKind::Reexport {
                    imported_name: Some(name),
                    ..
                } if name.len() > 8
            )
        }));
    }
}
