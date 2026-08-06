use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::SymbolType;
use crate::metadata::dyld::ExportKind;

use crate::analysis::report::disassembly::{DisassemblyIssue, DisassemblyLabel, SymbolSource};

use super::DisassemblyError;
use super::section_index::SectionIndex;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Observation {
    pub(crate) va: u64,
    pub(crate) source: SymbolSource,
    pub(crate) raw_name: String,
    pub(crate) display_name: String,
    pub(crate) segment: Option<String>,
    pub(crate) section: Option<String>,
}

impl Observation {
    pub(crate) fn label(&self) -> DisassemblyLabel {
        DisassemblyLabel {
            va: self.va,
            raw_name: self.raw_name.clone(),
            display_name: self.display_name.clone(),
            source: self.source,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Metadata<'macho> {
    pub(crate) retained: Vec<Observation>,
    pub(crate) requested: BTreeMap<String, Vec<Observation>>,
    pub(crate) requested_non_code: BTreeSet<String>,
    pub(crate) truncated: bool,
    pub(crate) issues: Vec<DisassemblyIssue>,
    next_by_start: BTreeMap<u64, Observation>,
    requested_by_section: BTreeMap<(String, String), BTreeMap<u64, Observation>>,
    retained_keys: BTreeSet<(u64, SymbolSource, String)>,
    target_owners: BTreeMap<String, BTreeMap<String, BTreeMap<u64, usize>>>,
    sections: SectionIndex<'macho>,
    carried_section_queries: u64,
    boundary_queries: Cell<u64>,
    label_range_queries: Cell<u64>,
    target_owner_queries: Cell<u64>,
    pub(crate) traversals: [u64; 3],
    pub(crate) observations_visited: [u64; 3],
    pub(crate) name_bytes_visited: [u64; 3],
}

impl<'macho> Metadata<'macho> {
    fn new(macho: &'macho MachoFile<'_>) -> Self {
        Self {
            retained: Vec::new(),
            requested: BTreeMap::new(),
            requested_non_code: BTreeSet::new(),
            truncated: false,
            issues: Vec::new(),
            next_by_start: BTreeMap::new(),
            requested_by_section: BTreeMap::new(),
            retained_keys: BTreeSet::new(),
            target_owners: BTreeMap::new(),
            sections: SectionIndex::new(macho),
            carried_section_queries: 0,
            boundary_queries: Cell::new(0),
            label_range_queries: Cell::new(0),
            target_owner_queries: Cell::new(0),
            traversals: [0; 3],
            observations_visited: [0; 3],
            name_bytes_visited: [0; 3],
        }
    }

    fn record_traversal(&mut self, source: SymbolSource) {
        self.traversals[source_index(source)] += 1;
    }

    fn record_visit(&mut self, source: SymbolSource, raw_name: &str) {
        let index = source_index(source);
        self.observations_visited[index] += 1;
        self.name_bytes_visited[index] += raw_name.len() as u64;
    }

    fn observe_requested(&mut self, observation: Observation, requested: &BTreeSet<&str>) {
        if observation.source == SymbolSource::ObjcMetadata
            || !requested.contains(observation.raw_name.as_str())
        {
            return;
        }
        let observation_va = observation.va;
        let matches = self
            .requested
            .entry(observation.raw_name.clone())
            .or_default();
        if let Some(existing) = matches.iter_mut().find(|item| item.va == observation.va) {
            if (observation.source, &observation.raw_name) < (existing.source, &existing.raw_name) {
                *existing = observation.clone();
            }
        } else if matches.len() < 2 {
            // Two distinct addresses are sufficient to prove ambiguity while
            // keeping selector evidence bounded by the requested-name budget.
            matches.push(observation);
        }
        let selected = matches
            .iter()
            .find(|item| item.va == observation_va)
            .cloned();
        if let Some(selected) = selected
            && let (Some(segment), Some(section)) =
                (selected.segment.clone(), selected.section.clone())
        {
            self.requested_by_section
                .entry((segment, section))
                .or_default()
                .entry(selected.va)
                .and_modify(|current| {
                    if (selected.source, &selected.raw_name) < (current.source, &current.raw_name) {
                        *current = selected.clone();
                    }
                })
                .or_insert(selected);
        }
    }

    fn reserve_requested(&mut self, max: usize) {
        for matches in self.requested.values() {
            let Some(observation) = matches.iter().min().cloned() else {
                continue;
            };
            let key = observation_key(&observation);
            if self.retained.len() < max && self.retained_keys.insert(key) {
                self.retained.push(observation);
            }
        }
    }

    fn push(&mut self, observation: Observation, max: usize) {
        self.record_visit(observation.source, &observation.raw_name);
        self.push_recorded(observation, max);
    }

    fn push_recorded(&mut self, observation: Observation, max: usize) {
        self.consider_boundary(&observation);
        let key = observation_key(&observation);
        if self.retained_keys.contains(&key) {
            return;
        }
        if self.retained.len() < max {
            self.retained_keys.insert(key);
            self.retained.push(observation);
        } else {
            self.truncated = true;
        }
    }

    fn consider_boundary(&mut self, candidate: &Observation) {
        let (Some(segment), Some(section)) = (&candidate.segment, &candidate.section) else {
            return;
        };
        let Some(starts) = self
            .requested_by_section
            .get(&(segment.clone(), section.clone()))
        else {
            return;
        };
        let Some((&start, _)) = starts.range(..candidate.va).next_back() else {
            return;
        };
        let replace = self.next_by_start.get(&start).is_none_or(|current| {
            (candidate.va, candidate.source, &candidate.raw_name)
                < (current.va, current.source, &current.raw_name)
        });
        if replace {
            self.next_by_start.insert(start, candidate.clone());
        }
    }

    pub(crate) fn next_boundary(&self, start: u64) -> Option<&Observation> {
        self.boundary_queries.set(self.boundary_queries.get() + 1);
        self.next_by_start.get(&start)
    }

    pub(crate) fn target_owner(&self, target: u64) -> Option<&Observation> {
        self.target_owner_queries
            .set(self.target_owner_queries.get() + 1);
        let section = self.sections.find(target)?;
        let index = self
            .target_owners
            .get(&section.segment_name().to_string())?
            .get(&section.section_name().to_string())?
            .range(..=target)
            .next_back()?
            .1;
        self.retained.get(*index)
    }

    pub(crate) fn find_file_section(
        &self,
        va: u64,
    ) -> Option<&'macho crate::core::model::section::Section> {
        self.sections.find_file_backed(va)
    }

    pub(crate) fn named_section(
        &self,
        segment: &str,
        section: &str,
    ) -> Option<&'macho crate::core::model::section::Section> {
        self.sections.named(segment, section)
    }

    pub(crate) fn has_objc_roots(&self) -> bool {
        self.sections.has_objc_roots()
    }

    pub(crate) fn labels_between(&self, start: u64, end: u64) -> Vec<DisassemblyLabel> {
        self.label_range_queries
            .set(self.label_range_queries.get() + 1);
        let first = self.retained.partition_point(|item| item.va < start);
        let last = self.retained.partition_point(|item| item.va < end);
        self.retained[first..last]
            .iter()
            .map(Observation::label)
            .collect()
    }

    /// Retained labels whose VA is exactly `va`, in retained (sorted) order.
    ///
    /// Used by the streaming path to emit label lines inline before the record
    /// at that VA. Point lookup only; does not touch `label_range_queries`
    /// accounting, which counts per-region range scans.
    pub(crate) fn labels_at(&self, va: u64) -> Vec<DisassemblyLabel> {
        let first = self.retained.partition_point(|item| item.va < va);
        self.retained[first..]
            .iter()
            .take_while(|item| item.va == va)
            .map(Observation::label)
            .collect()
    }

    pub(crate) fn sections_visited(&self) -> u64 {
        self.sections.sections_visited()
    }

    pub(crate) fn section_index_entries(&self) -> u64 {
        self.sections.index_entries()
    }

    pub(crate) fn section_query_count(&self) -> u64 {
        self.carried_section_queries + self.sections.query_count()
    }

    pub(crate) fn boundary_query_count(&self) -> u64 {
        self.boundary_queries.get()
    }

    pub(crate) fn label_range_query_count(&self) -> u64 {
        self.label_range_queries.get()
    }

    pub(crate) fn target_owner_query_count(&self) -> u64 {
        self.target_owner_queries.get()
    }

    fn failure_state(&self) -> MetadataFailureState {
        MetadataFailureState {
            issues: self.issues.clone(),
            traversals: self.traversals,
            observations_visited: self.observations_visited,
            name_bytes_visited: self.name_bytes_visited,
            section_queries: self.section_query_count(),
            boundary_queries: self.boundary_queries.get(),
            label_range_queries: self.label_range_queries.get(),
            target_owner_queries: self.target_owner_queries.get(),
        }
    }

    fn after_failed_fold(macho: &'macho MachoFile<'_>, state: MetadataFailureState) -> Self {
        let mut metadata = Self::new(macho);
        metadata.issues = state.issues;
        metadata.traversals = state.traversals;
        metadata.observations_visited = state.observations_visited;
        metadata.name_bytes_visited = state.name_bytes_visited;
        metadata.carried_section_queries = state.section_queries;
        metadata.boundary_queries.set(state.boundary_queries);
        metadata.label_range_queries.set(state.label_range_queries);
        metadata
            .target_owner_queries
            .set(state.target_owner_queries);
        metadata
    }

    pub(crate) fn finish(&mut self) {
        self.retained.sort_by(|left, right| {
            (left.va, left.source, &left.raw_name, &left.display_name).cmp(&(
                right.va,
                right.source,
                &right.raw_name,
                &right.display_name,
            ))
        });
        for values in self.requested.values_mut() {
            values.sort();
        }
        for (index, observation) in self.retained.iter().enumerate() {
            if let (Some(segment), Some(section)) = (&observation.segment, &observation.section) {
                self.target_owners
                    .entry(segment.clone())
                    .or_default()
                    .entry(section.clone())
                    .or_default()
                    .entry(observation.va)
                    .or_insert(index);
            }
        }
        self.issues.sort();
        self.issues.dedup();
    }
}

struct MetadataFailureState {
    issues: Vec<DisassemblyIssue>,
    traversals: [u64; 3],
    observations_visited: [u64; 3],
    name_bytes_visited: [u64; 3],
    section_queries: u64,
    boundary_queries: u64,
    label_range_queries: u64,
    target_owner_queries: u64,
}

pub(crate) fn collect_metadata<'macho>(
    macho: &'macho MachoFile<'_>,
    requested_names: &[String],
    max: usize,
    demangle: bool,
    fatal_errors: bool,
) -> Result<Metadata<'macho>, DisassemblyError> {
    let requested: BTreeSet<&str> = requested_names.iter().map(String::as_str).collect();
    let mut metadata = Metadata::new(macho);

    let has_symtab = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::Symtab(_)));
    // Discover every exact selector start before considering any boundary or
    // presentation observation. This keeps source traversal order and a low
    // presentation budget from changing an explicitly requested extent.
    if !requested.is_empty() {
        if has_symtab {
            metadata.record_traversal(SymbolSource::Nlist);
            let failure_state = metadata.failure_state();
            match crate::core::format::fold_symbols(macho, metadata, |state, symbol| {
                state.record_visit(SymbolSource::Nlist, symbol.name);
                if symbol.sym_type != SymbolType::Section || symbol.value == 0 {
                    if requested.contains(symbol.name) {
                        state.requested_non_code.insert(symbol.name.to_owned());
                    }
                    return Ok(());
                }
                if requested.contains(symbol.name) {
                    let item = observation(
                        &state.sections,
                        symbol.value,
                        SymbolSource::Nlist,
                        symbol.name,
                        demangle,
                    );
                    state.observe_requested(item, &requested);
                }
                Ok(())
            }) {
                Ok(next) => metadata = next,
                Err(error) => {
                    metadata = Metadata::after_failed_fold(macho, failure_state);
                    metadata_error(&mut metadata, fatal_errors, "nlist", error.to_string())?;
                }
            }
        }
        metadata.record_traversal(SymbolSource::ExportTrie);
        let failure_state = metadata.failure_state();
        match crate::metadata::dyld::fold_exports(macho, metadata, |state, export| {
            state.record_visit(SymbolSource::ExportTrie, &export.name);
            match export_va(macho, &export.kind)? {
                Some(va) if requested.contains(export.name.as_str()) => {
                    let item = observation(
                        &state.sections,
                        va,
                        SymbolSource::ExportTrie,
                        &export.name,
                        demangle,
                    );
                    state.observe_requested(item, &requested);
                }
                None if requested.contains(export.name.as_str()) => {
                    state.requested_non_code.insert(export.name);
                }
                _ => {}
            }
            Ok(())
        }) {
            Ok(next) => metadata = next,
            Err(error) => {
                metadata = Metadata::after_failed_fold(macho, failure_state);
                metadata_error(
                    &mut metadata,
                    fatal_errors,
                    "export trie",
                    error.to_string(),
                )?;
            }
        }
    }

    metadata.reserve_requested(max);

    if has_symtab {
        metadata.record_traversal(SymbolSource::Nlist);
        let failure_state = metadata.failure_state();
        match crate::core::format::fold_symbols(macho, metadata, |state, symbol| {
            if symbol.sym_type == SymbolType::Section && symbol.value != 0 {
                let item = observation(
                    &state.sections,
                    symbol.value,
                    SymbolSource::Nlist,
                    symbol.name,
                    demangle,
                );
                state.push(item, max);
            } else {
                state.record_visit(SymbolSource::Nlist, symbol.name);
            }
            Ok(())
        }) {
            Ok(next) => metadata = next,
            Err(error) => {
                metadata = Metadata::after_failed_fold(macho, failure_state);
                metadata_error(&mut metadata, fatal_errors, "nlist", error.to_string())?;
            }
        }
    }

    metadata.record_traversal(SymbolSource::ExportTrie);
    let failure_state = metadata.failure_state();
    match crate::metadata::dyld::fold_exports(macho, metadata, |state, export| {
        state.record_visit(SymbolSource::ExportTrie, &export.name);
        let Some(va) = export_va(macho, &export.kind)? else {
            return Ok(());
        };
        let item = observation(
            &state.sections,
            va,
            SymbolSource::ExportTrie,
            &export.name,
            demangle,
        );
        state.push_recorded(item, max);
        Ok(())
    }) {
        Ok(next) => metadata = next,
        Err(error) => {
            metadata = Metadata::after_failed_fold(macho, failure_state);
            metadata_error(
                &mut metadata,
                fatal_errors,
                "export trie",
                error.to_string(),
            )?;
        }
    }

    let has_objc = metadata.has_objc_roots();
    if has_objc {
        metadata.record_traversal(SymbolSource::ObjcMetadata);
        let failure_state = metadata.failure_state();
        match crate::metadata::objc::fold_method_imps(macho, metadata, |state, method| {
            let sigil = match method.kind {
                crate::metadata::objc::ObjCMethodKind::Instance => '-',
                crate::metadata::objc::ObjCMethodKind::Class => '+',
            };
            let raw_name = match method.category_name {
                Some(category) => format!(
                    "{sigil}[{}({category}) {}]",
                    method.class_name, method.method_name
                ),
                None => format!("{sigil}[{} {}]", method.class_name, method.method_name),
            };
            let item = observation(
                &state.sections,
                method.imp.0,
                SymbolSource::ObjcMetadata,
                &raw_name,
                demangle,
            );
            state.push(item, max);
            Ok(())
        }) {
            Ok(next) => metadata = next,
            Err(error) => {
                metadata = Metadata::after_failed_fold(macho, failure_state);
                metadata_error(
                    &mut metadata,
                    fatal_errors,
                    "Objective-C metadata",
                    error.to_string(),
                )?;
            }
        }
    }

    metadata.finish();
    Ok(metadata)
}

fn observation_key(observation: &Observation) -> (u64, SymbolSource, String) {
    (
        observation.va,
        observation.source,
        observation.raw_name.clone(),
    )
}

const fn source_index(source: SymbolSource) -> usize {
    match source {
        SymbolSource::Nlist => 0,
        SymbolSource::ExportTrie => 1,
        SymbolSource::ObjcMetadata => 2,
    }
}

fn export_va(
    macho: &MachoFile<'_>,
    kind: &ExportKind,
) -> crate::metadata::dyld::Result<Option<u64>> {
    match kind {
        ExportKind::Regular { address } | ExportKind::ThreadLocal { address } => {
            if *address == 0 {
                return Ok(None);
            }
            macho
                .image_base()
                .0
                .checked_add(*address)
                .map(Some)
                .ok_or_else(|| {
                    crate::metadata::dyld::DyldError::address("export virtual address overflows")
                })
        }
        ExportKind::Absolute { .. }
        | ExportKind::Reexport { .. }
        | ExportKind::StubAndResolver { .. } => Ok(None),
        _ => Ok(None),
    }
}

fn observation(
    sections: &SectionIndex<'_>,
    va: u64,
    source: SymbolSource,
    raw_name: &str,
    demangle: bool,
) -> Observation {
    let display_name = if demangle {
        crate::metadata::symbols::demangle::demangle_symbol(raw_name)
            .unwrap_or_else(|| raw_name.to_owned())
    } else {
        raw_name.to_owned()
    };
    let owning_section = sections.find(va);
    Observation {
        va,
        source,
        raw_name: raw_name.to_owned(),
        display_name,
        segment: owning_section.map(|section| section.segment_name().to_string()),
        section: owning_section.map(|section| section.section_name().to_string()),
    }
}

fn metadata_error(
    metadata: &mut Metadata,
    fatal: bool,
    source: &str,
    message: String,
) -> Result<(), DisassemblyError> {
    let message = format!("failed to parse {source}: {message}");
    if fatal {
        Err(DisassemblyError::new(
            "analysis.disassembly.symbol.metadata_invalid",
            message,
        ))
    } else {
        metadata.issues.push(DisassemblyIssue {
            code: "analysis.disassembly.symbol.metadata_invalid".to_owned(),
            message,
        });
        Ok(())
    }
}
