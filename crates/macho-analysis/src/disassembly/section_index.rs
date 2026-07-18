use std::cell::Cell;
use std::collections::BTreeMap;

use macho_core::model::macho_file::MachoFile;
use macho_core::model::section::Section;

#[derive(Debug, Clone, Copy)]
struct Event<'macho> {
    position: u64,
    section_index: usize,
    starts: bool,
    section: &'macho Section,
}

#[derive(Debug, Clone, Copy)]
struct Span<'macho> {
    start: u64,
    end: u64,
    section: &'macho Section,
}

/// Slice-local section lookup authority.
///
/// The sweep converts even overlapping input sections into disjoint ownership
/// spans, preserving `MachoFile::all_sections()`'s first-section precedence.
/// Queries are then logarithmic instead of rescanning every section for every
/// metadata observation, selected address, or direct target.
#[derive(Debug)]
pub(crate) struct SectionIndex<'macho> {
    all: Vec<Span<'macho>>,
    file_backed: Vec<Span<'macho>>,
    by_name: BTreeMap<(String, String), &'macho Section>,
    has_objc_roots: bool,
    sections_visited: u64,
    index_entries: u64,
    all_queries: Cell<u64>,
    file_queries: Cell<u64>,
    name_queries: Cell<u64>,
}

impl<'macho> SectionIndex<'macho> {
    pub(crate) fn new(macho: &'macho MachoFile<'_>) -> Self {
        let sections: Vec<_> = macho.all_sections().collect();
        let mut by_name = BTreeMap::new();
        let mut has_objc_roots = false;
        for section in &sections {
            let segment = section.segment_name().to_string();
            let name = section.section_name().to_string();
            by_name.entry((segment, name.clone())).or_insert(*section);
            has_objc_roots |= matches!(
                name.as_str(),
                "__objc_classlist" | "__objc_catlist" | "__objc_protolist"
            );
        }
        let all = ownership_spans(&sections, |_| true);
        let file_backed = ownership_spans(&sections, |section| {
            !section.section_type().is_zerofill()
                && section
                    .offset()
                    .0
                    .checked_add(section.size())
                    .is_some_and(|end| end <= macho.file_size() as u64)
        });
        let index_entries = all.len() + file_backed.len() + by_name.len();
        Self {
            all,
            file_backed,
            by_name,
            has_objc_roots,
            sections_visited: sections.len() as u64,
            index_entries: index_entries as u64,
            all_queries: Cell::new(0),
            file_queries: Cell::new(0),
            name_queries: Cell::new(0),
        }
    }

    pub(crate) fn find(&self, va: u64) -> Option<&'macho Section> {
        self.all_queries.set(self.all_queries.get() + 1);
        find_span(&self.all, va)
    }

    pub(crate) fn find_file_backed(&self, va: u64) -> Option<&'macho Section> {
        self.file_queries.set(self.file_queries.get() + 1);
        find_span(&self.file_backed, va)
    }

    pub(crate) fn named(&self, segment: &str, section: &str) -> Option<&'macho Section> {
        self.name_queries.set(self.name_queries.get() + 1);
        self.by_name
            .get(&(segment.to_owned(), section.to_owned()))
            .copied()
    }

    pub(crate) fn has_objc_roots(&self) -> bool {
        self.has_objc_roots
    }

    pub(crate) fn sections_visited(&self) -> u64 {
        self.sections_visited
    }

    pub(crate) fn index_entries(&self) -> u64 {
        self.index_entries
    }

    pub(crate) fn query_count(&self) -> u64 {
        self.all_queries.get() + self.file_queries.get() + self.name_queries.get()
    }
}

fn ownership_spans<'macho>(
    sections: &[&'macho Section],
    include: impl Fn(&Section) -> bool,
) -> Vec<Span<'macho>> {
    let mut events = Vec::new();
    for (section_index, section) in sections.iter().copied().enumerate() {
        if !include(section) || section.size() == 0 {
            continue;
        }
        let Some(end) = section.addr().0.checked_add(section.size()) else {
            continue;
        };
        events.push(Event {
            position: section.addr().0,
            section_index,
            starts: true,
            section,
        });
        events.push(Event {
            position: end,
            section_index,
            starts: false,
            section,
        });
    }
    events.sort_by_key(|event| (event.position, event.starts, event.section_index));

    let mut spans: Vec<Span<'macho>> = Vec::with_capacity(events.len());
    let mut active: BTreeMap<usize, &'macho Section> = BTreeMap::new();
    let mut cursor = events.first().map_or(0, |event| event.position);
    let mut index = 0;
    while index < events.len() {
        let position = events[index].position;
        if cursor < position
            && let Some((_, section)) = active.first_key_value()
        {
            if let Some(previous) = spans.last_mut()
                && std::ptr::eq::<Section>(previous.section, *section)
                && previous.end == cursor
            {
                previous.end = position;
            } else {
                spans.push(Span {
                    start: cursor,
                    end: position,
                    section,
                });
            }
        }
        while index < events.len() && events[index].position == position && !events[index].starts {
            active.remove(&events[index].section_index);
            index += 1;
        }
        while index < events.len() && events[index].position == position && events[index].starts {
            active.insert(events[index].section_index, events[index].section);
            index += 1;
        }
        cursor = position;
    }
    spans
}

fn find_span<'macho>(spans: &[Span<'macho>], va: u64) -> Option<&'macho Section> {
    let index = spans.partition_point(|span| span.start <= va);
    let span = index.checked_sub(1).and_then(|index| spans.get(index))?;
    (va < span.end).then_some(span.section)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_file_backed_sections_and_names() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = macho_core::parse(&bytes).unwrap();
        let macho = match &container {
            macho_core::model::container::MachoContainer::Thin(macho) => macho,
            macho_core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        };
        let index = SectionIndex::new(macho);
        let text = index.named("__TEXT", "__text").unwrap();
        assert_eq!(index.find(text.addr().0).unwrap().section_name(), "__text");
        assert_eq!(
            index
                .find_file_backed(text.addr().0)
                .unwrap()
                .section_name(),
            "__text"
        );
        assert_eq!(index.query_count(), 3);
    }
}
