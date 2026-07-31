use macho::analysis::report::{ObjCEntity, ObjCPresence, ObjCReport};

use super::model::{entity_methods, known};

#[derive(Debug, Clone, Default, clap::Args)]
pub(super) struct ObjCFilterArgs {
    /// Select a class and its categories by exact runtime name.
    #[arg(long)]
    class: Option<String>,
    /// Retain entities whose runtime name contains this text.
    #[arg(long)]
    name: Option<String>,
    /// Retain one or more entity kinds (repeatable).
    #[arg(long = "kind", value_name = "KIND", value_enum, action = clap::ArgAction::Append)]
    kinds: Vec<ObjCEntityKindArg>,
    /// Retain one or more evidence-presence states (repeatable).
    #[arg(
        long = "presence",
        value_name = "PRESENCE",
        value_enum,
        action = clap::ArgAction::Append
    )]
    presences: Vec<ObjCPresenceArg>,
    /// Retain entities declaring an exact selector spelling (repeatable).
    #[arg(long = "selector", value_name = "SELECTOR", action = clap::ArgAction::Append)]
    selectors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ObjCEntityKindArg {
    Class,
    Category,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ObjCPresenceArg {
    Defined,
    Referenced,
    Partial,
}

impl ObjCFilterArgs {
    /// Whether the caller narrowed the selection.
    ///
    /// This is the question a listing actually needs, so it is answered from the
    /// arguments rather than inferred by comparing a selected count against a
    /// total, which cannot distinguish "no filter" from "a filter that retained
    /// everything".
    pub(super) fn is_active(&self) -> bool {
        self.class.is_some()
            || self.name.is_some()
            || !self.kinds.is_empty()
            || !self.presences.is_empty()
            || !self.selectors.is_empty()
    }
}

pub(super) fn apply_filters(report: &mut ObjCReport, filters: &ObjCFilterArgs) {
    for slice in report.slices.as_mut_slice() {
        let entities = &slice.entities;
        slice.selection.selected_entity_ids.retain(|id| {
            entities
                .iter()
                .find(|entity| entity.common().id == *id)
                .is_some_and(|entity| entity_matches_filters(entity, filters))
        });
    }
}

fn entity_matches_filters(entity: &ObjCEntity, filters: &ObjCFilterArgs) -> bool {
    filters
        .class
        .as_deref()
        .is_none_or(|class| entity_matches_class(entity, class))
        && filters.name.as_deref().is_none_or(|query| {
            known(&entity.common().name).is_some_and(|name| name.contains(query))
        })
        && (filters.kinds.is_empty() || filters.kinds.iter().any(|kind| kind.matches(entity)))
        && (filters.presences.is_empty()
            || filters
                .presences
                .iter()
                .any(|presence| presence.matches(entity.common().presence)))
        && (filters.selectors.is_empty()
            || entity_methods(entity).any(|method| {
                known(&method.selector)
                    .is_some_and(|selector| filters.selectors.contains(&selector.spelling))
            }))
}

impl ObjCEntityKindArg {
    fn matches(self, entity: &ObjCEntity) -> bool {
        matches!(
            (self, entity),
            (Self::Class, ObjCEntity::Class(_))
                | (Self::Category, ObjCEntity::Category(_))
                | (Self::Protocol, ObjCEntity::Protocol(_))
        )
    }
}

impl ObjCPresenceArg {
    fn matches(self, presence: ObjCPresence) -> bool {
        matches!(
            (self, presence),
            (Self::Defined, ObjCPresence::Defined)
                | (Self::Referenced, ObjCPresence::Referenced)
                | (Self::Partial, ObjCPresence::Partial)
        )
    }
}

fn entity_matches_class(entity: &ObjCEntity, class: &str) -> bool {
    match entity {
        ObjCEntity::Class(value) => known(&value.common.name).is_some_and(|name| name == class),
        ObjCEntity::Category(value) => {
            known(&value.extended_class).is_some_and(|reference| reference.name == class)
        }
        ObjCEntity::Protocol(_) => false,
    }
}
