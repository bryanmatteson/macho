//! Container-aware mutation while preserving exact selected-member identity.

use macho_core::model::{MachoContainer, SelectionKey};

use crate::owned::OwnedFatBinary;
use crate::{MutationError, Result};

/// Target set for one container edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerTarget {
    /// Apply to exactly one member and reject stale identity.
    One(SelectionKey),
    /// Apply independently to every member in deterministic table order.
    All,
}

/// Per-member result of a container edit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMemberResult {
    /// Zero-based container member index.
    pub container_index: usize,
    /// Canonical architecture name.
    pub architecture: String,
    /// Whether this member's bytes changed.
    pub changed: bool,
}

/// Rebuilt container and its deterministic member accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerEditResult {
    /// Validated output bytes.
    pub bytes: Vec<u8>,
    /// Edited members in table order.
    pub members: Vec<ContainerMemberResult>,
}

/// Apply an image-local transform to one exact member or every member.
///
/// Parsing, exact selection, fat-member replacement, container rebuild, and
/// final structural validation are owned here. The caller supplies only the
/// leaf operation that turns one already-selected image into candidate bytes.
pub fn transform_container(
    bytes: &[u8],
    target: ContainerTarget,
    mut transform: impl FnMut(&macho_core::MachoFile<'_>) -> Result<Vec<u8>>,
) -> Result<ContainerEditResult> {
    let parsed = macho_core::parse(bytes).map_err(MutationError::from)?;
    if let ContainerTarget::One(key) = target {
        parsed.select_exact(key).map_err(MutationError::from)?;
    }
    let mut members = Vec::new();
    let output = match &parsed {
        MachoContainer::Thin(image) => {
            let selected = matches!(target, ContainerTarget::All)
                || matches!(target, ContainerTarget::One(key) if key.container_index == 0);
            if !selected {
                return Err(MutationError::invalid(
                    "container target does not identify the thin image",
                ));
            }
            let replacement = transform(image)?;
            let changed = replacement != image.bytes();
            members.push(ContainerMemberResult {
                container_index: 0,
                architecture: image_architecture(image),
                changed,
            });
            replacement
        }
        MachoContainer::Fat(fat) => {
            let mut output = OwnedFatBinary::from_fat(fat, bytes);
            for (index, arch) in fat.arches().iter().enumerate() {
                let selected = matches!(target, ContainerTarget::All)
                    || matches!(target, ContainerTarget::One(key) if key.container_index == index);
                if !selected {
                    continue;
                }
                let replacement = transform(arch.macho())?;
                let changed = replacement != arch.macho().bytes();
                output.replace_arch(index, replacement)?;
                members.push(ContainerMemberResult {
                    container_index: index,
                    architecture: arch.spec().name(),
                    changed,
                });
            }
            output.try_into_bytes()?
        }
    };
    macho_core::parse(&output).map_err(MutationError::from)?;
    Ok(ContainerEditResult {
        bytes: output,
        members,
    })
}

fn image_architecture(image: &macho_core::MachoFile<'_>) -> String {
    macho_core::model::ArchSpec {
        cpu_type: image.header().cpu_type(),
        cpu_subtype: image.header().cpu_subtype(),
    }
    .name()
}
