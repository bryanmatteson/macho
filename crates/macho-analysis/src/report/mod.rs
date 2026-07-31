//! Canonical, validated language-recovery wire vocabulary.

mod canonical;
mod common;
/// Versioned disassembly report schema.
pub mod disassembly;
mod header;
mod header_correlation;
mod objc;
mod recovery;
mod recovery_execute;
mod registry;
mod swift;
mod symbol_recovery;

use macho_core::MachoFile;
use macho_core::model::header::ArchSpec;

pub use canonical::{CanonicalJsonError, canonical_json, sha256_hex};
pub use common::*;
pub use header::*;
pub use header_correlation::{HeaderCorrelationInput, execute_header_correlation};
pub use objc::*;
pub use recovery::*;
pub use recovery_execute::{execute_recovery_abi, execute_recovery_sources};
pub use registry::{
    DOMAIN_IDS, HEADER_VALIDATION_CODES, RECOVERY_DIAGNOSTIC_CODES, RECOVERY_ENTITY_KINDS,
    RECOVERY_ENTITY_ROLES, RECOVERY_FIELDS,
};
pub use swift::*;
pub use symbol_recovery::{recover_symbol_container, recover_symbol_surface};

/// Whether `selector` names this image's architecture.
///
/// Both spellings a user meets elsewhere in the tool are accepted: the CPU-type
/// name (`arm64`), and the qualified slice name a fat listing or the
/// disassembler prints (`arm64e`). The qualified name only differs from the
/// CPU-type name for arm64e, so accepting both cannot make a selector match
/// more slices than the CPU-type name already did.
pub(crate) fn slice_matches_architecture(macho: &MachoFile<'_>, selector: &str) -> bool {
    let header = macho.header();
    let spec = ArchSpec {
        cpu_type: header.cpu_type(),
        cpu_subtype: header.cpu_subtype(),
    };
    selector == header.cpu_type().name() || selector == spec.name()
}

#[cfg(test)]
mod architecture_selection_tests {
    use macho_core::model::container::MachoContainer;

    use super::slice_matches_architecture;

    fn parse_container(bytes: &[u8]) -> MachoContainer<'_> {
        macho_core::parse(bytes).expect("parse fixture")
    }

    #[test]
    fn arm64e_slices_answer_to_both_their_names() {
        let bytes = macho_test_support::disassembly_arm64e();
        let container = parse_container(&bytes);
        let macho = container.macho_files().next().expect("one slice");
        assert!(slice_matches_architecture(macho, "arm64"));
        assert!(slice_matches_architecture(macho, "arm64e"));
        assert!(!slice_matches_architecture(macho, "x86_64"));
    }

    #[test]
    fn plain_slices_answer_to_their_cpu_type_name_only() {
        let bytes = macho_test_support::thin64_x86_64(2);
        let container = parse_container(&bytes);
        let macho = container.macho_files().next().expect("one slice");
        assert!(slice_matches_architecture(macho, "x86_64"));
        assert!(!slice_matches_architecture(macho, "arm64e"));
        assert!(!slice_matches_architecture(macho, "X86_64"));
    }
}
