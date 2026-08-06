use crate::analysis::header_syntax as syntax;

use super::{Identifier, ObjCUnavailableReason};

/// Reject context-sensitive runtime type spellings as declaration names.
pub(super) fn objc_member_identifier(
    value: &str,
) -> Result<(Identifier, syntax::Identifier), ObjCUnavailableReason> {
    if matches!(value, "id" | "Class" | "SEL" | "instancetype") {
        return Err(ObjCUnavailableReason::UnsupportedEncoding);
    }
    let wire = Identifier::new(value.to_owned())
        .map_err(|_| ObjCUnavailableReason::UnsupportedEncoding)?;
    let syntax =
        syntax::Identifier::new(value).ok_or(ObjCUnavailableReason::UnsupportedEncoding)?;
    Ok((wire, syntax))
}
