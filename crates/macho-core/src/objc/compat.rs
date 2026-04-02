//! Objective-C method signature compatibility comparison.
//!
//! Given two [`ObjCMethodSignature`] values (parsed from type encoding strings),
//! determine whether a provider method is ABI-compatible with a target method
//! for purposes such as method swizzling, replace hooks, or intercept hooks.

use super::encoding::{ObjCMethodSignature, ObjCQualifiedType, ObjCType, TypeQualifier};

/// Result of comparing two ObjC method signatures.
#[derive(Debug, Clone)]
pub struct SignatureCompat {
    /// Whether the signatures are considered compatible (no `Error`-severity issues).
    pub compatible: bool,
    /// Individual findings from the comparison.
    pub findings: Vec<SignatureIssue>,
}

/// A single compatibility finding.
#[derive(Debug, Clone)]
pub struct SignatureIssue {
    pub severity: IssueSeverity,
    pub message: String,
}

/// Severity level for a compatibility finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSeverity {
    /// Definite ABI mismatch — will crash or corrupt at runtime.
    Error,
    /// Possible mismatch or loss of safety, but may work in practice.
    Warning,
}

/// Compare two ObjC method signatures for ABI compatibility.
///
/// The `target` is the method being hooked/replaced.
/// The `provider` is the replacement implementation.
///
/// Returns a [`SignatureCompat`] indicating whether the provider can safely
/// replace the target at the ABI level.
pub fn compare_method_signatures(
    target: &ObjCMethodSignature,
    provider: &ObjCMethodSignature,
) -> SignatureCompat {
    let mut findings = Vec::new();

    // --- Argument count ---
    if target.arguments.len() != provider.arguments.len() {
        findings.push(SignatureIssue {
            severity: IssueSeverity::Error,
            message: format!(
                "argument count mismatch: target has {}, provider has {}",
                target.arguments.len(),
                provider.arguments.len(),
            ),
        });
    } else {
        // --- Per-argument type compatibility ---
        for (i, (t_arg, p_arg)) in target.arguments.iter().zip(&provider.arguments).enumerate() {
            if !types_compatible(&t_arg.ty, &p_arg.ty) {
                let sev = if types_width_compatible(&t_arg.ty, &p_arg.ty) {
                    IssueSeverity::Warning
                } else {
                    IssueSeverity::Error
                };
                findings.push(SignatureIssue {
                    severity: sev,
                    message: format!(
                        "argument {i} type mismatch: target '{}', provider '{}'",
                        t_arg.ty.render(),
                        p_arg.ty.render(),
                    ),
                });
            }

            // Qualifier differences are warnings, not errors.
            let qual_diff = qualifier_diff(&t_arg.ty.qualifiers, &p_arg.ty.qualifiers);
            if !qual_diff.is_empty() {
                findings.push(SignatureIssue {
                    severity: IssueSeverity::Warning,
                    message: format!("argument {i} qualifier difference: {qual_diff}"),
                });
            }
        }
    }

    // --- Return type ---
    if !types_compatible(&target.return_type, &provider.return_type) {
        let sev = if types_width_compatible(&target.return_type, &provider.return_type) {
            IssueSeverity::Warning
        } else {
            IssueSeverity::Error
        };
        findings.push(SignatureIssue {
            severity: sev,
            message: format!(
                "return type mismatch: target '{}', provider '{}'",
                target.return_type.render(),
                provider.return_type.render(),
            ),
        });
    }

    let compatible = !findings.iter().any(|f| f.severity == IssueSeverity::Error);

    SignatureCompat {
        compatible,
        findings,
    }
}

/// Check structural type compatibility between two ObjC types.
///
/// This is a recursive check:
/// - Primitive types must match exactly.
/// - `id` is compatible with any object type (and vice versa).
/// - Pointers must match in depth and pointee compatibility.
/// - Struct/union names must match.
/// - Qualifiers are ignored here (checked separately).
pub fn types_compatible(a: &ObjCQualifiedType, b: &ObjCQualifiedType) -> bool {
    type_cores_compatible(&a.ty, &b.ty)
}

fn type_cores_compatible(a: &ObjCType, b: &ObjCType) -> bool {
    match (a, b) {
        // Exact match on primitives.
        (ObjCType::Void, ObjCType::Void)
        | (ObjCType::Bool, ObjCType::Bool)
        | (ObjCType::Char, ObjCType::Char)
        | (ObjCType::UnsignedChar, ObjCType::UnsignedChar)
        | (ObjCType::Short, ObjCType::Short)
        | (ObjCType::UnsignedShort, ObjCType::UnsignedShort)
        | (ObjCType::Int, ObjCType::Int)
        | (ObjCType::UnsignedInt, ObjCType::UnsignedInt)
        | (ObjCType::Long, ObjCType::Long)
        | (ObjCType::UnsignedLong, ObjCType::UnsignedLong)
        | (ObjCType::LongLong, ObjCType::LongLong)
        | (ObjCType::UnsignedLongLong, ObjCType::UnsignedLongLong)
        | (ObjCType::Float, ObjCType::Float)
        | (ObjCType::Double, ObjCType::Double)
        | (ObjCType::CString, ObjCType::CString)
        | (ObjCType::CharPtr, ObjCType::CharPtr)
        | (ObjCType::Selector, ObjCType::Selector)
        | (ObjCType::Class, ObjCType::Class) => true,

        // Object types: `id` (no class name) is compatible with any object type.
        (
            ObjCType::Object { class_name: a_cls, is_block: a_blk, .. },
            ObjCType::Object { class_name: b_cls, is_block: b_blk, .. },
        ) => {
            // Both blocks → compatible.
            if *a_blk && *b_blk {
                return true;
            }
            // `id` (class_name = None) is compatible with any object.
            if a_cls.is_none() || b_cls.is_none() {
                return true;
            }
            // Named classes must match.
            a_cls == b_cls
        }

        // Pointers: recursive check on pointee.
        (ObjCType::Pointer(a_inner), ObjCType::Pointer(b_inner)) => {
            types_compatible(a_inner, b_inner)
        }

        // Struct/union: names must match.
        (ObjCType::Struct { name: a_name, .. }, ObjCType::Struct { name: b_name, .. }) => {
            a_name == b_name
        }
        (ObjCType::Union { name: a_name, .. }, ObjCType::Union { name: b_name, .. }) => {
            a_name == b_name
        }

        // Arrays: element type and length must match.
        (
            ObjCType::Array { len: a_len, element: a_el },
            ObjCType::Array { len: b_len, element: b_el },
        ) => a_len == b_len && types_compatible(a_el, b_el),

        // BitFields: width must match.
        (ObjCType::BitField(a_bits), ObjCType::BitField(b_bits)) => a_bits == b_bits,

        // CString ↔ CharPtr: compatible (both are `char *`).
        (ObjCType::CString, ObjCType::CharPtr) | (ObjCType::CharPtr, ObjCType::CString) => true,

        // Everything else is incompatible.
        _ => false,
    }
}

/// Check if two types have the same ABI width even if semantically different.
///
/// For example, `int` and `unsigned int` have the same width. This is used
/// to downgrade errors to warnings when the mismatch is unlikely to cause
/// a crash (same register / stack slot size).
///
/// Returns `false` for pointer/struct mismatches where same width is
/// coincidental rather than meaningful.
fn types_width_compatible(a: &ObjCQualifiedType, b: &ObjCQualifiedType) -> bool {
    // Don't downgrade pointer-vs-different-pointer mismatches — same width
    // but passing the wrong level of indirection will crash.
    if is_pointer_family(&a.ty) != is_pointer_family(&b.ty) {
        return false;
    }
    // Both are pointers but pointees differ — structural mismatch, not width.
    if is_pointer_family(&a.ty) && is_pointer_family(&b.ty) {
        return false;
    }
    let a_w = type_width(&a.ty);
    let b_w = type_width(&b.ty);
    match (a_w, b_w) {
        (Some(aw), Some(bw)) => aw == bw,
        _ => false,
    }
}

fn is_pointer_family(ty: &ObjCType) -> bool {
    matches!(
        ty,
        ObjCType::Pointer(_)
            | ObjCType::Object { .. }
            | ObjCType::CharPtr
            | ObjCType::CString
            | ObjCType::Selector
            | ObjCType::Class
    )
}

/// Estimate the ABI width of a type in bytes (on 64-bit).
fn type_width(ty: &ObjCType) -> Option<usize> {
    match ty {
        ObjCType::Void => Some(0),
        ObjCType::Bool | ObjCType::Char | ObjCType::UnsignedChar => Some(1),
        ObjCType::Short | ObjCType::UnsignedShort => Some(2),
        ObjCType::Int | ObjCType::UnsignedInt | ObjCType::Float => Some(4),
        ObjCType::Long | ObjCType::UnsignedLong | ObjCType::LongLong
        | ObjCType::UnsignedLongLong | ObjCType::Double => Some(8),
        ObjCType::Pointer(_)
        | ObjCType::Object { .. }
        | ObjCType::CharPtr
        | ObjCType::CString
        | ObjCType::Selector
        | ObjCType::Class => Some(8),
        _ => None,
    }
}

/// Describe qualifier differences between two qualifier lists.
fn qualifier_diff(a: &[TypeQualifier], b: &[TypeQualifier]) -> String {
    let mut diffs = Vec::new();
    for q in a {
        if !b.contains(q) {
            diffs.push(format!("target has {q:?}"));
        }
    }
    for q in b {
        if !a.contains(q) {
            diffs.push(format!("provider has {q:?}"));
        }
    }
    diffs.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objc::encoding::ObjCMethodArg;

    fn make_sig(
        ret: ObjCType,
        args: Vec<ObjCType>,
    ) -> ObjCMethodSignature {
        ObjCMethodSignature {
            return_type: ObjCQualifiedType {
                qualifiers: vec![],
                ty: ret,
            },
            return_offset: None,
            self_type: None,
            cmd_type: None,
            arguments: args
                .into_iter()
                .map(|ty| ObjCMethodArg {
                    ty: ObjCQualifiedType {
                        qualifiers: vec![],
                        ty,
                    },
                    stack_offset: None,
                })
                .collect(),
        }
    }

    #[test]
    fn identical_signatures_compatible() {
        let sig = make_sig(ObjCType::Void, vec![ObjCType::Int, ObjCType::Bool]);
        let result = compare_method_signatures(&sig, &sig);
        assert!(result.compatible);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn arg_count_mismatch() {
        let target = make_sig(ObjCType::Void, vec![ObjCType::Int]);
        let provider = make_sig(ObjCType::Void, vec![ObjCType::Int, ObjCType::Bool]);
        let result = compare_method_signatures(&target, &provider);
        assert!(!result.compatible);
        assert!(result.findings.iter().any(|f| f.severity == IssueSeverity::Error));
    }

    #[test]
    fn return_type_mismatch_is_error() {
        let target = make_sig(ObjCType::Void, vec![]);
        let provider = make_sig(ObjCType::Int, vec![]);
        let result = compare_method_signatures(&target, &provider);
        assert!(!result.compatible);
    }

    #[test]
    fn same_width_mismatch_is_warning() {
        // int vs unsigned int → same width (4 bytes) → warning, not error.
        let target = make_sig(ObjCType::Int, vec![]);
        let provider = make_sig(ObjCType::UnsignedInt, vec![]);
        let result = compare_method_signatures(&target, &provider);
        assert!(result.compatible); // warning, not error
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn id_compatible_with_named_object() {
        let id_type = ObjCType::Object {
            class_name: None,
            protocols: vec![],
            is_block: false,
        };
        let named_type = ObjCType::Object {
            class_name: Some("NSString".into()),
            protocols: vec![],
            is_block: false,
        };
        let target = make_sig(id_type.clone(), vec![named_type.clone()]);
        let provider = make_sig(named_type, vec![id_type]);
        let result = compare_method_signatures(&target, &provider);
        assert!(result.compatible);
    }

    #[test]
    fn pointer_depth_mismatch() {
        let ptr = ObjCType::Pointer(Box::new(ObjCQualifiedType {
            qualifiers: vec![],
            ty: ObjCType::Int,
        }));
        let double_ptr = ObjCType::Pointer(Box::new(ObjCQualifiedType {
            qualifiers: vec![],
            ty: ptr.clone(),
        }));
        let target = make_sig(ObjCType::Void, vec![ptr]);
        let provider = make_sig(ObjCType::Void, vec![double_ptr]);
        let result = compare_method_signatures(&target, &provider);
        assert!(!result.compatible);
    }

    #[test]
    fn struct_name_mismatch() {
        let a = ObjCType::Struct { name: "CGRect".into(), fields: vec![] };
        let b = ObjCType::Struct { name: "CGSize".into(), fields: vec![] };
        let target = make_sig(ObjCType::Void, vec![a]);
        let provider = make_sig(ObjCType::Void, vec![b]);
        let result = compare_method_signatures(&target, &provider);
        assert!(!result.compatible);
    }

    #[test]
    fn cstring_and_charptr_compatible() {
        let target = make_sig(ObjCType::CString, vec![]);
        let provider = make_sig(ObjCType::CharPtr, vec![]);
        let result = compare_method_signatures(&target, &provider);
        assert!(result.compatible);
    }
}
