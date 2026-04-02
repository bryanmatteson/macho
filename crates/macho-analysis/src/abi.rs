//! ABI compatibility checking between symbols, methods, and vtables.
//!
//! Uses a tiered evidence hierarchy:
//! 1. **DWARF** (High confidence): parameter count, types, return type from debug info
//! 2. **ObjC encoding** (Medium confidence): argument count and type comparison from method signatures
//! 3. **Symbol table** (Low confidence): both symbols exist, size heuristics
//! 4. **Export only** (Unknown confidence): provider exports the symbol, no ABI data

use crate::core::dwarf::DwarfFunctionIndex;
use crate::core::dwarf::types::{DwarfFunctionInfo, DwarfType};
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::SymbolTable;
use crate::core::objc::ObjCMetadata;
use crate::core::objc::compat::{self, IssueSeverity as ObjCSeverity};
use crate::core::objc::encoding::ObjCMethodSignature;
use crate::core::rtti::VtableIndex;
use crate::{Error, Result};

/// Result of an ABI compatibility check.
#[derive(Debug, Clone)]
pub struct AbiCompatResult {
    /// Overall compatibility verdict.
    pub compatible: bool,
    /// Confidence level of the verdict.
    pub confidence: AbiConfidence,
    /// Individual findings.
    pub findings: Vec<AbiFinding>,
}

/// Confidence in the compatibility verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AbiConfidence {
    /// Verdict from DWARF debug info (parameter types, return type).
    High,
    /// Verdict from ObjC type encoding or other metadata.
    Medium,
    /// Verdict from symbol existence and size heuristics.
    Low,
    /// No ABI information available; only confirmed presence.
    Unknown,
}

/// Severity of a compatibility finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiSeverity {
    /// Definite incompatibility.
    Error,
    /// Potential issue, may work.
    Warning,
    /// Informational.
    Info,
}

/// A single finding from the compatibility check.
#[derive(Debug, Clone)]
pub struct AbiFinding {
    pub severity: AbiSeverity,
    pub message: String,
}

// ───────────────────────────── symbol compat ─────────────────────────────

/// Check ABI compatibility between two symbols in different images.
///
/// Uses the best available evidence: DWARF > ObjC encoding > symbol size > export presence.
pub fn check_symbol_compat(
    target: &MachoFile<'_>,
    target_symbol: &str,
    provider: &MachoFile<'_>,
    provider_symbol: &str,
) -> Result<AbiCompatResult> {
    let mut findings = Vec::new();

    // --- 1. Check symbol existence ---
    let t_symtab = target.ext::<SymbolTable<'_>>()?;
    let p_symtab = provider.ext::<SymbolTable<'_>>()?;

    let t_sym = t_symtab.symbols().iter().find(|s| s.name == target_symbol);
    let p_sym = p_symtab.symbols().iter().find(|s| s.name == provider_symbol);

    if t_sym.is_none() {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!("target symbol '{target_symbol}' not found"),
        });
    }
    if p_sym.is_none() {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!("provider symbol '{provider_symbol}' not found"),
        });
    }

    if t_sym.is_none() || p_sym.is_none() {
        return Ok(AbiCompatResult {
            compatible: false,
            confidence: AbiConfidence::Unknown,
            findings,
        });
    }

    // --- 2. Try DWARF comparison (highest confidence) ---
    let t_dwarf = DwarfFunctionIndex::build(target).ok();
    let p_dwarf = DwarfFunctionIndex::build(provider).ok();

    if let (Some(t_idx), Some(p_idx)) = (&t_dwarf, &p_dwarf) {
        let t_func = t_idx.find_by_linkage_name(target_symbol);
        let p_func = p_idx.find_by_linkage_name(provider_symbol);

        if let (Some(tf), Some(pf)) = (t_func, p_func) {
            return Ok(compare_dwarf_functions(tf, pf));
        }
    }

    // --- 3. Both symbols exist but no further ABI info (low confidence) ---
    findings.push(AbiFinding {
        severity: AbiSeverity::Info,
        message: format!(
            "both symbols exist; target at {:#x}, provider at {:#x}",
            t_sym.unwrap().value,
            p_sym.unwrap().value,
        ),
    });

    let compatible = !findings.iter().any(|f| f.severity == AbiSeverity::Error);
    Ok(AbiCompatResult {
        compatible,
        confidence: AbiConfidence::Low,
        findings,
    })
}

// ───────────────────────────── ObjC compat ─────────────────────────────

/// Check ABI compatibility between two ObjC methods.
pub fn check_objc_compat(
    target: &MachoFile<'_>,
    target_class: &str,
    target_selector: &str,
    target_is_instance: bool,
    provider: &MachoFile<'_>,
    provider_class: &str,
    provider_selector: &str,
    provider_is_instance: bool,
) -> Result<AbiCompatResult> {
    let t_meta = target.ext::<ObjCMetadata>()?;
    let p_meta = provider.ext::<ObjCMetadata>()?;

    let t_method = find_objc_method(&t_meta, target_class, target_selector, target_is_instance);
    let p_method = find_objc_method(&p_meta, provider_class, provider_selector, provider_is_instance);

    let mut findings = Vec::new();

    if t_method.is_none() {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!(
                "target method {}[{target_class} {target_selector}] not found",
                if target_is_instance { "-" } else { "+" }
            ),
        });
    }
    if p_method.is_none() {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!(
                "provider method {}[{provider_class} {provider_selector}] not found",
                if provider_is_instance { "-" } else { "+" }
            ),
        });
    }

    if t_method.is_none() || p_method.is_none() {
        return Ok(AbiCompatResult {
            compatible: false,
            confidence: AbiConfidence::Unknown,
            findings,
        });
    }

    let t_encoding = &t_method.unwrap().type_encoding;
    let p_encoding = &p_method.unwrap().type_encoding;

    // Parse type encodings into signatures.
    let t_sig = ObjCMethodSignature::parse(t_encoding);
    let p_sig = ObjCMethodSignature::parse(p_encoding);

    match (t_sig, p_sig) {
        (Ok(ts), Ok(ps)) => {
            let compat_result = compat::compare_method_signatures(&ts, &ps);
            for issue in &compat_result.findings {
                findings.push(AbiFinding {
                    severity: match issue.severity {
                        ObjCSeverity::Error => AbiSeverity::Error,
                        ObjCSeverity::Warning => AbiSeverity::Warning,
                    },
                    message: issue.message.clone(),
                });
            }
            let compatible = !findings.iter().any(|f| f.severity == AbiSeverity::Error);
            Ok(AbiCompatResult {
                compatible,
                confidence: AbiConfidence::Medium,
                findings,
            })
        }
        _ => {
            findings.push(AbiFinding {
                severity: AbiSeverity::Warning,
                message: "could not parse one or both type encodings".into(),
            });
            Ok(AbiCompatResult {
                compatible: true,
                confidence: AbiConfidence::Unknown,
                findings,
            })
        }
    }
}

// ───────────────────────────── vtable compat ─────────────────────────────

/// Check that a vtable has at least `declared_slot_count` slots.
pub fn check_vtable_compat(
    macho: &MachoFile<'_>,
    class_name: &str,
    declared_slot_count: usize,
) -> Result<AbiCompatResult> {
    let vtable_idx = VtableIndex::build(macho)?;
    let mut findings = Vec::new();

    let entry = vtable_idx.find_by_class(class_name);

    let Some(entry) = entry else {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!("vtable for '{class_name}' not found"),
        });
        return Ok(AbiCompatResult {
            compatible: false,
            confidence: AbiConfidence::Low,
            findings,
        });
    };

    // Vtable has 2 header slots (offset-to-top + typeinfo), then function slots.
    let function_slots = entry.slots.len().saturating_sub(2);

    if declared_slot_count > function_slots {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!(
                "declared {declared_slot_count} vtable slots but found only {function_slots} function slots"
            ),
        });
        return Ok(AbiCompatResult {
            compatible: false,
            confidence: AbiConfidence::Medium,
            findings,
        });
    }

    findings.push(AbiFinding {
        severity: AbiSeverity::Info,
        message: format!("vtable has {function_slots} function slots, {declared_slot_count} declared"),
    });

    Ok(AbiCompatResult {
        compatible: true,
        confidence: AbiConfidence::Medium,
        findings,
    })
}

// ───────────────────────────── DWARF comparison ─────────────────────────

fn compare_dwarf_functions(target: &DwarfFunctionInfo, provider: &DwarfFunctionInfo) -> AbiCompatResult {
    let mut findings = Vec::new();

    // Filter out artificial params (implicit 'this').
    let t_params: Vec<_> = target.parameters.iter().filter(|p| !p.is_artificial).collect();
    let p_params: Vec<_> = provider.parameters.iter().filter(|p| !p.is_artificial).collect();

    // Parameter count.
    if t_params.len() != p_params.len() {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!(
                "parameter count mismatch: target has {}, provider has {}",
                t_params.len(),
                p_params.len(),
            ),
        });
    } else {
        // Per-parameter type comparison.
        for (i, (tp, pp)) in t_params.iter().zip(&p_params).enumerate() {
            if !dwarf_types_compat(&tp.ty, &pp.ty) {
                findings.push(AbiFinding {
                    severity: if dwarf_types_width_compat(&tp.ty, &pp.ty) {
                        AbiSeverity::Warning
                    } else {
                        AbiSeverity::Error
                    },
                    message: format!("parameter {i} type mismatch: target '{}', provider '{}'", tp.ty, pp.ty),
                });
            }
        }
    }

    // Return type.
    if !dwarf_types_compat(&target.return_type, &provider.return_type) {
        findings.push(AbiFinding {
            severity: if dwarf_types_width_compat(&target.return_type, &provider.return_type) {
                AbiSeverity::Warning
            } else {
                AbiSeverity::Error
            },
            message: format!(
                "return type mismatch: target '{}', provider '{}'",
                target.return_type, provider.return_type,
            ),
        });
    }

    // Variadic.
    if target.is_variadic != provider.is_variadic {
        findings.push(AbiFinding {
            severity: AbiSeverity::Error,
            message: format!(
                "variadic mismatch: target {}, provider {}",
                target.is_variadic, provider.is_variadic,
            ),
        });
    }

    let compatible = !findings.iter().any(|f| f.severity == AbiSeverity::Error);
    AbiCompatResult {
        compatible,
        confidence: AbiConfidence::High,
        findings,
    }
}

/// Structural compatibility between DWARF types.
fn dwarf_types_compat(a: &DwarfType, b: &DwarfType) -> bool {
    match (a, b) {
        (DwarfType::Void, DwarfType::Void) => true,
        (
            DwarfType::Base { encoding: ae, byte_size: as_, .. },
            DwarfType::Base { encoding: be, byte_size: bs, .. },
        ) => ae == be && as_ == bs,
        (DwarfType::Pointer { pointee: ap, .. }, DwarfType::Pointer { pointee: bp, .. }) => {
            dwarf_types_compat(ap, bp)
        }
        (DwarfType::Reference { referent: ar }, DwarfType::Reference { referent: br }) => {
            dwarf_types_compat(ar, br)
        }
        (DwarfType::Const(a), DwarfType::Const(b)) => dwarf_types_compat(a, b),
        (DwarfType::Typedef { underlying: au, .. }, DwarfType::Typedef { underlying: bu, .. }) => {
            dwarf_types_compat(au, bu)
        }
        // Unwrap typedef on one side.
        (DwarfType::Typedef { underlying, .. }, other)
        | (other, DwarfType::Typedef { underlying, .. }) => dwarf_types_compat(underlying, other),
        // Strip const on one side.
        (DwarfType::Const(inner), other) | (other, DwarfType::Const(inner)) => {
            dwarf_types_compat(inner, other)
        }
        (
            DwarfType::Structure { name: an, byte_size: as_, .. },
            DwarfType::Structure { name: bn, byte_size: bs, .. },
        ) => an == bn && as_ == bs,
        (DwarfType::Enumeration { name: an, .. }, DwarfType::Enumeration { name: bn, .. }) => an == bn,
        // Void pointer is compatible with any pointer.
        (DwarfType::Pointer { pointee, .. }, _) if matches!(**pointee, DwarfType::Void) => {
            matches!(b, DwarfType::Pointer { .. })
        }
        (_, DwarfType::Pointer { pointee, .. }) if matches!(**pointee, DwarfType::Void) => {
            matches!(a, DwarfType::Pointer { .. })
        }
        _ => false,
    }
}

/// Same-width heuristic for downgradable mismatches.
fn dwarf_types_width_compat(a: &DwarfType, b: &DwarfType) -> bool {
    let aw = dwarf_type_width(a);
    let bw = dwarf_type_width(b);
    matches!((aw, bw), (Some(a), Some(b)) if a == b)
}

fn dwarf_type_width(ty: &DwarfType) -> Option<u64> {
    match ty {
        DwarfType::Void => Some(0),
        DwarfType::Base { byte_size, .. } => Some(*byte_size),
        DwarfType::Pointer { byte_size, .. } => Some(*byte_size),
        DwarfType::Reference { .. } | DwarfType::RvalueReference { .. } => Some(8),
        DwarfType::Structure { byte_size, .. } => *byte_size,
        DwarfType::Enumeration { byte_size, .. } => *byte_size,
        DwarfType::Typedef { underlying, .. } => dwarf_type_width(underlying),
        DwarfType::Const(inner) | DwarfType::Volatile(inner) | DwarfType::Restrict(inner) => {
            dwarf_type_width(inner)
        }
        _ => None,
    }
}

// ───────────────────────────── helpers ─────────────────────────────

fn find_objc_method<'a>(
    meta: &'a ObjCMetadata,
    class_name: &str,
    selector: &str,
    is_instance: bool,
) -> Option<&'a crate::core::objc::types::ObjCMethod> {
    for class in &meta.classes {
        if class.name == class_name {
            let methods = if is_instance {
                &class.instance_methods
            } else {
                &class.class_methods
            };
            return methods.iter().find(|m| m.name == selector);
        }
    }
    // Also search categories.
    for cat in &meta.categories {
        if cat.class_name == class_name {
            let methods = if is_instance {
                &cat.instance_methods
            } else {
                &cat.class_methods
            };
            if let Some(m) = methods.iter().find(|m| m.name == selector) {
                return Some(m);
            }
        }
    }
    None
}
