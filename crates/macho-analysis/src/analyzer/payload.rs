use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::AnalysisDomain;

#[derive(Debug, Clone, PartialEq)]
/// One closed snapshot-domain payload.
#[non_exhaustive]
pub enum DomainPayload {
    /// Container payload.
    Container(Value),
    /// Header payload.
    Header(Value),
    /// Load-command payload.
    LoadCommands(Value),
    /// Segment payload.
    Segments(Value),
    /// Relocation payload.
    Relocations(Value),
    /// Symbol payload.
    Symbols(Value),
    /// Export payload.
    Exports(Value),
    /// Import payload.
    Imports(Value),
    /// Fixup payload.
    Fixups(Value),
    /// Code-signature payload.
    Codesign(Value),
    /// Canonical Objective-C payload.
    Objc(Value),
    /// Canonical Swift payload.
    Swift(Value),
    /// DWARF payload.
    Dwarf(Value),
    /// Vtable payload.
    Vtables(Value),
    /// String payload.
    Strings(Value),
    /// Range payload.
    Ranges(Value),
    /// Cross-reference payload.
    Xrefs(Value),
    /// Dependency payload.
    Dependencies(Value),
    /// Audit payload.
    Audit(Value),
    /// Canonical C recovery payload.
    CSurface(Value),
    /// Canonical C++ recovery payload.
    CppSurface(Value),
    /// Canonical Objective-C header payload.
    ObjcHeaders(Value),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainPayloadWire {
    kind: AnalysisDomain,
    report_schema: u32,
    report: Value,
}

impl Serialize for DomainPayload {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        DomainPayloadWire {
            kind: self.domain(),
            report_schema: 1,
            report: self.value().clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DomainPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DomainPayloadWire::deserialize(deserializer)?;
        if wire.report_schema != 1 {
            return Err(serde::de::Error::custom(format!(
                "unsupported {} report schema {}; expected 1",
                wire.kind.as_str(),
                wire.report_schema
            )));
        }
        Self::from_parts(wire.kind, wire.report).map_err(serde::de::Error::custom)
    }
}

impl DomainPayload {
    fn from_parts(domain: AnalysisDomain, value: Value) -> Result<Self, String> {
        let value = validate_typed_payload(domain, value)?;
        Ok(match domain {
            AnalysisDomain::Container => Self::Container(value),
            AnalysisDomain::Header => Self::Header(value),
            AnalysisDomain::LoadCommands => Self::LoadCommands(value),
            AnalysisDomain::Segments => Self::Segments(value),
            AnalysisDomain::Relocations => Self::Relocations(value),
            AnalysisDomain::Symbols => Self::Symbols(value),
            AnalysisDomain::Exports => Self::Exports(value),
            AnalysisDomain::Imports => Self::Imports(value),
            AnalysisDomain::Fixups => Self::Fixups(value),
            AnalysisDomain::Codesign => Self::Codesign(value),
            AnalysisDomain::Objc => Self::Objc(value),
            AnalysisDomain::Swift => Self::Swift(value),
            AnalysisDomain::Dwarf => Self::Dwarf(value),
            AnalysisDomain::Vtables => Self::Vtables(value),
            AnalysisDomain::Strings => Self::Strings(value),
            AnalysisDomain::Ranges => Self::Ranges(value),
            AnalysisDomain::Xrefs => Self::Xrefs(value),
            AnalysisDomain::Dependencies => Self::Dependencies(value),
            AnalysisDomain::Audit => Self::Audit(value),
            AnalysisDomain::CSurface => Self::CSurface(value),
            AnalysisDomain::CppSurface => Self::CppSurface(value),
            AnalysisDomain::ObjcHeaders => Self::ObjcHeaders(value),
        })
    }

    /// Returns the domain discriminant.
    pub const fn domain(&self) -> AnalysisDomain {
        match self {
            Self::Container(_) => AnalysisDomain::Container,
            Self::Header(_) => AnalysisDomain::Header,
            Self::LoadCommands(_) => AnalysisDomain::LoadCommands,
            Self::Segments(_) => AnalysisDomain::Segments,
            Self::Relocations(_) => AnalysisDomain::Relocations,
            Self::Symbols(_) => AnalysisDomain::Symbols,
            Self::Exports(_) => AnalysisDomain::Exports,
            Self::Imports(_) => AnalysisDomain::Imports,
            Self::Fixups(_) => AnalysisDomain::Fixups,
            Self::Codesign(_) => AnalysisDomain::Codesign,
            Self::Objc(_) => AnalysisDomain::Objc,
            Self::Swift(_) => AnalysisDomain::Swift,
            Self::Dwarf(_) => AnalysisDomain::Dwarf,
            Self::Vtables(_) => AnalysisDomain::Vtables,
            Self::Strings(_) => AnalysisDomain::Strings,
            Self::Ranges(_) => AnalysisDomain::Ranges,
            Self::Xrefs(_) => AnalysisDomain::Xrefs,
            Self::Dependencies(_) => AnalysisDomain::Dependencies,
            Self::Audit(_) => AnalysisDomain::Audit,
            Self::CSurface(_) => AnalysisDomain::CSurface,
            Self::CppSurface(_) => AnalysisDomain::CppSurface,
            Self::ObjcHeaders(_) => AnalysisDomain::ObjcHeaders,
        }
    }

    /// Returns the validated domain report value.
    pub const fn value(&self) -> &Value {
        match self {
            Self::Container(value)
            | Self::Header(value)
            | Self::LoadCommands(value)
            | Self::Segments(value)
            | Self::Relocations(value)
            | Self::Symbols(value)
            | Self::Exports(value)
            | Self::Imports(value)
            | Self::Fixups(value)
            | Self::Codesign(value)
            | Self::Objc(value)
            | Self::Swift(value)
            | Self::Dwarf(value)
            | Self::Vtables(value)
            | Self::Strings(value)
            | Self::Ranges(value)
            | Self::Xrefs(value)
            | Self::Dependencies(value)
            | Self::Audit(value)
            | Self::CSurface(value)
            | Self::CppSurface(value)
            | Self::ObjcHeaders(value) => value,
        }
    }
}

fn validate_typed_payload(domain: AnalysisDomain, value: Value) -> Result<Value, String> {
    use crate::report::{ObjCReport, RecoveryLanguage, RecoveryReport, SwiftReport};

    match domain {
        AnalysisDomain::Objc => {
            let report: ObjCReport = serde_json::from_value(value)
                .map_err(|error| format!("invalid objc report: {error}"))?;
            report
                .validate()
                .map_err(|error| format!("invalid objc report: {error}"))?;
            serde_json::to_value(report)
                .map_err(|error| format!("cannot serialize objc report: {error}"))
        }
        AnalysisDomain::Swift => {
            let report: SwiftReport = serde_json::from_value(value)
                .map_err(|error| format!("invalid swift report: {error}"))?;
            report
                .validate()
                .map_err(|error| format!("invalid swift report: {error}"))?;
            serde_json::to_value(report)
                .map_err(|error| format!("cannot serialize swift report: {error}"))
        }
        AnalysisDomain::CSurface | AnalysisDomain::CppSurface => {
            let report: RecoveryReport = serde_json::from_value(value)
                .map_err(|error| format!("invalid {} report: {error}", domain.as_str()))?;
            let expected = if domain == AnalysisDomain::CSurface {
                RecoveryLanguage::CAbi
            } else {
                RecoveryLanguage::Cpp
            };
            if report.language != expected {
                return Err(format!(
                    "{} payload carries {:?} recovery data",
                    domain.as_str(),
                    report.language
                ));
            }
            report
                .validate()
                .map_err(|error| format!("invalid {} report: {error}", domain.as_str()))?;
            serde_json::to_value(report)
                .map_err(|error| format!("cannot serialize {} report: {error}", domain.as_str()))
        }
        AnalysisDomain::ObjcHeaders => {
            let report: ObjCReport = serde_json::from_value(value)
                .map_err(|error| format!("invalid objc_headers report: {error}"))?;
            report
                .validate()
                .map_err(|error| format!("invalid objc_headers report: {error}"))?;
            if report
                .slices
                .as_slice()
                .iter()
                .any(|slice| slice.header.is_none())
            {
                return Err(
                    "objc_headers report contains a slice without a header projection".into(),
                );
            }
            serde_json::to_value(report)
                .map_err(|error| format!("cannot serialize objc_headers report: {error}"))
        }
        _ => Ok(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_payloads_reject_mismatched_and_unversioned_reports() {
        let unversioned = serde_json::json!({
            "kind": "swift",
            "report_schema": 1,
            "report": {"slices": []}
        });
        assert!(serde_json::from_value::<DomainPayload>(unversioned).is_err());

        let mismatched = serde_json::json!({
            "kind": "c_surface",
            "report_schema": 1,
            "report": {"schema_version": 1, "slices": []}
        });
        assert!(serde_json::from_value::<DomainPayload>(mismatched).is_err());
    }
}
