use std::fmt;

use macho_codesign::CodesignError;
use macho_core::{ContextFrame, OffsetSpan, ParseError};
use macho_cpp::CppError;
use macho_dwarf::DwarfError;
use macho_dyld::DyldError;
use macho_objc::ObjcError;
use macho_swift::SwiftError;
use macho_symbols::SymbolsError;
use serde::{Deserialize, Serialize};

const INVALID_INPUT_CODE: &str = "analysis.input.invalid";
const VALIDATION_FAILED_CODE: &str = "analysis.validation.failed";
const PARSE_FAILED_CODE: &str = "analysis.parse.failed";
pub(crate) const SYMBOLS_FAILED_CODE: &str = "analysis.symbols.failed";
const DYLD_FAILED_CODE: &str = "analysis.dyld.failed";
pub(crate) const CODESIGN_FAILED_CODE: &str = "analysis.codesign.failed";
const DWARF_FAILED_CODE: &str = "analysis.dwarf.failed";
pub(crate) const OBJC_FAILED_CODE: &str = "analysis.objc.failed";
const SWIFT_FAILED_CODE: &str = "analysis.swift.failed";
const CPP_FAILED_CODE: &str = "analysis.cpp.failed";
const UNSUPPORTED_CAPABILITY_CODE: &str = "analysis.capability.unsupported";
const DOMAIN_TYPE_MISMATCH_CODE: &str = "analysis.domain.type_mismatch";
pub(crate) const EXPORTS_FAILED_CODE: &str = "analysis.exports.failed";
pub(crate) const IMPORTS_FAILED_CODE: &str = "analysis.imports.failed";
pub(crate) const FIXUPS_FAILED_CODE: &str = "analysis.fixups.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The AnalysisDomain type.
#[non_exhaustive]
pub enum AnalysisDomain {
    /// The Container variant.
    Container,
    /// The Header variant.
    Header,
    /// The LoadCommands variant.
    LoadCommands,
    /// The Segments variant.
    Segments,
    /// The Relocations variant.
    Relocations,
    /// The Symbols variant.
    Symbols,
    /// The Exports variant.
    Exports,
    /// The Imports variant.
    Imports,
    /// The Fixups variant.
    Fixups,
    /// The Codesign variant.
    Codesign,
    /// The Objc variant.
    Objc,
    /// The Swift variant.
    Swift,
    /// The Dwarf variant.
    Dwarf,
    /// The Vtables variant.
    Vtables,
    /// The Strings variant.
    Strings,
    /// The Ranges variant.
    Ranges,
    /// The Xrefs variant.
    Xrefs,
    /// The Dependencies variant.
    Dependencies,
    /// The Audit variant.
    Audit,
    /// The CSurface variant.
    CSurface,
    /// The CppSurface variant.
    CppSurface,
    /// The ObjcHeaders variant.
    ObjcHeaders,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The AnalysisErrorKind type.
#[non_exhaustive]
pub enum AnalysisErrorKind {
    /// The InvalidInput variant.
    InvalidInput,
    /// The Validation variant.
    Validation,
    /// The Parse variant.
    Parse,
    /// The Symbols variant.
    Symbols,
    /// The Dyld variant.
    Dyld,
    /// The Codesign variant.
    Codesign,
    /// The Dwarf variant.
    Dwarf,
    /// The Objc variant.
    Objc,
    /// The Swift variant.
    Swift,
    /// The Cpp variant.
    Cpp,
    /// The UnsupportedCapability variant.
    UnsupportedCapability,
    /// A typed report key was used with a payload from another domain.
    DomainTypeMismatch,
}

#[derive(Debug)]
/// The AnalysisErrorSource type.
#[non_exhaustive]
pub enum AnalysisErrorSource {
    /// The Parse variant.
    Parse(Box<ParseError>),
    /// The Symbols variant.
    Symbols(Box<SymbolsError>),
    /// The Dyld variant.
    Dyld(Box<DyldError>),
    /// The Codesign variant.
    Codesign(Box<CodesignError>),
    /// The Dwarf variant.
    Dwarf(Box<DwarfError>),
    /// The Objc variant.
    Objc(Box<ObjcError>),
    /// The Swift variant.
    Swift(Box<SwiftError>),
    /// The Cpp variant.
    Cpp(Box<CppError>),
}

#[derive(Debug)]
/// The AnalysisError type.
pub struct AnalysisError {
    /// The domain field.
    pub domain: AnalysisDomain,
    /// The kind field.
    pub kind: AnalysisErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<AnalysisErrorSource>,
}

impl AnalysisError {
    /// Performs new.
    pub fn new(
        domain: AnalysisDomain,
        kind: AnalysisErrorKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            domain,
            kind,
            location: None,
            context: Vec::new(),
            message: message.into(),
            source: None,
        }
    }
    /// Performs invalid.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(
            AnalysisDomain::Container,
            AnalysisErrorKind::InvalidInput,
            message,
        )
    }
    /// Performs validation.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(
            AnalysisDomain::CSurface,
            AnalysisErrorKind::Validation,
            message,
        )
    }
    /// Performs message.
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Performs code.
    pub const fn code(&self) -> &'static str {
        match self.kind {
            AnalysisErrorKind::InvalidInput => INVALID_INPUT_CODE,
            AnalysisErrorKind::Validation => VALIDATION_FAILED_CODE,
            AnalysisErrorKind::Parse => PARSE_FAILED_CODE,
            AnalysisErrorKind::Symbols => SYMBOLS_FAILED_CODE,
            AnalysisErrorKind::Dyld => DYLD_FAILED_CODE,
            AnalysisErrorKind::Codesign => CODESIGN_FAILED_CODE,
            AnalysisErrorKind::Dwarf => DWARF_FAILED_CODE,
            AnalysisErrorKind::Objc => OBJC_FAILED_CODE,
            AnalysisErrorKind::Swift => SWIFT_FAILED_CODE,
            AnalysisErrorKind::Cpp => CPP_FAILED_CODE,
            AnalysisErrorKind::UnsupportedCapability => UNSUPPORTED_CAPABILITY_CODE,
            AnalysisErrorKind::DomainTypeMismatch => DOMAIN_TYPE_MISMATCH_CODE,
        }
    }
}

macro_rules! from_source {
    ($source:ty, $variant:ident, $kind:ident, $domain:ident, $operation:literal) => {
        impl From<$source> for AnalysisError {
            fn from(source: $source) -> Self {
                let mut context = source.context.clone();
                context.push(ContextFrame::Operation { name: $operation });
                Self {
                    domain: AnalysisDomain::$domain,
                    kind: AnalysisErrorKind::$kind,
                    location: source.location,
                    context,
                    message: source.message().to_owned(),
                    source: Some(AnalysisErrorSource::$variant(Box::new(source))),
                }
            }
        }
    };
}

from_source!(ParseError, Parse, Parse, Container, "analysis.parse");
from_source!(SymbolsError, Symbols, Symbols, Symbols, "analysis.symbols");
from_source!(DyldError, Dyld, Dyld, Fixups, "analysis.dyld");
from_source!(
    CodesignError,
    Codesign,
    Codesign,
    Codesign,
    "analysis.codesign"
);
from_source!(DwarfError, Dwarf, Dwarf, Dwarf, "analysis.dwarf");
from_source!(ObjcError, Objc, Objc, Objc, "analysis.objc");
from_source!(SwiftError, Swift, Swift, Swift, "analysis.swift");
from_source!(CppError, Cpp, Cpp, CppSurface, "analysis.cpp");

impl fmt::Display for AnalysisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for AnalysisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            AnalysisErrorSource::Parse(source) => source as _,
            AnalysisErrorSource::Symbols(source) => source as _,
            AnalysisErrorSource::Dyld(source) => source as _,
            AnalysisErrorSource::Codesign(source) => source as _,
            AnalysisErrorSource::Dwarf(source) => source as _,
            AnalysisErrorSource::Objc(source) => source as _,
            AnalysisErrorSource::Swift(source) => source as _,
            AnalysisErrorSource::Cpp(source) => source as _,
        })
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, AnalysisError>;
/// The Error type.
pub(crate) type Error = AnalysisError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_preserve_source_and_add_ordered_context() {
        let location = OffsetSpan {
            offset: 0x40,
            len: 8,
        };
        let parse = ParseError::command("truncated command")
            .with_location(location)
            .with_context(ContextFrame::LoadCommand { index: 3 });

        let dyld = DyldError::from(parse);
        assert_eq!(dyld.location, Some(location));
        assert_eq!(
            dyld.context,
            vec![
                ContextFrame::LoadCommand { index: 3 },
                ContextFrame::Operation { name: "dyld" },
            ]
        );
        assert!(dyld.source.is_some());

        let analysis = AnalysisError::from(dyld);
        assert_eq!(analysis.domain, AnalysisDomain::Fixups);
        assert_eq!(analysis.kind, AnalysisErrorKind::Dyld);
        assert_eq!(analysis.location, Some(location));
        assert_eq!(
            analysis.context,
            vec![
                ContextFrame::LoadCommand { index: 3 },
                ContextFrame::Operation { name: "dyld" },
                ContextFrame::Operation {
                    name: "analysis.dyld",
                },
            ]
        );
        assert!(matches!(
            analysis.source,
            Some(AnalysisErrorSource::Dyld(_))
        ));
    }
}
