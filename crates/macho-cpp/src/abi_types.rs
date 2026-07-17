//! Owned results produced by architecture-aware body inference.

use serde::Serialize;

use crate::CppEvidence;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppReturnChannel type.
#[non_exhaustive]
pub enum CppReturnChannel {
    /// The Unknown variant.
    Unknown,
    /// The GeneralPurpose variant.
    GeneralPurpose,
    /// The FloatingPoint variant.
    FloatingPoint,
    /// The AggregateIndirect variant.
    AggregateIndirect,
    /// The Void variant.
    Void,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppBodyKind type.
#[non_exhaustive]
pub enum CppBodyKind {
    /// The Standard variant.
    Standard,
    /// The Thunk variant.
    Thunk,
    /// The Stub variant.
    Stub,
    /// The Unknown variant.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "hint", rename_all = "snake_case")]
/// The ArgumentTypeHint type.
#[non_exhaustive]
pub enum ArgumentTypeHint {
    /// The Unknown variant.
    Unknown,
    /// The Scalar variant.
    Scalar,
    /// The FloatingPoint variant.
    FloatingPoint,
    /// The Pointer variant.
    Pointer,
    /// The CString variant.
    CString,
    /// The ClassPointer variant.
    ClassPointer {
        #[doc = "The class_name field."]
        class_name: String,
    },
    /// The ObjcObject variant.
    ObjcObject,
    /// The StructPointer variant.
    StructPointer,
}

#[derive(Debug, Clone, Serialize)]
/// The CppBodyAnalysis type.
pub struct CppBodyAnalysis {
    /// The arch field.
    pub arch: String,
    /// The kind field.
    pub kind: CppBodyKind,
    /// The return_channel field.
    pub return_channel: CppReturnChannel,
    /// The this_adjustment field.
    pub this_adjustment: Option<i64>,
    /// The likely_wrapper field.
    pub likely_wrapper: bool,
    /// The param_count field.
    pub param_count: Option<u32>,
    /// The argument_hints field.
    pub argument_hints: Vec<ArgumentTypeHint>,
    /// The evidence field.
    pub evidence: Vec<CppEvidence>,
}
