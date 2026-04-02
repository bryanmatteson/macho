use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;

pub use macho_core::rtti::{
    CppBaseClass, CppConfidence, CppEvidence, CppEvidenceKind, CppTypeInfoKind, CppTypeInfoNode,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct QualifiedName {
    pub components: Vec<String>,
}

impl QualifiedName {
    pub fn new(components: Vec<String>) -> Self {
        Self { components }
    }

    pub fn from_text(name: &str) -> Self {
        Self {
            components: split_qualified_name(name),
        }
    }

    pub fn leaf(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    pub fn parent(&self) -> Option<Self> {
        if self.components.len() <= 1 {
            None
        } else {
            Some(Self {
                components: self.components[..self.components.len() - 1].to_vec(),
            })
        }
    }

    pub fn as_string(&self) -> String {
        self.components.join("::")
    }
}

impl fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CppType {
    Builtin {
        spelling: String,
    },
    Named {
        name: QualifiedName,
    },
    TemplateInstance {
        base: QualifiedName,
        args: Vec<CppType>,
    },
    Pointer {
        inner: Box<CppType>,
    },
    LvalueRef {
        inner: Box<CppType>,
    },
    RvalueRef {
        inner: Box<CppType>,
    },
    Qualified {
        is_const: bool,
        is_volatile: bool,
        inner: Box<CppType>,
    },
    FunctionPointer {
        result: Box<CppType>,
        params: Vec<CppType>,
    },
    Spelled {
        spelling: String,
    },
    Unknown {
        label: String,
    },
}

impl CppType {
    pub fn render(&self) -> String {
        match self {
            Self::Builtin { spelling } => spelling.clone(),
            Self::Named { name } => name.as_string(),
            Self::TemplateInstance { base, args } => format!(
                "{}<{}>",
                base,
                args.iter().map(Self::render).collect::<Vec<_>>().join(", ")
            ),
            Self::Pointer { inner } => format!("{}*", inner.render()),
            Self::LvalueRef { inner } => format!("{}&", inner.render()),
            Self::RvalueRef { inner } => format!("{}&&", inner.render()),
            Self::Qualified {
                is_const,
                is_volatile,
                inner,
            } => {
                let mut out = inner.render();
                if *is_const {
                    out.push_str(" const");
                }
                if *is_volatile {
                    out.push_str(" volatile");
                }
                out
            }
            Self::FunctionPointer { result, params } => format!(
                "{} (*)({})",
                result.render(),
                params
                    .iter()
                    .map(Self::render)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Spelled { spelling } => spelling.clone(),
            Self::Unknown { label } => label.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppRefQualifier {
    Lvalue,
    Rvalue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CppParameter {
    pub name: String,
    pub ty: CppType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CppFunctionSignature {
    pub return_type: Option<CppType>,
    pub params: Vec<CppParameter>,
    pub is_const: bool,
    pub is_volatile: bool,
    pub ref_qualifier: Option<CppRefQualifier>,
    pub noexcept: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppThunkKind {
    Virtual,
    NonVirtual,
    Override,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppSpecialSymbol {
    VirtualTable {
        class_name: String,
    },
    TypeInfo {
        class_name: String,
    },
    TypeInfoName {
        class_name: String,
    },
    Thunk {
        kind: CppThunkKind,
        target: String,
        adjustment: Option<i64>,
    },
    Other {
        description: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CppFunctionDecl {
    pub mangled_name: String,
    pub demangled_name: String,
    pub name: QualifiedName,
    pub signature: CppFunctionSignature,
    pub address: Option<u64>,
    pub is_method: bool,
    pub is_constructor: bool,
    pub is_destructor: bool,
    pub is_operator: bool,
    pub is_virtual: bool,
    pub is_thunk: bool,
    pub evidence: Vec<CppEvidence>,
    pub body_analysis: Option<CppBodyAnalysis>,
}

impl CppFunctionDecl {
    pub fn signature_key(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.name.as_string());
        out.push('(');
        out.push_str(
            &self
                .signature
                .params
                .iter()
                .map(|param| param.ty.render())
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push(')');
        if self.signature.is_const {
            out.push_str(" const");
        }
        if self.signature.is_volatile {
            out.push_str(" volatile");
        }
        if let Some(ref_qualifier) = &self.signature.ref_qualifier {
            match ref_qualifier {
                CppRefQualifier::Lvalue => out.push_str(" &"),
                CppRefQualifier::Rvalue => out.push_str(" &&"),
            }
        }
        out
    }

    pub fn overload_key(&self) -> String {
        format!(
            "{}|ctor:{}|dtor:{}|noexcept:{}",
            self.signature_key(),
            self.is_constructor,
            self.is_destructor,
            self.signature.noexcept
        )
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CppSymbolKind {
    Function { decl: CppFunctionDecl },
    Data { name: QualifiedName },
    Special { detail: CppSpecialSymbol },
    Unknown { demangled: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct CppSymbolRecord {
    pub mangled_name: String,
    pub demangled_name: Option<String>,
    pub address: Option<u64>,
    pub kind: CppSymbolKind,
    pub confidence: CppConfidence,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppVtableSlotKind {
    OffsetToTop,
    TypeInfo,
    Method,
    PureVirtual,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppVtableSlot {
    pub index: usize,
    pub offset: u64,
    pub kind: CppVtableSlotKind,
    pub target_name: Option<String>,
    pub target_va: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppVtableGroup {
    pub name: String,
    pub mangled_name: Option<String>,
    pub address: u64,
    pub size: u64,
    pub slots: Vec<CppVtableSlot>,
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppReturnChannel {
    Unknown,
    GeneralPurpose,
    FloatingPoint,
    AggregateIndirect,
    PointerLike,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppBodyKind {
    Standard,
    Thunk,
    Stub,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppBodyAnalysis {
    pub arch: String,
    pub kind: CppBodyKind,
    pub return_channel: CppReturnChannel,
    pub this_adjustment: Option<i64>,
    pub likely_wrapper: bool,
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppClass {
    pub name: String,
    pub bases: Vec<CppBaseClass>,
    pub methods: Vec<CppFunctionDecl>,
    pub vtables: Vec<CppVtableGroup>,
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppHeaderMatch {
    pub declaration: String,
    pub header: String,
    pub confidence: CppConfidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppImageInfo {
    pub arch: String,
    pub uuid: Option<String>,
    pub install_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppImageIndex {
    pub image: CppImageInfo,
    pub symbols: Vec<CppSymbolRecord>,
    pub typeinfos: BTreeMap<String, CppTypeInfoNode>,
    pub classes: BTreeMap<String, CppClass>,
    pub free_functions: Vec<CppFunctionDecl>,
    pub header_matches: Vec<CppHeaderMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppUnifiedIndex {
    pub images: Vec<CppImageInfo>,
    pub classes: BTreeMap<String, CppClass>,
    pub free_functions: Vec<CppFunctionDecl>,
    pub header_matches: Vec<CppHeaderMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppHeaderUnit {
    pub name: String,
    pub includes: Vec<String>,
    pub helpers: Vec<String>,
    pub classes: Vec<CppClass>,
    pub free_functions: Vec<CppFunctionDecl>,
    pub unresolved: Vec<String>,
}

fn split_qualified_name(name: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut angle_depth = 0usize;
    let mut paren_depth = 0usize;
    let bytes = name.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] as char {
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ':' if angle_depth == 0 && paren_depth == 0 => {
                if index + 1 < bytes.len() && bytes[index + 1] == b':' {
                    parts.push(name[start..index].trim().to_string());
                    index += 1;
                    start = index + 1;
                }
            }
            _ => {}
        }
        index += 1;
    }
    if start < name.len() {
        parts.push(name[start..].trim().to_string());
    }
    parts.retain(|part| !part.is_empty());
    parts
}
