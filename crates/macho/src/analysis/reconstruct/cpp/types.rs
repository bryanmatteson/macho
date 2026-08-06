use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;

pub use crate::metadata::cpp::{
    ArgumentTypeHint, CppBaseClass, CppBodyAnalysis, CppBodyKind, CppConfidence, CppEvidence,
    CppEvidenceKind, CppReturnChannel, CppTypeInfoKind, CppTypeInfoNode,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
/// The QualifiedName type.
pub struct QualifiedName {
    /// The components field.
    pub components: Vec<String>,
}

impl QualifiedName {
    /// Performs new.
    pub fn new(components: Vec<String>) -> Self {
        Self { components }
    }

    /// Performs from_text.
    pub fn from_text(name: &str) -> Self {
        Self {
            components: split_qualified_name(name),
        }
    }

    /// Performs leaf.
    pub fn leaf(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    /// Performs parent.
    pub fn parent(&self) -> Option<Self> {
        if self.components.len() <= 1 {
            None
        } else {
            Some(Self {
                components: self.components[..self.components.len() - 1].to_vec(),
            })
        }
    }

    /// Performs as_string.
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
/// The CppType type.
#[non_exhaustive]
pub enum CppType {
    /// The Builtin variant.
    Builtin {
        /// The String field.
        spelling: String,
    },
    /// The Named variant.
    Named {
        /// The QualifiedName field.
        name: QualifiedName,
    },
    /// The TemplateInstance variant.
    TemplateInstance {
        /// The QualifiedName field.
        base: QualifiedName,
        /// The item field.
        args: Vec<CppType>,
    },
    /// The Pointer variant.
    Pointer {
        /// The item field.
        inner: Box<CppType>,
    },
    /// The LvalueRef variant.
    LvalueRef {
        /// The item field.
        inner: Box<CppType>,
    },
    /// The RvalueRef variant.
    RvalueRef {
        /// The item field.
        inner: Box<CppType>,
    },
    /// The Qualified variant.
    Qualified {
        /// The bool field.
        is_const: bool,
        /// The bool field.
        is_volatile: bool,
        /// The item field.
        inner: Box<CppType>,
    },
    /// The FunctionPointer variant.
    FunctionPointer {
        /// The item field.
        result: Box<CppType>,
        /// The item field.
        params: Vec<CppType>,
    },
    /// The Spelled variant.
    Spelled {
        /// The String field.
        spelling: String,
    },
    /// The Unknown variant.
    Unknown {
        /// The String field.
        label: String,
    },
}

impl CppType {
    /// Performs render.
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
/// The CppRefQualifier type.
#[non_exhaustive]
pub enum CppRefQualifier {
    /// The Lvalue variant.
    Lvalue,
    /// The Rvalue variant.
    Rvalue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CppParameter type.
pub struct CppParameter {
    /// The name field.
    pub name: String,
    /// The ty field.
    pub ty: CppType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CppFunctionSignature type.
pub struct CppFunctionSignature {
    /// The return_type field.
    pub return_type: Option<CppType>,
    /// The params field.
    pub params: Vec<CppParameter>,
    /// The is_const field.
    pub is_const: bool,
    /// The is_volatile field.
    pub is_volatile: bool,
    /// The ref_qualifier field.
    pub ref_qualifier: Option<CppRefQualifier>,
    /// The noexcept field.
    pub noexcept: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppThunkKind type.
#[non_exhaustive]
pub enum CppThunkKind {
    /// The Virtual variant.
    Virtual,
    /// The NonVirtual variant.
    NonVirtual,
    /// The Override variant.
    Override,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppSpecialSymbol type.
#[non_exhaustive]
pub enum CppSpecialSymbol {
    /// The VirtualTable variant.
    VirtualTable {
        /// The String field.
        class_name: String,
    },
    /// The TypeInfo variant.
    TypeInfo {
        /// The String field.
        class_name: String,
    },
    /// The TypeInfoName variant.
    TypeInfoName {
        /// The String field.
        class_name: String,
    },
    /// The Thunk variant.
    Thunk {
        /// The CppThunkKind field.
        kind: CppThunkKind,
        /// The String field.
        target: String,
        /// The item field.
        adjustment: Option<i64>,
    },
    /// The Other variant.
    Other {
        /// The String field.
        description: String,
    },
}

#[derive(Debug, Clone, Serialize)]
/// The CppFunctionDecl type.
pub struct CppFunctionDecl {
    /// The mangled_name field.
    pub mangled_name: String,
    /// The demangled_name field.
    pub demangled_name: String,
    /// The name field.
    pub name: QualifiedName,
    /// The signature field.
    pub signature: CppFunctionSignature,
    /// The address field.
    pub address: Option<u64>,
    /// The is_method field.
    pub is_method: bool,
    /// The is_constructor field.
    pub is_constructor: bool,
    /// The is_destructor field.
    pub is_destructor: bool,
    /// The is_operator field.
    pub is_operator: bool,
    /// The is_virtual field.
    pub is_virtual: bool,
    /// The is_thunk field.
    pub is_thunk: bool,
    /// The evidence field.
    pub evidence: Vec<CppEvidence>,
    /// The body_analysis field.
    pub body_analysis: Option<CppBodyAnalysis>,
}

impl CppFunctionDecl {
    /// Performs signature_key.
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

    /// Performs overload_key.
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
/// The CppSymbolKind type.
#[non_exhaustive]
pub enum CppSymbolKind {
    /// The Function variant.
    Function {
        #[doc = "The decl field."]
        decl: Box<CppFunctionDecl>,
    },
    /// The Data variant.
    Data {
        #[doc = "The name field."]
        name: QualifiedName,
    },
    /// The Special variant.
    Special {
        #[doc = "The detail field."]
        detail: CppSpecialSymbol,
    },
    /// The Unknown variant.
    Unknown {
        #[doc = "The demangled field."]
        demangled: String,
    },
}

#[derive(Debug, Clone, Serialize)]
/// The CppSymbolRecord type.
pub struct CppSymbolRecord {
    /// The mangled_name field.
    pub mangled_name: String,
    /// The demangled_name field.
    pub demangled_name: Option<String>,
    /// The address field.
    pub address: Option<u64>,
    /// The kind field.
    pub kind: CppSymbolKind,
    /// The confidence field.
    pub confidence: CppConfidence,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppVtableSlotKind type.
#[non_exhaustive]
pub enum CppVtableSlotKind {
    /// The OffsetToTop variant.
    OffsetToTop,
    /// The TypeInfo variant.
    TypeInfo,
    /// The Method variant.
    Method,
    /// The PureVirtual variant.
    PureVirtual,
    /// The Unknown variant.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
/// The CppVtableSlot type.
pub struct CppVtableSlot {
    /// The index field.
    pub index: usize,
    /// The offset field.
    pub offset: u64,
    /// The kind field.
    pub kind: CppVtableSlotKind,
    /// The target_name field.
    pub target_name: Option<String>,
    /// The target_va field.
    pub target_va: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppVtableGroup type.
pub struct CppVtableGroup {
    /// The name field.
    pub name: String,
    /// The mangled_name field.
    pub mangled_name: Option<String>,
    /// The address field.
    pub address: u64,
    /// The size field.
    pub size: u64,
    /// The slots field.
    pub slots: Vec<CppVtableSlot>,
    /// The evidence field.
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppClass type.
pub struct CppClass {
    /// The name field.
    pub name: String,
    /// The bases field.
    pub bases: Vec<CppBaseClass>,
    /// The methods field.
    pub methods: Vec<CppFunctionDecl>,
    /// The vtables field.
    pub vtables: Vec<CppVtableGroup>,
    /// The evidence field.
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppHeaderMatch type.
pub struct CppHeaderMatch {
    /// The declaration field.
    pub declaration: String,
    /// The header field.
    pub header: String,
    /// The confidence field.
    pub confidence: CppConfidence,
}

#[derive(Debug, Clone, Serialize)]
/// The CppImageInfo type.
pub struct CppImageInfo {
    /// The arch field.
    pub arch: String,
    /// The uuid field.
    pub uuid: Option<String>,
    /// The install_name field.
    pub install_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppImageIndex type.
pub struct CppImageIndex {
    /// The image field.
    pub image: CppImageInfo,
    /// The symbols field.
    pub symbols: Vec<CppSymbolRecord>,
    /// The typeinfos field.
    pub typeinfos: BTreeMap<String, CppTypeInfoNode>,
    /// The classes field.
    pub classes: BTreeMap<String, CppClass>,
    /// The free_functions field.
    pub free_functions: Vec<CppFunctionDecl>,
    /// The header_matches field.
    pub header_matches: Vec<CppHeaderMatch>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppUnifiedIndex type.
pub struct CppUnifiedIndex {
    /// The images field.
    pub images: Vec<CppImageInfo>,
    /// The classes field.
    pub classes: BTreeMap<String, CppClass>,
    /// The free_functions field.
    pub free_functions: Vec<CppFunctionDecl>,
    /// The header_matches field.
    pub header_matches: Vec<CppHeaderMatch>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppHeaderUnit type.
pub struct CppHeaderUnit {
    /// The name field.
    pub name: String,
    /// The includes field.
    pub includes: Vec<String>,
    /// The helpers field.
    pub helpers: Vec<String>,
    /// The classes field.
    pub classes: Vec<CppClass>,
    /// The free_functions field.
    pub free_functions: Vec<CppFunctionDecl>,
    /// The unresolved field.
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
            ':' if angle_depth == 0
                && paren_depth == 0
                && index + 1 < bytes.len()
                && bytes[index + 1] == b':' =>
            {
                parts.push(name[start..index].trim().to_string());
                index += 1;
                start = index + 1;
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
