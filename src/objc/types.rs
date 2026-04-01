use crate::addr::Va;
use crate::objc::encoding::{ObjCMethodSignature, ObjCPropertyAttributes, ObjCQualifiedType};
use std::fmt;

#[derive(Debug, Clone)]
pub struct ObjCClass {
    pub name: String,
    pub superclass_name: Option<String>,
    pub instance_methods: Vec<ObjCMethod>,
    pub class_methods: Vec<ObjCMethod>,
    pub ivars: Vec<ObjCIvar>,
    pub properties: Vec<ObjCProperty>,
    pub protocols: Vec<String>,
    pub instance_size: u32,
    pub is_meta: bool,
    pub is_swift: bool,
}

#[derive(Debug, Clone)]
pub struct ObjCCategory {
    pub name: String,
    pub class_name: String,
    pub instance_methods: Vec<ObjCMethod>,
    pub class_methods: Vec<ObjCMethod>,
    pub properties: Vec<ObjCProperty>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ObjCProtocol {
    pub name: String,
    pub instance_methods: Vec<ObjCMethod>,
    pub class_methods: Vec<ObjCMethod>,
    pub optional_instance_methods: Vec<ObjCMethod>,
    pub optional_class_methods: Vec<ObjCMethod>,
    pub properties: Vec<ObjCProperty>,
    pub adopted_protocols: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ObjCMethod {
    pub name: String,
    pub type_encoding: String,
    pub imp: Va,
}

impl fmt::Display for ObjCMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.type_encoding)
    }
}

impl ObjCMethod {
    pub fn parsed_signature(&self) -> Option<ObjCMethodSignature> {
        ObjCMethodSignature::parse(&self.type_encoding).ok()
    }
}

#[derive(Debug, Clone)]
pub struct ObjCIvar {
    pub name: String,
    pub type_encoding: String,
    pub offset: u32,
    pub size: u32,
    pub alignment: u32,
}

impl ObjCIvar {
    pub fn parsed_type(&self) -> Option<ObjCQualifiedType> {
        ObjCQualifiedType::parse(&self.type_encoding).ok()
    }
}

#[derive(Debug, Clone)]
pub struct ObjCProperty {
    pub name: String,
    pub attributes: String,
    pub is_class: bool,
}

impl ObjCProperty {
    pub fn parsed_attributes(&self) -> ObjCPropertyAttributes {
        ObjCPropertyAttributes::parse(&self.attributes)
    }
}

// ObjC class_ro_t flags
pub const RO_META: u32 = 1 << 0;
pub const RO_ROOT: u32 = 1 << 1;
pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 2;
pub const RO_HIDDEN: u32 = 1 << 4;
pub const RO_IS_ARC: u32 = 1 << 7;
pub const RO_HAS_CXX_DTOR_ONLY: u32 = 1 << 8;

// method_list_t flags
pub const METHOD_LIST_USES_RELATIVE_OFFSETS: u32 = 0x8000_0000;
pub const METHOD_LIST_ENTSIZE_MASK: u32 = 0x0000_FFFF;
