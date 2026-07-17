use crate::model::addr::Va;
use crate::objc::encoding::{ObjCMethodSignature, ObjCPropertyAttributes, ObjCQualifiedType};
use std::fmt;

#[derive(Debug, Clone)]
/// The ObjCClass type.
pub struct ObjCClass {
    /// The name field.
    pub name: String,
    /// The superclass_name field.
    pub superclass_name: Option<String>,
    /// The instance_methods field.
    pub instance_methods: Vec<ObjCMethod>,
    /// The class_methods field.
    pub class_methods: Vec<ObjCMethod>,
    /// The ivars field.
    pub ivars: Vec<ObjCIvar>,
    /// The properties field.
    pub properties: Vec<ObjCProperty>,
    /// The protocols field.
    pub protocols: Vec<String>,
    /// The instance_size field.
    pub instance_size: u32,
    /// The is_meta field.
    pub is_meta: bool,
    /// The is_swift field.
    pub is_swift: bool,
}

#[derive(Debug, Clone)]
/// The ObjCCategory type.
pub struct ObjCCategory {
    /// The name field.
    pub name: String,
    /// The class_name field.
    pub class_name: String,
    /// The instance_methods field.
    pub instance_methods: Vec<ObjCMethod>,
    /// The class_methods field.
    pub class_methods: Vec<ObjCMethod>,
    /// The properties field.
    pub properties: Vec<ObjCProperty>,
    /// The protocols field.
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone)]
/// The ObjCProtocol type.
pub struct ObjCProtocol {
    /// The name field.
    pub name: String,
    /// The instance_methods field.
    pub instance_methods: Vec<ObjCMethod>,
    /// The class_methods field.
    pub class_methods: Vec<ObjCMethod>,
    /// The optional_instance_methods field.
    pub optional_instance_methods: Vec<ObjCMethod>,
    /// The optional_class_methods field.
    pub optional_class_methods: Vec<ObjCMethod>,
    /// The properties field.
    pub properties: Vec<ObjCProperty>,
    /// The adopted_protocols field.
    pub adopted_protocols: Vec<String>,
}

#[derive(Debug, Clone)]
/// The ObjCMethod type.
pub struct ObjCMethod {
    /// The name field.
    pub name: String,
    /// The type_encoding field.
    pub type_encoding: String,
    /// The imp field.
    pub imp: Va,
}

impl fmt::Display for ObjCMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.type_encoding)
    }
}

impl ObjCMethod {
    /// Performs parsed_signature.
    pub fn parsed_signature(&self) -> Option<ObjCMethodSignature> {
        ObjCMethodSignature::parse(&self.type_encoding).ok()
    }
}

#[derive(Debug, Clone)]
/// The ObjCIvar type.
pub struct ObjCIvar {
    /// The name field.
    pub name: String,
    /// The type_encoding field.
    pub type_encoding: String,
    /// The offset field.
    pub offset: u32,
    /// The size field.
    pub size: u32,
    /// The alignment field.
    pub alignment: u32,
}

impl ObjCIvar {
    /// Performs parsed_type.
    pub fn parsed_type(&self) -> Option<ObjCQualifiedType> {
        ObjCQualifiedType::parse(&self.type_encoding).ok()
    }
}

#[derive(Debug, Clone)]
/// The ObjCProperty type.
pub struct ObjCProperty {
    /// The name field.
    pub name: String,
    /// The attributes field.
    pub attributes: String,
    /// The is_class field.
    pub is_class: bool,
}

impl ObjCProperty {
    /// Performs parsed_attributes.
    pub fn parsed_attributes(&self) -> ObjCPropertyAttributes {
        ObjCPropertyAttributes::parse(&self.attributes)
    }
}

// ObjC class_ro_t flags
/// The RO_META constant.
pub const RO_META: u32 = 1 << 0;
/// The RO_ROOT constant.
pub const RO_ROOT: u32 = 1 << 1;
/// The RO_HAS_CXX_STRUCTORS constant.
pub const RO_HAS_CXX_STRUCTORS: u32 = 1 << 2;
/// The RO_HIDDEN constant.
pub const RO_HIDDEN: u32 = 1 << 4;
/// The RO_IS_ARC constant.
pub const RO_IS_ARC: u32 = 1 << 7;
/// The RO_HAS_CXX_DTOR_ONLY constant.
pub const RO_HAS_CXX_DTOR_ONLY: u32 = 1 << 8;

// method_list_t flags
/// The METHOD_LIST_USES_RELATIVE_OFFSETS constant.
pub const METHOD_LIST_USES_RELATIVE_OFFSETS: u32 = 0x8000_0000;
/// The METHOD_LIST_ENTSIZE_MASK constant.
pub const METHOD_LIST_ENTSIZE_MASK: u32 = 0x0000_FFFF;
