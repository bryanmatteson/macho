//! Raw 64-bit Objective-C runtime structures.

use zerocopy::{FromBytes, Immutable, KnownLayout};

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawObjCClass64 type.
pub struct RawObjCClass64 {
    /// The isa field.
    pub isa: u64,
    /// The superclass field.
    pub superclass: u64,
    /// The cache field.
    pub cache: u64,
    /// The vtable field.
    pub vtable: u64,
    /// The data field.
    pub data: u64, // pointer to class_ro_t (bit 0 = swift flag in some ABIs)
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawClassRoT64 type.
pub struct RawClassRoT64 {
    /// The flags field.
    pub flags: u32,
    /// The instance_start field.
    pub instance_start: u32,
    /// The instance_size field.
    pub instance_size: u32,
    /// The reserved field.
    pub reserved: u32,
    /// The ivar_layout field.
    pub ivar_layout: u64,
    /// The name field.
    pub name: u64,
    /// The base_methods field.
    pub base_methods: u64,
    /// The base_protocols field.
    pub base_protocols: u64,
    /// The ivars field.
    pub ivars: u64,
    /// The weak_ivar_layout field.
    pub weak_ivar_layout: u64,
    /// The base_properties field.
    pub base_properties: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawMethodListHeader type.
pub struct RawMethodListHeader {
    /// The entsize_and_flags field.
    pub entsize_and_flags: u32,
    /// The count field.
    pub count: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawMethodT type.
pub struct RawMethodT {
    /// The name field.
    pub name: u64,
    /// The types field.
    pub types: u64,
    /// The imp field.
    pub imp: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawRelativeMethodT type.
pub struct RawRelativeMethodT {
    /// The name_offset field.
    pub name_offset: i32,
    /// The types_offset field.
    pub types_offset: i32,
    /// The imp_offset field.
    pub imp_offset: i32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawIvarT64 type.
pub struct RawIvarT64 {
    /// The offset_ptr field.
    pub offset_ptr: u64,
    /// The name field.
    pub name: u64,
    /// The type_encoding field.
    pub type_encoding: u64,
    /// The alignment field.
    pub alignment: u32,
    /// The size field.
    pub size: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawPropertyT type.
pub struct RawPropertyT {
    /// The name field.
    pub name: u64,
    /// The attributes field.
    pub attributes: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawProtocolT64 type.
pub struct RawProtocolT64 {
    /// The isa field.
    pub isa: u64,
    /// The name field.
    pub name: u64,
    /// The protocols field.
    pub protocols: u64,
    /// The instance_methods field.
    pub instance_methods: u64,
    /// The class_methods field.
    pub class_methods: u64,
    /// The optional_instance_methods field.
    pub optional_instance_methods: u64,
    /// The optional_class_methods field.
    pub optional_class_methods: u64,
    /// The instance_properties field.
    pub instance_properties: u64,
    /// The size field.
    pub size: u32,
    /// The flags field.
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawCategoryT64 type.
pub struct RawCategoryT64 {
    /// The name field.
    pub name: u64,
    /// The cls field.
    pub cls: u64,
    /// The instance_methods field.
    pub instance_methods: u64,
    /// The class_methods field.
    pub class_methods: u64,
    /// The protocols field.
    pub protocols: u64,
}
