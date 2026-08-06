use crate::core::format::constants::{SegmentFlags, VmProtection};
use crate::core::model::addr::{ThinFileOffset, Va};
use crate::core::model::names::SegmentName;
use crate::core::model::section::Section;

#[derive(Debug, Clone)]
/// The Segment type.
pub struct Segment {
    pub(crate) name: SegmentName,
    pub(crate) vm_addr: Va,
    pub(crate) vm_size: u64,
    pub(crate) file_offset: ThinFileOffset,
    pub(crate) file_size: u64,
    pub(crate) max_prot: VmProtection,
    pub(crate) init_prot: VmProtection,
    pub(crate) flags: SegmentFlags,
    pub(crate) sections: Vec<Section>,
}

impl Segment {
    /// Fixed-width segment name.
    pub const fn name(&self) -> &SegmentName {
        &self.name
    }
    /// Segment virtual start address.
    pub const fn vm_addr(&self) -> Va {
        self.vm_addr
    }
    /// Segment virtual size in bytes.
    pub const fn vm_size(&self) -> u64 {
        self.vm_size
    }
    /// Slice-relative start of file-backed bytes.
    pub const fn file_offset(&self) -> ThinFileOffset {
        self.file_offset
    }
    /// File-backed length in bytes.
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }
    /// Maximum virtual-memory protections.
    pub const fn max_prot(&self) -> VmProtection {
        self.max_prot
    }
    /// Initial virtual-memory protections.
    pub const fn init_prot(&self) -> VmProtection {
        self.init_prot
    }
    /// Parsed segment flags.
    pub const fn flags(&self) -> SegmentFlags {
        self.flags
    }
    /// Validated sections in load-command order.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }
}
