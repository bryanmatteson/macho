use crate::format::constants::{SegmentFlags, VmProtection};
use crate::model::addr::{ThinFileOffset, Va};
use crate::model::names::SegmentName;
use crate::model::section::Section;

#[derive(Debug, Clone)]
pub struct Segment {
    pub name: SegmentName,
    pub vm_addr: Va,
    pub vm_size: u64,
    pub file_offset: ThinFileOffset,
    pub file_size: u64,
    pub max_prot: VmProtection,
    pub init_prot: VmProtection,
    pub flags: SegmentFlags,
    pub sections: Vec<Section>,
}
