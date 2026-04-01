use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::fat::parse_fat_binary;
use crate::format::mach::parse_mach_file;
use crate::model::container::MachContainer;

pub fn parse(data: &[u8]) -> Result<MachContainer<'_>> {
    if data.len() < 4 {
        return Err(Error::Format("file too small to identify".into()));
    }

    let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());

    match magic {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => {
            parse_fat_binary(data).map(MachContainer::Fat)
        }
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => {
            parse_mach_file(data).map(MachContainer::Thin)
        }
        _ => Err(Error::Format(format!(
            "unrecognized file magic: {magic:#010x}"
        ))),
    }
}
