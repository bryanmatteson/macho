use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::fat::parse_fat_binary;
use crate::format::macho::parse_macho_file;
use crate::model::container::MachoContainer;

pub fn parse(data: &[u8]) -> Result<MachoContainer<'_>> {
    if data.len() < 4 {
        return Err(Error::Format("file too small to identify".into()));
    }

    let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());

    match magic {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => {
            parse_fat_binary(data).map(MachoContainer::Fat)
        }
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => {
            parse_macho_file(data).map(MachoContainer::Thin)
        }
        _ => Err(Error::Format(format!(
            "unrecognized file magic: {magic:#010x}"
        ))),
    }
}
