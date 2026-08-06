use crate::core::error::{Error, Result};
use crate::core::format::constants::*;
use crate::core::format::fat::parse_fat_binary_with_limits;
use crate::core::format::macho::parse_macho_file_with_limits;
use crate::core::format::{ParseMode, ParseOptions, ParseOutcome};
use crate::core::model::container::MachoContainer;
use crate::core::model::validate::{self, Severity};

/// Performs parse.
pub fn parse(data: &[u8]) -> Result<MachoContainer<'_>> {
    parse_with_options(data, &ParseOptions::default()).map(|outcome| outcome.container)
}

/// Performs parse_with_options.
pub fn parse_with_options<'data>(
    data: &'data [u8],
    options: &ParseOptions,
) -> Result<ParseOutcome<'data>> {
    if data.len() < 4 {
        return Err(Error::format("file too small to identify"));
    }

    let magic = u32::from_ne_bytes(data[0..4].try_into().unwrap());

    let container = match magic {
        FAT_MAGIC | FAT_CIGAM | FAT_MAGIC_64 | FAT_CIGAM_64 => {
            parse_fat_binary_with_limits(data, &options.limits).map(MachoContainer::Fat)
        }
        MH_MAGIC | MH_CIGAM | MH_MAGIC_64 | MH_CIGAM_64 => {
            parse_macho_file_with_limits(data, &options.limits).map(MachoContainer::Thin)
        }
        _ => Err(Error::format(format!(
            "unrecognized file magic: {magic:#010x}"
        ))),
    }?;

    let diagnostics = container
        .macho_files()
        .flat_map(validate::validate)
        .collect::<Vec<_>>();
    if options.mode == ParseMode::Strict
        && let Some(diagnostic) = diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error)
    {
        return Err(Error::validation(format!(
            "{}: {}",
            diagnostic.code.0, diagnostic.message
        )));
    }

    Ok(ParseOutcome {
        container,
        diagnostics,
    })
}
