use crate::container::{FilesetEntryInspection, FilesetMemberReport};
use crate::format::parse;
use crate::model::container::{FatBinary, MachoContainer};
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

/// Structural fileset-member inspection for fat containers.
pub trait FatBinaryExt {
    /// Inspect every entry with the requested identifier across all slices.
    fn inspect_fileset_entry(&self, entry_id: &str) -> Vec<FilesetEntryInspection>;
}

impl FatBinaryExt for FatBinary<'_> {
    fn inspect_fileset_entry(&self, entry_id: &str) -> Vec<FilesetEntryInspection> {
        self.arches()
            .iter()
            .flat_map(|arch| {
                inspect_fileset_entry_in_macho(arch.macho(), &arch.spec().name(), entry_id)
            })
            .collect()
    }
}

/// Structural fileset-member inspection for parsed containers.
pub trait MachoContainerExt {
    /// Inspect every entry with the requested identifier across selected slices.
    fn inspect_fileset_entry(&self, entry_id: &str) -> Vec<FilesetEntryInspection>;
}

impl MachoContainerExt for MachoContainer<'_> {
    fn inspect_fileset_entry(&self, entry_id: &str) -> Vec<FilesetEntryInspection> {
        match self {
            Self::Thin(macho) => {
                inspect_fileset_entry_in_macho(macho, macho.header().cpu_type().name(), entry_id)
            }
            Self::Fat(fat) => fat.inspect_fileset_entry(entry_id),
        }
    }
}

fn inspect_fileset_entry_in_macho(
    macho: &MachoFile<'_>,
    arch: &str,
    entry_id: &str,
) -> Vec<FilesetEntryInspection> {
    macho
        .load_commands()
        .iter()
        .filter_map(|command| match command.kind() {
            LoadCommand::FilesetEntry(data) if data.entry_id == entry_id => Some(data),
            _ => None,
        })
        .map(|data| {
            let (member, parse_error) = inspect_fileset_member(macho, data.file_offset);
            FilesetEntryInspection {
                arch: arch.to_owned(),
                entry_id: data.entry_id.clone(),
                vm_addr: data.vm_addr,
                file_offset: data.file_offset,
                member,
                parse_error,
            }
        })
        .collect()
}

fn inspect_fileset_member(
    macho: &MachoFile<'_>,
    file_offset: u64,
) -> (Option<FilesetMemberReport>, Option<String>) {
    let Ok(offset) = usize::try_from(file_offset) else {
        return (
            None,
            Some(format!("member offset {file_offset:#x} is too large")),
        );
    };
    if offset >= macho.bytes().len() {
        return (
            None,
            Some(format!(
                "member offset {file_offset:#x} is outside image bounds ({:#x} bytes)",
                macho.bytes().len()
            )),
        );
    }
    match parse(&macho.bytes()[offset..]) {
        Ok(member) => {
            let Some(member_mach) = member.first_macho() else {
                return (
                    None,
                    Some("parsed member contains no Mach-O image".to_owned()),
                );
            };
            (
                Some(FilesetMemberReport {
                    file_type: member_mach.header().file_type().name().to_owned(),
                    cpu: member_mach.header().cpu_type().to_string(),
                    load_commands: member_mach.load_commands().len(),
                    segments: member_mach.segments().len(),
                }),
                None,
            )
        }
        Err(error) => (None, Some(error.to_string())),
    }
}
