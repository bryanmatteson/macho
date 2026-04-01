use serde::Serialize;

use crate::model::load_command::{LoadCommand, format_uuid};
use crate::model::mach_file::MachFile;

#[derive(Debug, Clone, Serialize)]
pub struct ImageInfo {
    pub arch: String,
    pub file_type: String,
    pub uuid: Option<String>,
    pub image_base: u64,
    pub platform: Option<PlatformInfo>,
    pub source_version: Option<String>,
    pub install_name: Option<String>,
    pub linked_dylibs: Vec<LinkedDylib>,
    pub rpaths: Vec<String>,
    pub target_triple: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformInfo {
    pub platform: String,
    pub min_os: String,
    pub sdk: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkedDylib {
    pub name: String,
    pub ordinal: usize,
    pub current_version: String,
    pub compat_version: String,
    pub kind: DylibLinkKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DylibLinkKind {
    Required,
    Weak,
    Reexport,
    Lazy,
    Upward,
}

impl std::fmt::Display for DylibLinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required => write!(f, "required"),
            Self::Weak => write!(f, "weak"),
            Self::Reexport => write!(f, "reexport"),
            Self::Lazy => write!(f, "lazy"),
            Self::Upward => write!(f, "upward"),
        }
    }
}

impl ImageInfo {
    pub fn from_mach(mach: &MachFile<'_>) -> Self {
        let header = mach.header();
        let arch = header.cpu_type.name().to_string();
        let file_type = header.file_type.name().to_string();
        let uuid = mach.uuid().map(format_uuid);
        let image_base = mach.image_base().0;

        let platform = extract_platform(mach);
        let source_version = extract_source_version(mach);
        let install_name = extract_install_name(mach);
        let linked_dylibs = extract_linked_dylibs(mach);
        let rpaths = extract_rpaths(mach);
        let target_triple = extract_target_triple(mach);

        Self {
            arch,
            file_type,
            uuid,
            image_base,
            platform,
            source_version,
            install_name,
            linked_dylibs,
            rpaths,
            target_triple,
        }
    }
}

pub fn extract_platform(mach: &MachFile<'_>) -> Option<PlatformInfo> {
    if let Some(bv) = mach
        .load_commands()
        .iter()
        .find_map(|lc| lc.kind.as_build_version())
    {
        return Some(PlatformInfo {
            platform: bv.platform.name().to_string(),
            min_os: bv.minos.to_string(),
            sdk: bv.sdk.to_string(),
        });
    }

    for lc in mach.load_commands() {
        match &lc.kind {
            LoadCommand::VersionMinMacOS(d) => {
                return Some(PlatformInfo {
                    platform: "macOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinIOS(d) => {
                return Some(PlatformInfo {
                    platform: "iOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinTvOS(d) => {
                return Some(PlatformInfo {
                    platform: "tvOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            LoadCommand::VersionMinWatchOS(d) => {
                return Some(PlatformInfo {
                    platform: "watchOS".to_string(),
                    min_os: d.version.to_string(),
                    sdk: d.sdk.to_string(),
                });
            }
            _ => {}
        }
    }

    None
}

pub fn extract_source_version(mach: &MachFile<'_>) -> Option<String> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::SourceVersion(d) = &lc.kind {
            Some(d.version.to_string())
        } else {
            None
        }
    })
}

pub fn extract_install_name(mach: &MachFile<'_>) -> Option<String> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::IdDylib(d) = &lc.kind {
            Some(d.name.clone())
        } else {
            None
        }
    })
}

pub fn extract_linked_dylibs(mach: &MachFile<'_>) -> Vec<LinkedDylib> {
    let mut dylibs = Vec::new();
    let mut ordinal: usize = 1;

    for lc in mach.load_commands() {
        let (data, kind) = match &lc.kind {
            LoadCommand::LoadDylib(d) => (d, DylibLinkKind::Required),
            LoadCommand::LoadWeakDylib(d) => (d, DylibLinkKind::Weak),
            LoadCommand::ReexportDylib(d) => (d, DylibLinkKind::Reexport),
            LoadCommand::LazyLoadDylib(d) => (d, DylibLinkKind::Lazy),
            LoadCommand::LoadUpwardDylib(d) => (d, DylibLinkKind::Upward),
            _ => continue,
        };

        dylibs.push(LinkedDylib {
            name: data.name.clone(),
            ordinal,
            current_version: data.current_version.to_string(),
            compat_version: data.compatibility_version.to_string(),
            kind,
        });
        ordinal += 1;
    }

    dylibs
}

pub fn extract_rpaths(mach: &MachFile<'_>) -> Vec<String> {
    mach.load_commands()
        .iter()
        .filter_map(|lc| lc.kind.as_rpath().map(|s| s.to_string()))
        .collect()
}

pub fn extract_target_triple(mach: &MachFile<'_>) -> Option<String> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::TargetTriple(d) = &lc.kind {
            Some(d.value.clone())
        } else {
            None
        }
    })
}
