use serde::Serialize;

use crate::model::load_command::{LoadCommand, format_uuid};
use crate::model::macho_file::MachoFile;

#[derive(Debug, Clone, Serialize)]
/// The ImageInfo type.
pub struct ImageInfo {
    /// The arch field.
    pub arch: String,
    /// The file_type field.
    pub file_type: String,
    /// The uuid field.
    pub uuid: Option<String>,
    /// The image_base field.
    pub image_base: u64,
    /// The platform field.
    pub platform: Option<PlatformInfo>,
    /// The source_version field.
    pub source_version: Option<String>,
    /// The install_name field.
    pub install_name: Option<String>,
    /// The linked_dylibs field.
    pub linked_dylibs: Vec<LinkedDylib>,
    /// The rpaths field.
    pub rpaths: Vec<String>,
    /// The target_triple field.
    pub target_triple: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
/// The PlatformInfo type.
pub struct PlatformInfo {
    /// The platform field.
    pub platform: String,
    /// The min_os field.
    pub min_os: String,
    /// The sdk field.
    pub sdk: String,
}

#[derive(Debug, Clone, Serialize)]
/// The LinkedDylib type.
pub struct LinkedDylib {
    /// The name field.
    pub name: String,
    /// The ordinal field.
    pub ordinal: usize,
    /// The current_version field.
    pub current_version: String,
    /// The compat_version field.
    pub compat_version: String,
    /// The kind field.
    pub kind: DylibLinkKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The DylibLinkKind type.
#[non_exhaustive]
pub enum DylibLinkKind {
    /// The Required variant.
    Required,
    /// The Weak variant.
    Weak,
    /// The Reexport variant.
    Reexport,
    /// The Lazy variant.
    Lazy,
    /// The Upward variant.
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
    /// Performs from_mach.
    pub fn from_mach(macho: &MachoFile<'_>) -> Self {
        let header = macho.header();
        let arch = header.cpu_type().name().to_string();
        let file_type = header.file_type().name().to_string();
        let uuid = macho.uuid().map(format_uuid);
        let image_base = macho.image_base().0;

        let platform = extract_platform(macho);
        let source_version = extract_source_version(macho);
        let install_name = extract_install_name(macho);
        let linked_dylibs = extract_linked_dylibs(macho);
        let rpaths = extract_rpaths(macho);
        let target_triple = extract_target_triple(macho);

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

/// Performs extract_platform.
pub fn extract_platform(macho: &MachoFile<'_>) -> Option<PlatformInfo> {
    if let Some(bv) = macho
        .load_commands()
        .iter()
        .find_map(|lc| lc.kind().as_build_version())
    {
        return Some(PlatformInfo {
            platform: bv.platform.name().to_string(),
            min_os: bv.minos.to_string(),
            sdk: bv.sdk.to_string(),
        });
    }

    for lc in macho.load_commands() {
        match lc.kind() {
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

/// Performs extract_source_version.
pub fn extract_source_version(macho: &MachoFile<'_>) -> Option<String> {
    macho.load_commands().iter().find_map(|lc| {
        if let LoadCommand::SourceVersion(d) = lc.kind() {
            Some(d.version.to_string())
        } else {
            None
        }
    })
}

/// Performs extract_install_name.
pub fn extract_install_name(macho: &MachoFile<'_>) -> Option<String> {
    macho.load_commands().iter().find_map(|lc| {
        if let LoadCommand::IdDylib(d) = lc.kind() {
            Some(d.name.clone())
        } else {
            None
        }
    })
}

/// Performs extract_linked_dylibs.
pub fn extract_linked_dylibs(macho: &MachoFile<'_>) -> Vec<LinkedDylib> {
    let mut dylibs = Vec::new();
    let mut ordinal: usize = 1;

    for lc in macho.load_commands() {
        let (data, kind) = match lc.kind() {
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

/// Performs extract_rpaths.
pub fn extract_rpaths(macho: &MachoFile<'_>) -> Vec<String> {
    macho
        .load_commands()
        .iter()
        .filter_map(|lc| lc.kind().as_rpath().map(|s| s.to_string()))
        .collect()
}

/// Performs extract_target_triple.
pub fn extract_target_triple(macho: &MachoFile<'_>) -> Option<String> {
    macho.load_commands().iter().find_map(|lc| {
        if let LoadCommand::TargetTriple(d) = lc.kind() {
            Some(d.value.clone())
        } else {
            None
        }
    })
}
