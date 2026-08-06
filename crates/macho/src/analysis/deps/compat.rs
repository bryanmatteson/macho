use serde::Serialize;

use crate::analysis::Result;
use crate::analysis::deps::graph::DepGraph;
use crate::analysis::format::constants::{
    MachoHeaderFlags, PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_WATCHOS,
};
use crate::analysis::model::header::FileType;
use crate::analysis::model::load_command::{LoadCommand, Platform};
use crate::analysis::model::macho_file::MachoFile;

#[derive(Debug, Clone, Serialize)]
/// The CompatReport type.
pub struct CompatReport {
    /// The target_path field.
    pub target_path: String,
    /// The provider_path field.
    pub provider_path: Option<String>,
    /// The findings field.
    pub findings: Vec<CompatFinding>,
}

#[derive(Debug, Clone, Serialize)]
/// The CompatFinding type.
pub struct CompatFinding {
    /// The category field.
    pub category: CompatCategory,
    /// The severity field.
    pub severity: CompatSeverity,
    /// The message field.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CompatCategory type.
#[non_exhaustive]
pub enum CompatCategory {
    /// The Architecture variant.
    Architecture,
    /// The Platform variant.
    Platform,
    /// The MinOS variant.
    MinOS,
    /// The FileType variant.
    FileType,
    /// The DylibVersion variant.
    DylibVersion,
    /// The ImportCoverage variant.
    ImportCoverage,
    /// The WeakImport variant.
    WeakImport,
    /// The Rpath variant.
    Rpath,
    /// The NamespaceMode variant.
    NamespaceMode,
}

impl std::fmt::Display for CompatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Architecture => write!(f, "architecture"),
            Self::Platform => write!(f, "platform"),
            Self::MinOS => write!(f, "min-os"),
            Self::FileType => write!(f, "file-type"),
            Self::DylibVersion => write!(f, "dylib-version"),
            Self::ImportCoverage => write!(f, "import-coverage"),
            Self::WeakImport => write!(f, "weak-import"),
            Self::Rpath => write!(f, "rpath"),
            Self::NamespaceMode => write!(f, "namespace-mode"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CompatSeverity type.
#[non_exhaustive]
pub enum CompatSeverity {
    /// The Incompatible variant.
    Incompatible,
    /// The Warning variant.
    Warning,
    /// The Info variant.
    Info,
}

impl std::fmt::Display for CompatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incompatible => write!(f, "incompatible"),
            Self::Warning => write!(f, "warning"),
            Self::Info => write!(f, "info"),
        }
    }
}

impl CompatReport {
    /// Performs check.
    pub fn check(
        target: &MachoFile<'_>,
        target_path: &str,
        provider: Option<&MachoFile<'_>>,
        provider_path: Option<&str>,
    ) -> Result<Self> {
        let mut findings = Vec::new();

        let target_graph = DepGraph::build(target)?;
        let graph_issues = target_graph.validate();
        for issue in &graph_issues {
            findings.push(CompatFinding {
                category: CompatCategory::ImportCoverage,
                severity: match issue.severity {
                    crate::analysis::deps::graph::IssueSeverity::Error => {
                        CompatSeverity::Incompatible
                    }
                    crate::analysis::deps::graph::IssueSeverity::Warning => CompatSeverity::Warning,
                },
                message: issue.message.clone(),
            });
        }

        // Weak import analysis on target
        for imp in &target_graph.imports {
            if imp.weak {
                let provider_display = format!("{}", imp.provider);
                findings.push(CompatFinding {
                    category: CompatCategory::WeakImport,
                    severity: CompatSeverity::Info,
                    message: format!("weak import '{}' from {}", imp.name, provider_display,),
                });
            }
        }

        // Namespace mode check (target only, no provider needed)
        check_namespace_mode(target, &mut findings);

        // Rpath check (target only)
        check_rpaths(target, &mut findings);

        if let Some(prov) = provider {
            check_arch(target, prov, &mut findings);
            check_platform(target, prov, &mut findings);
            check_file_type(target, prov, &mut findings);
            check_version_compat(target, prov, &target_graph, &mut findings);
            check_import_coverage(target, prov, &target_graph, &mut findings)?;
        }

        Ok(Self {
            target_path: target_path.to_string(),
            provider_path: provider_path.map(|s| s.to_string()),
            findings,
        })
    }

    /// Performs has_incompatible.
    pub fn has_incompatible(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == CompatSeverity::Incompatible)
    }
}

fn check_arch(target: &MachoFile<'_>, provider: &MachoFile<'_>, findings: &mut Vec<CompatFinding>) {
    let target_arch = target.header().arch_spec();
    let provider_arch = provider.header().arch_spec();

    if target_arch.cpu_type != provider_arch.cpu_type
        || target_arch.cpu_subtype.masked() != provider_arch.cpu_subtype.masked()
    {
        findings.push(CompatFinding {
            category: CompatCategory::Architecture,
            severity: CompatSeverity::Incompatible,
            message: format!(
                "architecture mismatch: target is {} but provider is {}",
                target_arch.name(),
                provider_arch.name(),
            ),
        });
    } else {
        findings.push(CompatFinding {
            category: CompatCategory::Architecture,
            severity: CompatSeverity::Info,
            message: format!("architecture match: {}", target_arch.name()),
        });
    }
}

fn get_platform(
    macho: &MachoFile<'_>,
) -> Option<(
    Platform,
    crate::analysis::model::load_command::PackedVersion,
)> {
    for lc in macho.load_commands() {
        match lc.kind() {
            LoadCommand::BuildVersion(d) => return Some((d.platform, d.minos)),
            LoadCommand::VersionMinMacOS(d) => {
                return Some((Platform(PLATFORM_MACOS), d.version));
            }
            LoadCommand::VersionMinIOS(d) => {
                return Some((Platform(PLATFORM_IOS), d.version));
            }
            LoadCommand::VersionMinTvOS(d) => {
                return Some((Platform(PLATFORM_TVOS), d.version));
            }
            LoadCommand::VersionMinWatchOS(d) => {
                return Some((Platform(PLATFORM_WATCHOS), d.version));
            }
            _ => {}
        }
    }
    None
}

fn check_platform(
    target: &MachoFile<'_>,
    provider: &MachoFile<'_>,
    findings: &mut Vec<CompatFinding>,
) {
    let t_plat = get_platform(target);
    let p_plat = get_platform(provider);

    match (t_plat, p_plat) {
        (Some((tp, t_minos)), Some((pp, p_minos))) => {
            if tp.0 != pp.0 {
                findings.push(CompatFinding {
                    category: CompatCategory::Platform,
                    severity: CompatSeverity::Incompatible,
                    message: format!(
                        "platform mismatch: target is {} but provider is {}",
                        tp.name(),
                        pp.name(),
                    ),
                });
            } else {
                findings.push(CompatFinding {
                    category: CompatCategory::Platform,
                    severity: CompatSeverity::Info,
                    message: format!("platform match: {}", tp.name()),
                });

                // Check min OS: provider's min OS should be <= target's min OS
                // (provider must support at least as old as what target might run on)
                if p_minos.0 > t_minos.0 {
                    findings.push(CompatFinding {
                        category: CompatCategory::MinOS,
                        severity: CompatSeverity::Warning,
                        message: format!(
                            "provider min OS ({}) is higher than target min OS ({})",
                            p_minos, t_minos,
                        ),
                    });
                }
            }
        }
        (Some(_), None) => {
            findings.push(CompatFinding {
                category: CompatCategory::Platform,
                severity: CompatSeverity::Warning,
                message: "provider has no platform info".to_string(),
            });
        }
        (None, Some(_)) => {
            findings.push(CompatFinding {
                category: CompatCategory::Platform,
                severity: CompatSeverity::Warning,
                message: "target has no platform info".to_string(),
            });
        }
        (None, None) => {}
    }
}

fn check_file_type(
    target: &MachoFile<'_>,
    provider: &MachoFile<'_>,
    findings: &mut Vec<CompatFinding>,
) {
    let p_type = provider.header().file_type();

    match p_type {
        FileType::Dylib | FileType::Bundle | FileType::DylibStub => {
            findings.push(CompatFinding {
                category: CompatCategory::FileType,
                severity: CompatSeverity::Info,
                message: format!("provider is {}", p_type.name()),
            });
        }
        _ => {
            let t_type = target.header().file_type();
            findings.push(CompatFinding {
                category: CompatCategory::FileType,
                severity: CompatSeverity::Warning,
                message: format!(
                    "target is {} but provider is {} (expected dylib/bundle)",
                    t_type.name(),
                    p_type.name(),
                ),
            });
        }
    }
}

fn check_version_compat(
    _target: &MachoFile<'_>,
    provider: &MachoFile<'_>,
    target_graph: &DepGraph,
    findings: &mut Vec<CompatFinding>,
) {
    // Find the provider's install name among target's dylibs
    let provider_graph = match DepGraph::build(provider) {
        Ok(g) => g,
        Err(_) => return,
    };

    let provider_install_name = match &provider_graph.install_name {
        Some(n) => n.clone(),
        None => return,
    };

    // Get provider's current version from its own LC_ID_DYLIB
    let provider_current = provider.load_commands().iter().find_map(|lc| {
        if let LoadCommand::IdDylib(d) = lc.kind() {
            Some(d.current_version)
        } else {
            None
        }
    });

    if let Some(prov_ver) = provider_current {
        // Find matching dylib in target's dependencies
        if let Some(target_dylib) = target_graph
            .dylibs
            .iter()
            .find(|d| d.name == provider_install_name)
        {
            // Parse target's compat_version back to a PackedVersion for comparison
            // The compat_version string was created from PackedVersion::to_string() -> "M.m.p"
            // We need to compare: target's required compat_version <= provider's current_version
            let target_compat_parts: Vec<u32> = target_dylib
                .compat_version
                .split('.')
                .filter_map(|s| s.parse().ok())
                .collect();

            if target_compat_parts.len() == 3 {
                let target_compat_packed = (target_compat_parts[0] << 16)
                    | (target_compat_parts[1] << 8)
                    | target_compat_parts[2];

                if target_compat_packed > prov_ver.0 {
                    findings.push(CompatFinding {
                        category: CompatCategory::DylibVersion,
                        severity: CompatSeverity::Incompatible,
                        message: format!(
                            "target requires compat version {} of '{}' but provider current version is {}",
                            target_dylib.compat_version, provider_install_name, prov_ver,
                        ),
                    });
                } else {
                    findings.push(CompatFinding {
                        category: CompatCategory::DylibVersion,
                        severity: CompatSeverity::Info,
                        message: format!(
                            "version compatible: target needs compat {} of '{}', provider has {}",
                            target_dylib.compat_version, provider_install_name, prov_ver,
                        ),
                    });
                }
            }
        }
    }
}

fn check_import_coverage(
    _target: &MachoFile<'_>,
    provider: &MachoFile<'_>,
    target_graph: &DepGraph,
    findings: &mut Vec<CompatFinding>,
) -> Result<()> {
    let provider_graph = DepGraph::build(provider)?;

    let provider_install_name = match &provider_graph.install_name {
        Some(n) => n.clone(),
        None => return Ok(()),
    };

    // Find imports from this provider
    let target_dylib = target_graph
        .dylibs
        .iter()
        .find(|d| d.name == provider_install_name);

    let target_dylib = match target_dylib {
        Some(d) => d,
        None => return Ok(()),
    };

    let imports_from_provider = target_graph.imports_from(target_dylib.ordinal);

    let mut missing = Vec::new();
    for imp in &imports_from_provider {
        if imp.weak {
            continue;
        }
        if provider_graph.find_export(&imp.name).is_none() {
            missing.push(imp.name.clone());
        }
    }

    if missing.is_empty() {
        findings.push(CompatFinding {
            category: CompatCategory::ImportCoverage,
            severity: CompatSeverity::Info,
            message: format!(
                "all {} non-weak imports from '{}' are covered by provider exports",
                imports_from_provider.len(),
                provider_install_name,
            ),
        });
    } else {
        for name in &missing {
            findings.push(CompatFinding {
                category: CompatCategory::ImportCoverage,
                severity: CompatSeverity::Incompatible,
                message: format!(
                    "import '{}' not found in provider '{}' exports",
                    name, provider_install_name,
                ),
            });
        }
    }

    Ok(())
}

fn check_namespace_mode(target: &MachoFile<'_>, findings: &mut Vec<CompatFinding>) {
    let flags = target.header().flags();

    if flags.contains(MachoHeaderFlags::FORCE_FLAT) {
        findings.push(CompatFinding {
            category: CompatCategory::NamespaceMode,
            severity: CompatSeverity::Warning,
            message: "target uses flat namespace (FORCE_FLAT); symbol collisions may occur"
                .to_string(),
        });
    } else if flags.contains(MachoHeaderFlags::TWOLEVEL) {
        findings.push(CompatFinding {
            category: CompatCategory::NamespaceMode,
            severity: CompatSeverity::Info,
            message: "target uses two-level namespace".to_string(),
        });
    }
}

fn check_rpaths(target: &MachoFile<'_>, findings: &mut Vec<CompatFinding>) {
    let rpaths: Vec<String> = target
        .load_commands()
        .iter()
        .filter_map(|lc| lc.kind().as_rpath().map(|s| s.to_string()))
        .collect();

    // Check if any linked dylib uses @rpath and whether rpaths are defined
    let has_rpath_dylib = target.load_commands().iter().any(|lc| {
        matches!(
            lc.kind(),
            LoadCommand::LoadDylib(d)
            | LoadCommand::LoadWeakDylib(d)
            | LoadCommand::ReexportDylib(d)
            | LoadCommand::LazyLoadDylib(d)
            | LoadCommand::LoadUpwardDylib(d)
            if d.name.starts_with("@rpath/")
        )
    });

    if has_rpath_dylib && rpaths.is_empty() {
        findings.push(CompatFinding {
            category: CompatCategory::Rpath,
            severity: CompatSeverity::Warning,
            message: "target links dylibs via @rpath but defines no LC_RPATH entries".to_string(),
        });
    } else if !rpaths.is_empty() {
        findings.push(CompatFinding {
            category: CompatCategory::Rpath,
            severity: CompatSeverity::Info,
            message: format!("target defines {} rpath(s)", rpaths.len()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(bytes: &[u8]) -> crate::core::model::container::MachoContainer<'_> {
        crate::core::parse(bytes).expect("parse fixture")
    }

    #[test]
    fn architecture_compatibility_distinguishes_arm64e_from_plain_arm64() {
        let plain_bytes = macho_test_support::disassembly_arm64();
        let arm64e_bytes = macho_test_support::disassembly_arm64e();
        let plain = first(&plain_bytes);
        let arm64e = first(&arm64e_bytes);
        let report = CompatReport::check(
            plain.first_macho().unwrap(),
            "plain",
            arm64e.first_macho(),
            Some("arm64e"),
        )
        .unwrap();

        let finding = report
            .findings
            .iter()
            .find(|finding| finding.category == CompatCategory::Architecture)
            .expect("architecture finding");
        assert_eq!(finding.severity, CompatSeverity::Incompatible);
        assert!(finding.message.contains("target is arm64"));
        assert!(finding.message.contains("provider is arm64e"));
    }
}
