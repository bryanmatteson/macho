use crate::Result;
use crate::core::dyld::bind::parse_bind_entries;
use crate::core::dyld::chained::parse_chained_fixups;
use crate::core::dyld::exports::parse_exports;
use crate::core::dyld::types::ExportKind;
use crate::core::image::DylibLinkKind;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

#[derive(Debug, Clone)]
pub struct DepGraph {
    pub install_name: Option<String>,
    pub dylibs: Vec<NormalizedDylib>,
    pub imports: Vec<ResolvedImport>,
    pub exports: Vec<ResolvedExport>,
}

#[derive(Debug, Clone)]
pub struct NormalizedDylib {
    pub name: String,
    pub ordinal: usize,
    pub current_version: String,
    pub compat_version: String,
    pub kind: DylibLinkKind,
}

#[derive(Debug, Clone)]
pub struct ResolvedImport {
    pub name: String,
    pub provider: ImportProvider,
    pub weak: bool,
    pub addend: i64,
}

#[derive(Debug, Clone)]
pub enum ImportProvider {
    Dylib { ordinal: usize, name: String },
    SelfImage,
    MainExecutable,
    DynamicLookup,
    WeakLookup,
    Unknown { ordinal: i32 },
}

impl std::fmt::Display for ImportProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dylib { name, .. } => write!(f, "{name}"),
            Self::SelfImage => write!(f, "self"),
            Self::MainExecutable => write!(f, "main-executable"),
            Self::DynamicLookup => write!(f, "dynamic-lookup"),
            Self::WeakLookup => write!(f, "weak-lookup"),
            Self::Unknown { ordinal } => write!(f, "unknown({ordinal})"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedExport {
    pub name: String,
    pub address: Option<u64>,
    pub weak: bool,
    pub reexport: Option<ReexportInfo>,
}

#[derive(Debug, Clone)]
pub struct ReexportInfo {
    pub provider_ordinal: u64,
    pub provider_name: Option<String>,
    pub original_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GraphIssue {
    pub severity: IssueSeverity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueSeverity {
    Error,
    Warning,
}

impl std::fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "error"),
            Self::Warning => write!(f, "warning"),
        }
    }
}

impl DepGraph {
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        let (install_name, dylibs) = collect_dylibs(macho);
        let imports = collect_imports(macho, &dylibs)?;
        let exports = collect_exports(macho, &dylibs)?;

        Ok(Self {
            install_name,
            dylibs,
            imports,
            exports,
        })
    }

    pub fn provider_of(&self, import_name: &str) -> Option<&ImportProvider> {
        self.imports
            .iter()
            .find(|i| i.name == import_name)
            .map(|i| &i.provider)
    }

    pub fn imports_from(&self, ordinal: usize) -> Vec<&ResolvedImport> {
        self.imports
            .iter()
            .filter(|i| match &i.provider {
                ImportProvider::Dylib { ordinal: o, .. } => *o == ordinal,
                _ => false,
            })
            .collect()
    }

    pub fn find_export(&self, name: &str) -> Option<&ResolvedExport> {
        self.exports.iter().find(|e| e.name == name)
    }

    pub fn reexports(&self) -> Vec<&ResolvedExport> {
        self.exports
            .iter()
            .filter(|e| e.reexport.is_some())
            .collect()
    }

    pub fn validate(&self) -> Vec<GraphIssue> {
        let mut issues = Vec::new();
        let dylib_count = self.dylibs.len();

        for imp in &self.imports {
            match &imp.provider {
                ImportProvider::Dylib { ordinal, name } => {
                    if *ordinal > dylib_count {
                        issues.push(GraphIssue {
                            severity: IssueSeverity::Error,
                            message: format!(
                                "import '{}' references ordinal {} but only {} dylibs are linked (provider: {})",
                                imp.name, ordinal, dylib_count, name,
                            ),
                        });
                    } else if !imp.weak {
                        // Check if the dylib itself is weakly linked but import is not weak
                        if let Some(dylib) = self.dylibs.iter().find(|d| d.ordinal == *ordinal) {
                            if dylib.kind == DylibLinkKind::Weak {
                                issues.push(GraphIssue {
                                    severity: IssueSeverity::Warning,
                                    message: format!(
                                        "import '{}' is not weak but references weakly-linked dylib '{}'",
                                        imp.name, dylib.name,
                                    ),
                                });
                            }
                        }
                    }
                }
                ImportProvider::Unknown { ordinal } => {
                    issues.push(GraphIssue {
                        severity: IssueSeverity::Warning,
                        message: format!(
                            "import '{}' has unknown special ordinal {}",
                            imp.name, ordinal,
                        ),
                    });
                }
                _ => {}
            }
        }

        for exp in &self.exports {
            if let Some(ref reexport) = exp.reexport {
                let ord = reexport.provider_ordinal as usize;
                if ord == 0 {
                    issues.push(GraphIssue {
                        severity: IssueSeverity::Error,
                        message: format!(
                            "reexport '{}' references ordinal 0 (self-image), which is invalid for reexports",
                            exp.name,
                        ),
                    });
                } else if ord > dylib_count {
                    issues.push(GraphIssue {
                        severity: IssueSeverity::Error,
                        message: format!(
                            "reexport '{}' references ordinal {} but only {} dylibs are linked",
                            exp.name, ord, dylib_count,
                        ),
                    });
                }
            }
        }

        issues
    }
}

fn collect_dylibs(macho: &MachoFile<'_>) -> (Option<String>, Vec<NormalizedDylib>) {
    let mut install_name = None;
    let mut dylibs = Vec::new();
    let mut ordinal: usize = 0;

    for lc in macho.load_commands() {
        match &lc.kind {
            LoadCommand::IdDylib(d) => {
                install_name = Some(d.name.clone());
            }
            LoadCommand::LoadDylib(d) => {
                ordinal += 1;
                dylibs.push(NormalizedDylib {
                    name: d.name.clone(),
                    ordinal,
                    current_version: d.current_version.to_string(),
                    compat_version: d.compatibility_version.to_string(),
                    kind: DylibLinkKind::Required,
                });
            }
            LoadCommand::LoadWeakDylib(d) => {
                ordinal += 1;
                dylibs.push(NormalizedDylib {
                    name: d.name.clone(),
                    ordinal,
                    current_version: d.current_version.to_string(),
                    compat_version: d.compatibility_version.to_string(),
                    kind: DylibLinkKind::Weak,
                });
            }
            LoadCommand::ReexportDylib(d) => {
                ordinal += 1;
                dylibs.push(NormalizedDylib {
                    name: d.name.clone(),
                    ordinal,
                    current_version: d.current_version.to_string(),
                    compat_version: d.compatibility_version.to_string(),
                    kind: DylibLinkKind::Reexport,
                });
            }
            LoadCommand::LazyLoadDylib(d) => {
                ordinal += 1;
                dylibs.push(NormalizedDylib {
                    name: d.name.clone(),
                    ordinal,
                    current_version: d.current_version.to_string(),
                    compat_version: d.compatibility_version.to_string(),
                    kind: DylibLinkKind::Lazy,
                });
            }
            LoadCommand::LoadUpwardDylib(d) => {
                ordinal += 1;
                dylibs.push(NormalizedDylib {
                    name: d.name.clone(),
                    ordinal,
                    current_version: d.current_version.to_string(),
                    compat_version: d.compatibility_version.to_string(),
                    kind: DylibLinkKind::Upward,
                });
            }
            _ => {}
        }
    }

    (install_name, dylibs)
}

fn resolve_ordinal(ordinal: i32, dylibs: &[NormalizedDylib]) -> ImportProvider {
    match ordinal {
        0 => ImportProvider::SelfImage,
        -1 => ImportProvider::MainExecutable,
        -2 => ImportProvider::DynamicLookup,
        -3 => ImportProvider::WeakLookup,
        n if n > 0 => {
            let idx = n as usize;
            if let Some(dylib) = dylibs.iter().find(|d| d.ordinal == idx) {
                ImportProvider::Dylib {
                    ordinal: idx,
                    name: dylib.name.clone(),
                }
            } else {
                ImportProvider::Dylib {
                    ordinal: idx,
                    name: format!("<ordinal {idx}>"),
                }
            }
        }
        other => ImportProvider::Unknown { ordinal: other },
    }
}

fn collect_imports(
    macho: &MachoFile<'_>,
    dylibs: &[NormalizedDylib],
) -> Result<Vec<ResolvedImport>> {
    // Try chained fixups first (modern)
    if let Ok(fixups) = parse_chained_fixups(macho) {
        let mut imports = Vec::with_capacity(fixups.imports.len());
        for ci in &fixups.imports {
            imports.push(ResolvedImport {
                name: ci.name.to_string(),
                provider: resolve_ordinal(ci.lib_ordinal, dylibs),
                weak: ci.weak,
                addend: ci.addend,
            });
        }
        return Ok(imports);
    }

    // Fall back to legacy bind entries
    if let Ok((regular, weak, lazy)) = parse_bind_entries(macho) {
        let mut seen = std::collections::HashSet::new();
        let mut imports = Vec::new();

        for entry in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
            if seen.insert(entry.symbol_name) {
                imports.push(ResolvedImport {
                    name: entry.symbol_name.to_string(),
                    provider: resolve_ordinal(entry.lib_ordinal as i32, dylibs),
                    weak: entry.weak,
                    addend: entry.addend,
                });
            }
        }
        return Ok(imports);
    }

    Ok(Vec::new())
}

fn collect_exports(
    macho: &MachoFile<'_>,
    dylibs: &[NormalizedDylib],
) -> Result<Vec<ResolvedExport>> {
    let raw_exports = match parse_exports(macho) {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };

    let mut exports = Vec::with_capacity(raw_exports.len());
    for e in &raw_exports {
        let (address, reexport) = match &e.kind {
            ExportKind::Regular { address } => (Some(*address), None),
            ExportKind::ThreadLocal { address } => (Some(*address), None),
            ExportKind::Absolute { address } => (Some(*address), None),
            ExportKind::Reexport { ordinal, name } => {
                let provider_name = dylibs
                    .iter()
                    .find(|d| d.ordinal == *ordinal as usize)
                    .map(|d| d.name.clone());
                (
                    None,
                    Some(ReexportInfo {
                        provider_ordinal: *ordinal,
                        provider_name,
                        original_name: name.clone(),
                    }),
                )
            }
            ExportKind::StubAndResolver {
                stub_offset,
                resolver_offset: _,
            } => (Some(*stub_offset), None),
        };

        exports.push(ResolvedExport {
            name: e.name.clone(),
            address,
            weak: e.is_weak(),
            reexport,
        });
    }

    Ok(exports)
}
