//! Dependency declarations and caller-selected static image universes.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::core::MaterializationLimits;
use crate::core::model::header::{CpuSubtype, CpuType};
use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::dyld_cache::{CacheMemberInput, CompletenessState, DyldCacheFamily, parse_dyld_cache};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;
use crate::analysis::image::ImageInfo;
use crate::analysis::paths::resolve_all_rpaths;
use crate::analysis::program::{ProgramRecoveryRequest, RecoveredProgram};
use crate::analysis::symbol_inventory::{RecoveredSymbolKind, SymbolInventory};

/// Explicit bounds for dependency and universe recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyRecoveryLimits {
    /// Maximum load-command dependency records retained per image.
    pub max_dependencies: usize,
    /// Maximum selected images admitted to one static universe.
    pub max_images: usize,
    /// Maximum import-resolution records retained across the universe.
    pub max_resolutions: usize,
}

impl Default for DependencyRecoveryLimits {
    fn default() -> Self {
        Self {
            max_dependencies: 65_536,
            max_images: 4_096,
            max_resolutions: 8_000_000,
        }
    }
}

impl DependencyRecoveryLimits {
    /// Reject zero-valued bounds.
    pub fn validate(self) -> Result<Self, DependencyRecoveryError> {
        if self.max_dependencies == 0 || self.max_images == 0 || self.max_resolutions == 0 {
            return Err(DependencyRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing dependency recovery.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DependencyRecoveryError {
    /// At least one explicit bound is zero.
    #[error("dependency recovery limits must be non-zero")]
    InvalidLimits,
    /// A selected image failed program recovery.
    #[error("selected-image program recovery failed: {0}")]
    Program(String),
    /// A filesystem image could not be read or parsed.
    #[error("filesystem dependency recovery failed: {0}")]
    Filesystem(String),
    /// A filesystem image does not contain the explicitly selected architecture.
    #[error("dependency image has no selected CPU tuple {cpu_type:#x}/{cpu_subtype:#x}: {path}")]
    ArchitectureMissing {
        /// Requested raw CPU type.
        cpu_type: i32,
        /// Requested raw CPU subtype.
        cpu_subtype: i32,
        /// Examined path.
        path: String,
    },
}

/// Load-command dependency semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Required dependency.
    Required,
    /// Weak dependency whose absence is permitted by dyld.
    Weak,
    /// Reexported dependency.
    Reexport,
    /// Lazily loaded dependency.
    Lazy,
    /// Upward dependency.
    Upward,
}

/// One dependency named by the selected image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredDependency {
    /// One-based dynamic-library ordinal used by imports.
    pub ordinal: u64,
    /// Install name exactly as encoded.
    pub install_name: String,
    /// Load semantics.
    pub kind: DependencyKind,
}

/// Static-analysis boundary that cannot be closed by loading named images.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeFrontierKind {
    /// `dlopen` or equivalent runtime image loading may add code.
    RuntimeLoadedImage,
    /// Objective-C mutation can replace or add methods.
    ObjectiveCRuntimeMutation,
    /// JIT or other generated executable code may appear.
    GeneratedCode,
    /// Encrypted executable bytes are not statically visible.
    EncryptedCode,
}

/// One explicit open-world boundary and its source evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFrontier {
    /// Boundary class.
    pub kind: RuntimeFrontierKind,
    /// Stable source reason.
    pub reason: String,
}

/// Dependency inventory status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyIndexStatus {
    /// Every named dependency was retained and no dynamic frontier was observed.
    Complete,
    /// Named dependencies were retained, with an explicit runtime-open frontier.
    Partial,
    /// A record budget omitted named dependency evidence.
    Truncated,
}

/// Conservation receipt for dependency recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyIndexCompleteness {
    /// Overall status.
    pub status: DependencyIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Named dependency commands observed.
    pub observed: u64,
    /// Named dependency commands retained.
    pub retained: u64,
    /// First omitted one-based dependency ordinal.
    pub continuation_ordinal: Option<u64>,
}

/// Dependencies and runtime boundary for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyIndex {
    image: FunctionImageIdentity,
    limits: DependencyRecoveryLimits,
    install_name: Option<String>,
    dependencies: Vec<RecoveredDependency>,
    frontiers: Vec<RuntimeFrontier>,
    completeness: DependencyIndexCompleteness,
}

impl DependencyIndex {
    /// Recover dependency declarations and evidence-backed runtime frontiers.
    pub fn recover(
        macho: &MachoFile<'_>,
        symbols: Option<&SymbolInventory>,
        limits: DependencyRecoveryLimits,
    ) -> Result<Self, DependencyRecoveryError> {
        let limits = limits.validate()?;
        let install_name = macho
            .load_commands()
            .iter()
            .find_map(|command| match command.kind() {
                LoadCommand::IdDylib(data) => Some(data.name.clone()),
                _ => None,
            });
        let mut observed = 0_u64;
        let mut dependencies = Vec::new();
        for command in macho.load_commands() {
            let item = match command.kind() {
                LoadCommand::LoadDylib(data) => Some((DependencyKind::Required, &data.name)),
                LoadCommand::LoadWeakDylib(data) => Some((DependencyKind::Weak, &data.name)),
                LoadCommand::ReexportDylib(data) => Some((DependencyKind::Reexport, &data.name)),
                LoadCommand::LazyLoadDylib(data) => Some((DependencyKind::Lazy, &data.name)),
                LoadCommand::LoadUpwardDylib(data) => Some((DependencyKind::Upward, &data.name)),
                _ => None,
            };
            let Some((kind, name)) = item else { continue };
            observed += 1;
            if dependencies.len() < limits.max_dependencies {
                dependencies.push(RecoveredDependency {
                    ordinal: observed,
                    install_name: name.clone(),
                    kind,
                });
            }
        }
        let mut frontiers = BTreeSet::new();
        if let Some(symbols) = symbols {
            for symbol in symbols.symbols() {
                let name = symbol.name.trim_start_matches('_');
                if matches!(name, "dlopen" | "NSCreateObjectFileImageFromFile") {
                    frontiers.insert((
                        RuntimeFrontierKind::RuntimeLoadedImage,
                        "dependency.runtime_loader_import",
                    ));
                }
                if matches!(
                    name,
                    "class_addMethod" | "method_setImplementation" | "objc_setAssociatedObject"
                ) {
                    frontiers.insert((
                        RuntimeFrontierKind::ObjectiveCRuntimeMutation,
                        "dependency.objc_runtime_mutation_import",
                    ));
                }
                // Generic virtual-memory allocation does not establish that
                // executable permissions or generated instructions ever
                // exist.  Retain a generated-code frontier only for an API
                // whose contract is itself JIT-specific; callsite argument
                // recovery may add narrower executable-memory evidence later.
                if name == "pthread_jit_write_protect_np" {
                    frontiers.insert((
                        RuntimeFrontierKind::GeneratedCode,
                        "dependency.executable_memory_import",
                    ));
                }
            }
        }
        if macho.load_commands().iter().any(|command| matches!(command.kind(), LoadCommand::EncryptionInfo(data) if data.crypt_id != 0) || matches!(command.kind(), LoadCommand::EncryptionInfo64(data) if data.crypt_id != 0)) {
            frontiers.insert((RuntimeFrontierKind::EncryptedCode, "dependency.encrypted_image"));
        }
        let frontiers = frontiers
            .into_iter()
            .map(|(kind, reason)| RuntimeFrontier {
                kind,
                reason: reason.into(),
            })
            .collect::<Vec<_>>();
        let continuation_ordinal =
            (observed > dependencies.len() as u64).then_some(dependencies.len() as u64 + 1);
        let mut reasons = Vec::new();
        if continuation_ordinal.is_some() {
            reasons.push("dependency.record_budget".into());
        }
        if !frontiers.is_empty() {
            reasons.push("dependency.runtime_open_world".into());
        }
        let status = if continuation_ordinal.is_some() {
            DependencyIndexStatus::Truncated
        } else if frontiers.is_empty() {
            DependencyIndexStatus::Complete
        } else {
            DependencyIndexStatus::Partial
        };
        let retained = dependencies.len() as u64;
        Ok(Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            install_name,
            dependencies,
            frontiers,
            completeness: DependencyIndexCompleteness {
                status,
                reasons,
                observed,
                retained,
                continuation_ordinal,
            },
        })
    }

    /// Exact image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }
    /// Image install name, when declared.
    pub fn install_name(&self) -> Option<&str> {
        self.install_name.as_deref()
    }
    /// Dependency declarations in ordinal order.
    pub fn dependencies(&self) -> &[RecoveredDependency] {
        &self.dependencies
    }
    /// Explicit runtime-open boundaries.
    pub fn frontiers(&self) -> &[RuntimeFrontier] {
        &self.frontiers
    }
    /// Completeness receipt.
    pub fn completeness(&self) -> &DependencyIndexCompleteness {
        &self.completeness
    }
}

/// Caller-selected image supplied to static-universe recovery.
#[derive(Debug, Clone, Copy)]
pub struct StaticUniverseInput<'image, 'data> {
    /// Stable caller name used when no `LC_ID_DYLIB` exists.
    pub name: &'image str,
    /// Parsed thin image.
    pub macho: &'image MachoFile<'data>,
}

/// Result of resolving one imported identity in the selected universe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniverseImportResolution {
    /// Source image name.
    pub source_image: String,
    /// Imported symbol spelling.
    pub import: String,
    /// Encoded library ordinal.
    pub library_ordinal: i32,
    /// Named dependency, when the ordinal maps to one.
    pub dependency: Option<String>,
    /// Selected provider image, when loaded.
    pub provider_image: Option<String>,
    /// Provider address, when exactly exported.
    pub provider_address: Option<u64>,
    /// Stable resolution status.
    pub status: String,
}

/// How one named image participated in automatic static-universe discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniverseImageDiscovery {
    /// Image that named the dependency, or `None` for the root executable.
    pub source_image: Option<String>,
    /// Encoded install name or root path.
    pub install_name: String,
    /// Concrete filesystem path when one was selected.
    pub resolved_path: Option<String>,
    /// Stable selected, missing, weak-missing, cache-frontier, or budget status.
    pub status: String,
}

/// Closed-under-selected-images program universe plus explicit frontiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StaticProgramUniverse {
    /// Recovered selected images in caller order.
    pub images: Vec<(String, RecoveredProgram)>,
    /// Deterministic import resolutions.
    pub resolutions: Vec<UniverseImportResolution>,
    /// Deterministic automatic-discovery ledger; explicit universes retain selected inputs here.
    pub discovery: Vec<UniverseImageDiscovery>,
    /// Stable reasons preventing closure.
    pub reasons: Vec<String>,
    /// First omitted image or resolution coordinate.
    pub continuation: Option<String>,
}

impl StaticProgramUniverse {
    /// Recover the explicit image set and resolve imports to loaded exports.
    pub fn recover(
        inputs: &[StaticUniverseInput<'_, '_>],
        request: ProgramRecoveryRequest,
        limits: DependencyRecoveryLimits,
    ) -> Result<Self, DependencyRecoveryError> {
        let limits = limits.validate()?;
        let admitted = inputs.len().min(limits.max_images);
        let mut images = Vec::with_capacity(admitted);
        for input in &inputs[..admitted] {
            let program = RecoveredProgram::recover(input.macho, request.clone())
                .map_err(|error| DependencyRecoveryError::Program(error.to_string()))?;
            let name = program
                .dependencies()
                .and_then(DependencyIndex::install_name)
                .unwrap_or(input.name)
                .to_owned();
            images.push((name, program));
        }
        let discovery = images
            .iter()
            .map(|(name, _)| UniverseImageDiscovery {
                source_image: None,
                install_name: name.clone(),
                resolved_path: None,
                status: "caller_selected".into(),
            })
            .collect();
        Self::resolve_programs(images, discovery, admitted < inputs.len(), request, limits)
    }

    /// Recursively discover named dependencies from the filesystem for one exact CPU tuple.
    ///
    /// Dyld path variables and caller search roots are expanded deterministically. Images that
    /// exist only in the shared cache remain typed frontiers instead of being claimed absent.
    pub fn recover_filesystem(
        root_path: &Path,
        cpu_type: i32,
        cpu_subtype: i32,
        request: ProgramRecoveryRequest,
        limits: DependencyRecoveryLimits,
        search_paths: &[PathBuf],
    ) -> Result<Self, DependencyRecoveryError> {
        Self::recover_filesystem_with_cache(
            root_path,
            cpu_type,
            cpu_subtype,
            request,
            limits,
            search_paths,
            None,
        )
    }

    /// Recursively discover named dependencies from files and one optional offline dyld cache.
    pub fn recover_filesystem_with_cache(
        root_path: &Path,
        cpu_type: i32,
        cpu_subtype: i32,
        request: ProgramRecoveryRequest,
        limits: DependencyRecoveryLimits,
        search_paths: &[PathBuf],
        cache_path: Option<&Path>,
    ) -> Result<Self, DependencyRecoveryError> {
        let limits = limits.validate()?;
        let requested = ProgramRecoveryRequest::new(
            request
                .requested()
                .iter()
                .copied()
                .chain([crate::analysis::program::ProgramRecoveryStage::Dependencies]),
            request.limits(),
        );
        let executable_path = root_path.to_string_lossy().into_owned();
        let cache_storage = cache_path.map(load_cache_family_storage).transpose()?;
        let cache_family = cache_storage
            .as_ref()
            .map(|storage| storage.parse())
            .transpose()?;
        let mut pending = VecDeque::from([PendingUniverseImage {
            source_image: None,
            install_name: executable_path.clone(),
            source: PendingUniverseSource::Filesystem(root_path.to_path_buf()),
        }]);
        let mut seen_paths = BTreeSet::new();
        let mut images = Vec::new();
        let mut discovery = Vec::new();
        let mut image_budget_excluded = false;
        while let Some(pending_image) = pending.pop_front() {
            let pending_resolved_path = pending_image.resolved_path(cache_path);
            let source_image = pending_image.source_image;
            let install_name = pending_image.install_name;
            let identity = match &pending_image.source {
                PendingUniverseSource::Filesystem(path) => {
                    let canonical = std::fs::canonicalize(path).unwrap_or(path.clone());
                    format!("file:{}", canonical.display())
                }
                PendingUniverseSource::SharedCache(path) => format!("cache:{path}"),
            };
            if !seen_paths.insert(identity) {
                continue;
            }
            if images.len() == limits.max_images {
                image_budget_excluded = true;
                discovery.push(UniverseImageDiscovery {
                    source_image,
                    install_name,
                    resolved_path: pending_resolved_path,
                    status: "budget_excluded".into(),
                });
                continue;
            }
            let (program, info, resolved_path, discovery_status) = match pending_image.source {
                PendingUniverseSource::Filesystem(path) => {
                    let canonical = std::fs::canonicalize(&path).unwrap_or(path);
                    let (program, info) = recover_filesystem_image(
                        &canonical,
                        cpu_type,
                        cpu_subtype,
                        requested.clone(),
                    )?;
                    (
                        program,
                        info,
                        canonical.to_string_lossy().into_owned(),
                        "selected",
                    )
                }
                PendingUniverseSource::SharedCache(path) => {
                    let family = cache_family.as_ref().expect("cache source requires family");
                    let cache_file = cache_path.expect("cache source requires path");
                    let (program, info, complete) = recover_cache_image(
                        family,
                        &path,
                        cpu_type,
                        cpu_subtype,
                        requested.clone(),
                    )?;
                    (
                        program,
                        info,
                        format!("{}#{path}", cache_file.display()),
                        if complete {
                            "selected_shared_cache"
                        } else {
                            "selected_shared_cache_partial"
                        },
                    )
                }
            };
            let image_name = program
                .dependencies()
                .and_then(DependencyIndex::install_name)
                .unwrap_or(&install_name)
                .to_owned();
            discovery.push(UniverseImageDiscovery {
                source_image: source_image.clone(),
                install_name: install_name.clone(),
                resolved_path: Some(resolved_path.clone()),
                status: discovery_status.into(),
            });
            let loader_path = resolved_path;
            if let Some(dependencies) = program.dependencies() {
                for dependency in dependencies.dependencies() {
                    let candidates = dependency_path_candidates(
                        &dependency.install_name,
                        &info,
                        &loader_path,
                        &executable_path,
                        search_paths,
                    );
                    if let Some(candidate) = candidates.into_iter().find(|path| path.is_file()) {
                        pending.push_back(PendingUniverseImage {
                            source_image: Some(image_name.clone()),
                            install_name: dependency.install_name.clone(),
                            source: PendingUniverseSource::Filesystem(candidate),
                        });
                    } else if cache_family.as_ref().is_some_and(|family| {
                        family
                            .image_index_by_path(&dependency.install_name)
                            .is_some()
                    }) {
                        pending.push_back(PendingUniverseImage {
                            source_image: Some(image_name.clone()),
                            install_name: dependency.install_name.clone(),
                            source: PendingUniverseSource::SharedCache(
                                dependency.install_name.clone(),
                            ),
                        });
                    } else {
                        let cache_frontier = dependency.install_name.starts_with("/usr/lib/")
                            || dependency.install_name.starts_with("/System/Library/");
                        discovery.push(UniverseImageDiscovery {
                            source_image: Some(image_name.clone()),
                            install_name: dependency.install_name.clone(),
                            resolved_path: None,
                            status: if dependency.kind == DependencyKind::Weak {
                                "weak_missing"
                            } else if cache_frontier {
                                "dyld_shared_cache_frontier"
                            } else {
                                "missing"
                            }
                            .into(),
                        });
                    }
                }
            }
            images.push((image_name, program));
        }
        Self::resolve_programs(images, discovery, image_budget_excluded, requested, limits)
    }

    fn resolve_programs(
        images: Vec<(String, RecoveredProgram)>,
        discovery: Vec<UniverseImageDiscovery>,
        image_budget_excluded: bool,
        _request: ProgramRecoveryRequest,
        limits: DependencyRecoveryLimits,
    ) -> Result<Self, DependencyRecoveryError> {
        let providers = images
            .iter()
            .enumerate()
            .map(|(index, (name, program))| (name.clone(), (index, program)))
            .collect::<BTreeMap<_, _>>();
        let mut resolutions = Vec::new();
        let mut truncated = false;
        'images: for (source_name, program) in &images {
            let Some(symbols) = program.symbols() else {
                continue;
            };
            for symbol in symbols.symbols() {
                let RecoveredSymbolKind::Import { library_ordinal } = symbol.kind else {
                    continue;
                };
                if resolutions.len() == limits.max_resolutions {
                    truncated = true;
                    break 'images;
                }
                let dependency = (library_ordinal > 0)
                    .then(|| {
                        program
                            .dependencies()
                            .and_then(|deps| deps.dependencies().get(library_ordinal as usize - 1))
                            .map(|dep| dep.install_name.clone())
                    })
                    .flatten();
                let provider = dependency
                    .as_ref()
                    .and_then(|name| providers.get(name).copied());
                let resolved = provider.and_then(|(index, _)| {
                    resolve_export(
                        &images,
                        &providers,
                        index,
                        &symbol.name,
                        &mut BTreeSet::new(),
                    )
                });
                let provider_address = resolved.map(|(_, address, _)| address);
                let status = if resolved.is_some_and(|(_, _, reexported)| reexported) {
                    "resolved_reexport"
                } else if provider_address.is_some() {
                    "resolved"
                } else if provider.is_some() {
                    "provider_missing_export"
                } else if symbol.weak {
                    "weak_provider_missing"
                } else {
                    "provider_not_selected"
                };
                resolutions.push(UniverseImportResolution {
                    source_image: source_name.clone(),
                    import: symbol.name.clone(),
                    library_ordinal,
                    dependency,
                    provider_image: resolved
                        .map(|(index, _, _)| images[index].0.clone())
                        .or_else(|| provider.map(|(index, _)| images[index].0.clone())),
                    provider_address,
                    status: status.into(),
                });
            }
        }
        resolutions.sort_by(|a, b| {
            (&a.source_image, &a.import, a.library_ordinal).cmp(&(
                &b.source_image,
                &b.import,
                b.library_ordinal,
            ))
        });
        let mut reasons = BTreeSet::new();
        if image_budget_excluded {
            reasons.insert("universe.image_budget".into());
        }
        if truncated {
            reasons.insert("universe.resolution_budget".into());
        }
        if resolutions
            .iter()
            .any(|item| item.status == "provider_not_selected")
        {
            reasons.insert("universe.missing_named_image".into());
        }
        if images.iter().any(|(_, program)| {
            program
                .dependencies()
                .is_some_and(|deps| !deps.frontiers().is_empty())
        }) {
            reasons.insert("universe.runtime_open_world".into());
        }
        if discovery.iter().any(|item| item.status == "missing") {
            reasons.insert("universe.missing_named_image".into());
        }
        if discovery
            .iter()
            .any(|item| item.status == "dyld_shared_cache_frontier")
        {
            reasons.insert("universe.dyld_shared_cache_frontier".into());
        }
        if discovery
            .iter()
            .any(|item| item.status == "selected_shared_cache_partial")
        {
            reasons.insert("universe.shared_cache_reconstruction_partial".into());
        }
        let continuation = if image_budget_excluded {
            Some(format!("image:{}", images.len()))
        } else if truncated {
            Some(format!("resolution:{}", resolutions.len()))
        } else {
            None
        };
        Ok(Self {
            images,
            resolutions,
            discovery,
            reasons: reasons.into_iter().collect(),
            continuation,
        })
    }
}

fn recover_filesystem_image(
    path: &Path,
    cpu_type: i32,
    cpu_subtype: i32,
    request: ProgramRecoveryRequest,
) -> Result<(RecoveredProgram, ImageInfo), DependencyRecoveryError> {
    let bytes = std::fs::read(path).map_err(|error| {
        DependencyRecoveryError::Filesystem(format!("read {}: {error}", path.display()))
    })?;
    let container = crate::core::parse(&bytes).map_err(|error| {
        DependencyRecoveryError::Filesystem(format!("parse {}: {error}", path.display()))
    })?;
    let macho = container
        .find_arch_spec(CpuType(cpu_type), CpuSubtype(cpu_subtype))
        .ok_or_else(|| DependencyRecoveryError::ArchitectureMissing {
            cpu_type,
            cpu_subtype,
            path: path.display().to_string(),
        })?;
    let info = ImageInfo::from_mach(macho);
    let program = RecoveredProgram::recover(macho, request)
        .map_err(|error| DependencyRecoveryError::Program(error.to_string()))?;
    Ok((program, info))
}

enum PendingUniverseSource {
    Filesystem(PathBuf),
    SharedCache(String),
}

struct PendingUniverseImage {
    source_image: Option<String>,
    install_name: String,
    source: PendingUniverseSource,
}

impl PendingUniverseImage {
    fn resolved_path(&self, cache_path: Option<&Path>) -> Option<String> {
        match &self.source {
            PendingUniverseSource::Filesystem(path) => Some(path.to_string_lossy().into_owned()),
            PendingUniverseSource::SharedCache(path) => {
                cache_path.map(|cache| format!("{}#{path}", cache.display()))
            }
        }
    }
}

struct CacheFamilyStorage {
    primary_name: String,
    primary: Vec<u8>,
    siblings: Vec<(String, Vec<u8>)>,
}

impl CacheFamilyStorage {
    fn parse(&self) -> Result<DyldCacheFamily<'_>, DependencyRecoveryError> {
        DyldCacheFamily::parse(
            CacheMemberInput {
                name: &self.primary_name,
                data: &self.primary,
            },
            self.siblings
                .iter()
                .map(|(name, bytes)| CacheMemberInput { name, data: bytes }),
        )
        .map_err(|error| {
            DependencyRecoveryError::Filesystem(format!("parse dyld cache family: {error}"))
        })
    }
}

fn load_cache_family_storage(path: &Path) -> Result<CacheFamilyStorage, DependencyRecoveryError> {
    let primary = std::fs::read(path).map_err(|error| {
        DependencyRecoveryError::Filesystem(format!("read dyld cache {}: {error}", path.display()))
    })?;
    let parsed = parse_dyld_cache(&primary).map_err(|error| {
        DependencyRecoveryError::Filesystem(format!("parse dyld cache {}: {error}", path.display()))
    })?;
    let siblings = parsed
        .subcaches()
        .iter()
        .map(|entry| {
            let mut sibling_path = OsString::from(path.as_os_str());
            sibling_path.push(&entry.file_suffix);
            let sibling_path = PathBuf::from(sibling_path);
            std::fs::read(&sibling_path)
                .map(|bytes| (entry.file_suffix.clone(), bytes))
                .map_err(|error| {
                    DependencyRecoveryError::Filesystem(format!(
                        "read declared dyld subcache {}: {error}",
                        sibling_path.display()
                    ))
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CacheFamilyStorage {
        primary_name: path.to_string_lossy().into_owned(),
        primary,
        siblings,
    })
}

fn recover_cache_image(
    family: &DyldCacheFamily<'_>,
    install_name: &str,
    cpu_type: i32,
    cpu_subtype: i32,
    request: ProgramRecoveryRequest,
) -> Result<(RecoveredProgram, ImageInfo, bool), DependencyRecoveryError> {
    let index = family.image_index_by_path(install_name).ok_or_else(|| {
        DependencyRecoveryError::Filesystem(format!("dyld cache does not contain {install_name}"))
    })?;
    let reconstructed = family
        .reconstruct_image(index, MaterializationLimits::default())
        .map_err(|error| {
            DependencyRecoveryError::Filesystem(format!(
                "reconstruct dyld cache image {install_name}: {error}"
            ))
        })?;
    let components = &reconstructed.completeness;
    let reconstruction_complete = [
        &components.segments,
        &components.linkedit,
        &components.symbols,
        &components.exports,
        &components.imports,
        &components.fixups,
        &components.local_symbols,
        &components.code_signature,
    ]
    .into_iter()
    .all(|component| {
        matches!(
            component.state,
            CompletenessState::Complete | CompletenessState::Absent
        )
    });
    let container = crate::core::parse(reconstructed.bytes()).map_err(|error| {
        DependencyRecoveryError::Filesystem(format!(
            "parse reconstructed dyld cache image {install_name}: {error}"
        ))
    })?;
    let macho = container
        .find_arch_spec(CpuType(cpu_type), CpuSubtype(cpu_subtype))
        .ok_or_else(|| DependencyRecoveryError::ArchitectureMissing {
            cpu_type,
            cpu_subtype,
            path: install_name.to_owned(),
        })?;
    let info = ImageInfo::from_mach(macho);
    let program = RecoveredProgram::recover(macho, request)
        .map_err(|error| DependencyRecoveryError::Program(error.to_string()))?;
    Ok((program, info, reconstruction_complete))
}

fn dependency_path_candidates(
    install_name: &str,
    info: &ImageInfo,
    loader_path: &str,
    executable_path: &str,
    search_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut candidates =
        resolve_all_rpaths(install_name, info, Some(loader_path), Some(executable_path))
            .into_iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
    if let Some(file_name) = Path::new(install_name).file_name() {
        candidates.extend(search_paths.iter().map(|root| root.join(file_name)));
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

fn resolve_export(
    images: &[(String, RecoveredProgram)],
    providers: &BTreeMap<String, (usize, &RecoveredProgram)>,
    image_index: usize,
    name: &str,
    visited: &mut BTreeSet<(usize, String)>,
) -> Option<(usize, u64, bool)> {
    if !visited.insert((image_index, name.to_owned())) {
        return None;
    }
    let program = &images[image_index].1;
    for candidate in program.symbols()?.by_name(name) {
        match &candidate.kind {
            RecoveredSymbolKind::ExportRegular
            | RecoveredSymbolKind::ExportThreadLocal
            | RecoveredSymbolKind::ExportAbsolute
            | RecoveredSymbolKind::StubAndResolver { .. } => {
                return Some((image_index, candidate.address?, false));
            }
            RecoveredSymbolKind::Reexport {
                library_ordinal,
                imported_name,
            } => {
                let ordinal = usize::try_from(*library_ordinal).ok()?.checked_sub(1)?;
                let dependency = program.dependencies()?.dependencies().get(ordinal)?;
                let (target_index, _) = providers.get(&dependency.install_name).copied()?;
                let target_name = imported_name.as_deref().unwrap_or(name);
                let (resolved_index, address, _) =
                    resolve_export(images, providers, target_index, target_name, visited)?;
                return Some((resolved_index, address, true));
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::program::{ProgramRecoveryLimits, ProgramRecoveryStage};

    #[test]
    fn explicit_single_image_universe_is_closed_and_deterministic() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let image = match &container {
            crate::core::model::container::MachoContainer::Thin(image) => image,
            _ => panic!("thin fixture"),
        };
        let request = ProgramRecoveryRequest::new(
            [ProgramRecoveryStage::Dependencies],
            ProgramRecoveryLimits::default(),
        );
        let universe = StaticProgramUniverse::recover(
            &[StaticUniverseInput {
                name: "fixture",
                macho: image,
            }],
            request,
            DependencyRecoveryLimits::default(),
        )
        .unwrap();
        assert_eq!(universe.images.len(), 1);
        assert!(universe.resolutions.is_empty());
        assert!(universe.reasons.is_empty());
        assert!(universe.continuation.is_none());
        assert_eq!(universe.discovery[0].status, "caller_selected");
    }

    #[test]
    fn filesystem_universe_selects_the_explicit_cpu_tuple_and_retains_discovery() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let image = container.first_macho().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("fixture");
        std::fs::write(&root, &bytes).unwrap();
        let request = ProgramRecoveryRequest::new(
            [ProgramRecoveryStage::Dependencies],
            ProgramRecoveryLimits::default(),
        );
        let universe = StaticProgramUniverse::recover_filesystem(
            &root,
            image.header().cpu_type().0,
            image.header().cpu_subtype().0,
            request,
            DependencyRecoveryLimits::default(),
            &[],
        )
        .unwrap();
        assert_eq!(universe.images.len(), 1);
        assert_eq!(universe.discovery.len(), 1);
        assert_eq!(universe.discovery[0].status, "selected");
        assert!(universe.discovery[0].resolved_path.is_some());
        assert!(universe.continuation.is_none());
    }

    #[test]
    fn filesystem_universe_rejects_a_missing_selected_architecture() {
        let bytes = macho_test_support::disassembly_x86_64();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("fixture");
        std::fs::write(&root, &bytes).unwrap();
        let error = StaticProgramUniverse::recover_filesystem(
            &root,
            crate::core::format::constants::CPU_TYPE_ARM64,
            0,
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Dependencies],
                ProgramRecoveryLimits::default(),
            ),
            DependencyRecoveryLimits::default(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            DependencyRecoveryError::ArchitectureMissing { .. }
        ));
    }

    #[test]
    fn selected_shared_cache_is_validated_even_when_no_dependency_needs_it() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let image = container.first_macho().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("fixture");
        let cache = directory.path().join("dyld_shared_cache_arm64e");
        std::fs::write(&root, &bytes).unwrap();
        std::fs::write(&cache, macho_test_support::dyld_cache_old()).unwrap();
        let universe = StaticProgramUniverse::recover_filesystem_with_cache(
            &root,
            image.header().cpu_type().0,
            image.header().cpu_subtype().0,
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Dependencies],
                ProgramRecoveryLimits::default(),
            ),
            DependencyRecoveryLimits::default(),
            &[],
            Some(&cache),
        )
        .unwrap();
        assert_eq!(universe.images.len(), 1);
        assert_eq!(universe.discovery[0].status, "selected");

        std::fs::write(&cache, b"not a cache").unwrap();
        let error = StaticProgramUniverse::recover_filesystem_with_cache(
            &root,
            image.header().cpu_type().0,
            image.header().cpu_subtype().0,
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Dependencies],
                ProgramRecoveryLimits::default(),
            ),
            DependencyRecoveryLimits::default(),
            &[],
            Some(&cache),
        )
        .unwrap_err();
        assert!(matches!(error, DependencyRecoveryError::Filesystem(_)));
    }
}
