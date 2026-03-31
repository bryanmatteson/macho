use macho::depgraph::compat::{CompatCategory, CompatReport, CompatSeverity};
use macho::depgraph::graph::{DepGraph, DylibLinkKind, ImportProvider, IssueSeverity};
use macho::model::container::MachContainer;

fn load_binary(path: &str) -> memmap2::Mmap {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("failed to open {path}: {e}"));
    unsafe { memmap2::Mmap::map(&file).unwrap() }
}

// Note: /usr/lib/libSystem.B.dylib and /usr/lib/libc++.1.dylib are in the dyld
// shared cache and not accessible as regular files on modern macOS. Tests use
// /usr/bin/true, /usr/bin/tar, and /usr/lib/libgmalloc.dylib which exist on disk.

// --- DepGraph::build tests ---

#[test]
fn build_graph_libgmalloc() {
    let mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let graph = DepGraph::build(mach).expect("failed to build graph");

        // libgmalloc.dylib should have an install name
        assert!(
            graph.install_name.is_some(),
            "libgmalloc.dylib should have an install name"
        );

        // Should have linked dylibs
        assert!(
            !graph.dylibs.is_empty(),
            "libgmalloc.dylib should have linked dylibs"
        );

        // All dylibs should have valid ordinals (1-based, sequential)
        for (i, dylib) in graph.dylibs.iter().enumerate() {
            assert_eq!(dylib.ordinal, i + 1, "ordinal should be sequential from 1");
            assert!(!dylib.name.is_empty(), "dylib name should not be empty");
        }
    }
}

#[test]
fn build_graph_usr_bin_true() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let graph = DepGraph::build(mach).expect("failed to build graph");

        // /usr/bin/true is an executable, should not have install_name
        assert!(
            graph.install_name.is_none(),
            "/usr/bin/true should not have an install name"
        );

        // Should have at least libSystem as a dependency
        assert!(
            !graph.dylibs.is_empty(),
            "/usr/bin/true should have linked dylibs"
        );

        let has_libsystem = graph.dylibs.iter().any(|d| d.name.contains("libSystem"));
        assert!(has_libsystem, "expected libSystem dependency");
    }
}

#[test]
fn build_graph_tar() {
    let mmap = load_binary("/usr/bin/tar");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let graph = DepGraph::build(mach).expect("failed to build graph");

        assert!(
            graph.install_name.is_none(),
            "/usr/bin/tar should not have an install name"
        );

        assert!(
            !graph.dylibs.is_empty(),
            "/usr/bin/tar should have linked dylibs"
        );

        // tar should have more dylib dependencies than true
        assert!(graph.imports.len() > 1, "tar should have multiple imports");
    }
}

// --- Import resolution tests ---

#[test]
fn imports_have_providers() {
    let mmap = load_binary("/usr/bin/tar");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let graph = DepGraph::build(mach).expect("failed to build graph");

        for imp in &graph.imports {
            assert!(!imp.name.is_empty(), "import name should not be empty");
            match &imp.provider {
                ImportProvider::Dylib { ordinal, name } => {
                    assert!(*ordinal > 0, "dylib ordinal should be positive");
                    assert!(!name.is_empty(), "dylib name should not be empty");
                }
                ImportProvider::SelfImage
                | ImportProvider::MainExecutable
                | ImportProvider::DynamicLookup
                | ImportProvider::WeakLookup => {}
                ImportProvider::Unknown { ordinal } => {
                    panic!(
                        "unexpected unknown ordinal {ordinal} for import {}",
                        imp.name
                    );
                }
            }
        }
    }
}

#[test]
fn provider_of_lookup() {
    let mmap = load_binary("/usr/bin/tar");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    if let Some(first_import) = graph.imports.first() {
        let provider = graph.provider_of(&first_import.name);
        assert!(
            provider.is_some(),
            "provider_of should find the first import"
        );
    }

    assert!(graph.provider_of("_this_does_not_exist_xyz").is_none());
}

#[test]
fn imports_from_ordinal() {
    let mmap = load_binary("/usr/bin/tar");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    // Find a dylib ordinal that has imports
    let mut found_imports = false;
    for dylib in &graph.dylibs {
        let imports = graph.imports_from(dylib.ordinal);
        if !imports.is_empty() {
            found_imports = true;
            for imp in &imports {
                match &imp.provider {
                    ImportProvider::Dylib { ordinal, .. } => {
                        assert_eq!(*ordinal, dylib.ordinal);
                    }
                    _ => panic!("imports_from should only return dylib-provided imports"),
                }
            }
        }
    }
    assert!(found_imports, "expected at least one dylib with imports");

    // Ordinal 9999 should return empty
    assert!(graph.imports_from(9999).is_empty());
}

// --- Export tests ---

#[test]
fn exports_from_executable() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    let mh = graph.find_export("__mh_execute_header");
    assert!(
        mh.is_some(),
        "expected __mh_execute_header export from executable"
    );
    assert!(mh.unwrap().address.is_some());
}

#[test]
fn exports_from_dylib() {
    let mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    // libgmalloc uses interposition rather than a normal exports trie,
    // so it may have zero trie-based exports. Just verify it doesn't crash.
    let _ = graph.exports;
}

#[test]
fn find_export_nonexistent() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    assert!(graph.find_export("_nonexistent_symbol_xyz").is_none());
}

// --- Validation tests ---

#[test]
fn validate_clean_binary() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let graph = DepGraph::build(mach).expect("failed to build graph");
        let issues = graph.validate();

        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "expected no validation errors for /usr/bin/true, got: {:?}",
            errors,
        );
    }
}

#[test]
fn validate_dylib() {
    let mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let graph = DepGraph::build(mach).expect("failed to build graph");
        let issues = graph.validate();

        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.severity == IssueSeverity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "expected no validation errors for libgmalloc, got: {:?}",
            errors,
        );
    }
}

// --- Compatibility report tests ---

#[test]
fn compat_self_check() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let report =
        CompatReport::check(mach, "/usr/bin/true", None, None).expect("compat check failed");

    assert_eq!(report.target_path, "/usr/bin/true");
    assert!(report.provider_path.is_none());
}

#[test]
fn compat_with_provider() {
    let target_mmap = load_binary("/usr/bin/true");
    let target_container = macho::parse(&target_mmap).expect("failed to parse target");

    let provider_mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let provider_container = macho::parse(&provider_mmap).expect("failed to parse provider");

    let target_mach = target_container.first_mach();
    let provider_mach = provider_container.first_mach();

    let report = CompatReport::check(
        target_mach,
        "/usr/bin/true",
        Some(provider_mach),
        Some("/usr/lib/libgmalloc.dylib"),
    )
    .expect("compat check failed");

    assert_eq!(report.target_path, "/usr/bin/true");
    assert_eq!(
        report.provider_path.as_deref(),
        Some("/usr/lib/libgmalloc.dylib")
    );

    // Should have architecture finding
    let arch_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == CompatCategory::Architecture)
        .collect();
    assert!(
        !arch_findings.is_empty(),
        "expected architecture finding in compat report"
    );

    // Should have platform finding
    let platform_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == CompatCategory::Platform)
        .collect();
    assert!(
        !platform_findings.is_empty(),
        "expected platform finding in compat report"
    );
}

#[test]
fn compat_arch_mismatch() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");

    if let MachContainer::Fat(ref fat) = container {
        if fat.arches().len() >= 2 {
            let arch1 = &fat.arches()[0].mach;
            let arch2 = &fat.arches()[1].mach;

            if arch1.header().cpu_type != arch2.header().cpu_type {
                let report = CompatReport::check(arch1, "arch1", Some(arch2), Some("arch2"))
                    .expect("compat check failed");

                let has_arch_incompat = report.findings.iter().any(|f| {
                    f.category == CompatCategory::Architecture
                        && f.severity == CompatSeverity::Incompatible
                });
                assert!(
                    has_arch_incompat,
                    "different architectures should produce Incompatible finding"
                );
                assert!(report.has_incompatible());
            }
        }
    }
}

#[test]
fn compat_file_type_check() {
    let target_mmap = load_binary("/usr/bin/true");
    let target_container = macho::parse(&target_mmap).expect("failed to parse target");

    let provider_mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let provider_container = macho::parse(&provider_mmap).expect("failed to parse provider");

    let target_mach = target_container.first_mach();
    let provider_mach = provider_container.first_mach();

    let report = CompatReport::check(
        target_mach,
        "/usr/bin/true",
        Some(provider_mach),
        Some("/usr/lib/libgmalloc.dylib"),
    )
    .expect("compat check failed");

    let file_type_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == CompatCategory::FileType)
        .collect();
    assert!(!file_type_findings.is_empty(), "expected file type finding");
    // Provider is a dylib, so FileType finding should be Info
    assert_eq!(file_type_findings[0].severity, CompatSeverity::Info);
}

// --- Dylib version tests ---

#[test]
fn dylib_versions_are_valid() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    for dylib in &graph.dylibs {
        let parts: Vec<&str> = dylib.current_version.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "current_version should have 3 parts: {}",
            dylib.current_version
        );

        let parts: Vec<&str> = dylib.compat_version.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "compat_version should have 3 parts: {}",
            dylib.compat_version
        );
    }
}

// --- Display trait tests ---

#[test]
fn link_kinds_display() {
    assert_eq!(format!("{}", DylibLinkKind::Required), "required");
    assert_eq!(format!("{}", DylibLinkKind::Weak), "weak");
    assert_eq!(format!("{}", DylibLinkKind::Reexport), "reexport");
    assert_eq!(format!("{}", DylibLinkKind::Lazy), "lazy");
    assert_eq!(format!("{}", DylibLinkKind::Upward), "upward");
}

#[test]
fn import_provider_display() {
    let dylib = ImportProvider::Dylib {
        ordinal: 1,
        name: "/usr/lib/libSystem.B.dylib".to_string(),
    };
    assert_eq!(format!("{dylib}"), "/usr/lib/libSystem.B.dylib");

    assert_eq!(format!("{}", ImportProvider::SelfImage), "self");
    assert_eq!(
        format!("{}", ImportProvider::MainExecutable),
        "main-executable"
    );
    assert_eq!(
        format!("{}", ImportProvider::DynamicLookup),
        "dynamic-lookup"
    );
    assert_eq!(
        format!("{}", ImportProvider::WeakLookup),
        "weak-lookup"
    );
    assert_eq!(
        format!("{}", ImportProvider::Unknown { ordinal: -5 }),
        "unknown(-5)"
    );
}

#[test]
fn issue_severity_display() {
    assert_eq!(format!("{}", IssueSeverity::Error), "error");
    assert_eq!(format!("{}", IssueSeverity::Warning), "warning");
}

// --- Dylib graph for library ---

#[test]
fn libgmalloc_graph() {
    let mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    assert!(
        graph.install_name.is_some(),
        "libgmalloc.dylib should have install name"
    );

    // Should have dylib dependencies
    assert!(
        !graph.dylibs.is_empty(),
        "libgmalloc.dylib should have linked dylibs"
    );

    // Should have imports
    assert!(
        !graph.imports.is_empty(),
        "libgmalloc.dylib should have imports"
    );
}

// --- Graph consistency tests ---

#[test]
fn multiple_arch_graphs_consistent() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");

    if let MachContainer::Fat(ref fat) = container {
        let graphs: Vec<_> = fat
            .arches()
            .iter()
            .map(|a| DepGraph::build(&a.mach).expect("failed to build graph"))
            .collect();

        // All arches should have the same set of dylib names
        if graphs.len() >= 2 {
            let names0: std::collections::HashSet<_> =
                graphs[0].dylibs.iter().map(|d| &d.name).collect();
            let names1: std::collections::HashSet<_> =
                graphs[1].dylibs.iter().map(|d| &d.name).collect();
            assert_eq!(
                names0, names1,
                "different arches of the same binary should have the same dylib set"
            );
        }
    }
}

#[test]
fn reexports_vec_for_non_reexporting_binary() {
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    // An executable typically doesn't reexport
    let reexports = graph.reexports();
    // Just verify it doesn't crash; executables may or may not have reexports
    let _ = reexports;
}

// --- CompatSeverity and CompatCategory display tests ---

#[test]
fn compat_severity_display() {
    assert_eq!(format!("{}", CompatSeverity::Incompatible), "incompatible");
    assert_eq!(format!("{}", CompatSeverity::Warning), "warning");
    assert_eq!(format!("{}", CompatSeverity::Info), "info");
}

#[test]
fn compat_category_display() {
    assert_eq!(format!("{}", CompatCategory::Architecture), "architecture");
    assert_eq!(format!("{}", CompatCategory::Platform), "platform");
    assert_eq!(format!("{}", CompatCategory::MinOS), "min-os");
    assert_eq!(format!("{}", CompatCategory::FileType), "file-type");
    assert_eq!(format!("{}", CompatCategory::DylibVersion), "dylib-version");
    assert_eq!(
        format!("{}", CompatCategory::ImportCoverage),
        "import-coverage"
    );
    assert_eq!(format!("{}", CompatCategory::WeakImport), "weak-import");
}

// --- Same binary as target and provider ---

#[test]
fn compat_same_binary_as_provider() {
    // Using the same executable as both target and "provider" -- tests that
    // the code handles the case where provider is not a dylib that the target
    // links to.
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let report = CompatReport::check(mach, "/usr/bin/true", Some(mach), Some("/usr/bin/true"))
        .expect("compat check failed");

    // Should not crash. Architecture and platform should match.
    let arch_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.category == CompatCategory::Architecture)
        .collect();
    assert!(!arch_findings.is_empty());
    assert_eq!(arch_findings[0].severity, CompatSeverity::Info);
}

// --- Regression: fat binary compat should match arch (#22) ---

#[test]
fn compat_fat_provider_matches_arch() {
    // When both target and provider are fat binaries, the compat check
    // should match the provider arch to the target arch rather than
    // always using the first slice.
    let target_mmap = load_binary("/usr/bin/true");
    let target_container = macho::parse(&target_mmap).expect("failed to parse target");

    let provider_mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let provider_container = macho::parse(&provider_mmap).expect("failed to parse provider");

    // Both binaries are fat (x86_64 + arm64e). For each arch slice, the
    // provider should match. We verify by checking that architecture
    // findings are all Info (match), never Incompatible (mismatch).
    for mach in target_container.mach_files() {
        let cpu = mach.header().cpu_type;
        let prov_mach = provider_container
            .find_arch(cpu)
            .unwrap_or_else(|| provider_container.first_mach());

        let report = CompatReport::check(mach, "target", Some(prov_mach), Some("provider"))
            .expect("compat check failed");

        let arch_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == CompatCategory::Architecture)
            .collect();
        assert!(!arch_findings.is_empty());
        // After fix: should always match since both are fat with same arches
        assert_eq!(
            arch_findings[0].severity,
            CompatSeverity::Info,
            "expected arch match for {}, got: {}",
            cpu.name(),
            arch_findings[0].message,
        );
    }
}

// --- Weak lookup variant display ---

#[test]
fn weak_lookup_display() {
    // Ordinal -3 is BIND_SPECIAL_DYLIB_WEAK_LOOKUP, displayed as "weak-lookup"
    assert_eq!(format!("{}", ImportProvider::WeakLookup), "weak-lookup");
}

// --- Edge case: binary with minimal imports ---

#[test]
fn minimal_binary_no_imports() {
    // /usr/bin/true has very few or zero imports depending on the arch.
    // Verify the graph handles this gracefully.
    let mmap = load_binary("/usr/bin/true");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    // The graph should always be constructable even with zero imports
    assert!(graph.imports_from(9999).is_empty());
    assert!(graph.provider_of("_nonexistent").is_none());
    let issues = graph.validate();
    let errors: Vec<_> = issues
        .iter()
        .filter(|i| i.severity == IssueSeverity::Error)
        .collect();
    assert!(errors.is_empty(), "clean binary should have no errors");
}

// --- Ordinal boundary: dylib count matches max valid ordinal ---

#[test]
fn ordinal_boundary_matches_dylib_count() {
    let mmap = load_binary("/usr/bin/tar");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    let max_ordinal = graph.dylibs.iter().map(|d| d.ordinal).max().unwrap_or(0);
    assert_eq!(
        max_ordinal,
        graph.dylibs.len(),
        "max ordinal should equal dylib count for sequential 1-based ordinals"
    );

    // Every import with a Dylib provider should reference a valid ordinal
    for imp in &graph.imports {
        if let ImportProvider::Dylib { ordinal, .. } = &imp.provider {
            assert!(
                *ordinal >= 1 && *ordinal <= graph.dylibs.len(),
                "import '{}' has ordinal {} outside valid range 1..={}",
                imp.name,
                ordinal,
                graph.dylibs.len(),
            );
        }
    }
}

// --- Compat report: no provider produces only target-side findings ---

#[test]
fn compat_no_provider_produces_target_findings() {
    let mmap = load_binary("/usr/bin/tar");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let report = CompatReport::check(mach, "/usr/bin/tar", None, None)
        .expect("compat check failed");

    // Without a provider, should have no arch/platform/file-type findings
    let cross_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.category,
                CompatCategory::Architecture
                    | CompatCategory::Platform
                    | CompatCategory::FileType
                    | CompatCategory::DylibVersion
            )
        })
        .collect();
    assert!(
        cross_findings.is_empty(),
        "without provider, should have no cross-binary findings"
    );
}

// --- Reexport info enrichment ---

#[test]
fn reexport_info_has_provider_name_when_ordinal_valid() {
    let mmap = load_binary("/usr/lib/libgmalloc.dylib");
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();
    let graph = DepGraph::build(mach).expect("failed to build graph");

    for exp in &graph.exports {
        if let Some(ref reexport) = exp.reexport {
            let ord = reexport.provider_ordinal as usize;
            if ord > 0 && ord <= graph.dylibs.len() {
                assert!(
                    reexport.provider_name.is_some(),
                    "reexport '{}' with valid ordinal {} should have provider_name",
                    exp.name,
                    ord,
                );
            }
        }
    }
}
