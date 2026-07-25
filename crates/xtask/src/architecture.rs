use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use cargo_metadata::{DependencyKind, MetadataCommand};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use walkdir::WalkDir;

const PRODUCT_CRATES: &[&str] = &[
    "macho-core",
    "macho-insn",
    "macho-dyld",
    "macho-demangle",
    "macho-symbols",
    "macho-codesign",
    "macho-dwarf",
    "macho-objc",
    "macho-swift",
    "macho-cpp",
    "macho-evidence",
    "macho-analysis",
    "macho-mutate",
    "macho-patch",
    "macho-dyld-cache",
    "macho-header-infer",
    "macho-header-syntax",
    "macho-workflow",
    "macho",
    "macho-cli",
];

pub fn check(root: &Path) -> Result<()> {
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .context("cargo metadata failed")?;
    let permitted = permitted_edges();
    let workspace_names: BTreeSet<_> = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| package.name.as_str())
        .collect();

    let missing: Vec<_> = PRODUCT_CRATES
        .iter()
        .copied()
        .filter(|name| !workspace_names.contains(name))
        .collect();
    if !missing.is_empty() {
        bail!("missing required workspace crates: {}", missing.join(", "));
    }

    let facade = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "macho")
        .context("workspace has no macho facade package")?;
    check_feature_authority(&facade.features)?;

    let mut violations = Vec::new();
    for package in metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
    {
        let allowed = permitted
            .get(package.name.as_str())
            .cloned()
            .unwrap_or_default();
        for dependency in package
            .dependencies
            .iter()
            .filter(|dependency| dependency.kind == DependencyKind::Normal)
        {
            if let Some(violation) = dependency_violation(
                package.name.as_str(),
                dependency.name.as_str(),
                &workspace_names,
                &allowed,
            ) {
                violations.push(violation);
            }
            if dependency.name == "apple-codesign"
                && (dependency.uses_default_features
                    || dependency
                        .features
                        .iter()
                        .any(|feature| matches!(feature.as_str(), "notarize" | "notarization")))
            {
                violations.push(format!(
                    "macho signing must disable apple-codesign default/notarization features: {}",
                    package.name
                ));
            }
            if dependency.name == "termosaic"
                && (dependency.req.to_string() != "=0.2.0"
                    || dependency
                        .source
                        .as_ref()
                        .is_none_or(|source| !source.is_crates_io())
                    || dependency.uses_default_features
                    || !dependency.features.is_empty())
            {
                violations.push(format!(
                    "macho-cli must pin crates.io termosaic =0.2.0 with default features disabled: {}",
                    package.name
                ));
            }
        }
    }

    violations.extend(scan_workspace_sources(root)?);
    if violations.is_empty() {
        println!("architecture: ok");
        Ok(())
    } else {
        violations.sort();
        violations.dedup();
        bail!("architecture violations:\n  {}", violations.join("\n  "))
    }
}

fn dependency_violation(
    package: &str,
    dependency: &str,
    workspace_names: &BTreeSet<&str>,
    allowed_workspace_edges: &BTreeSet<&str>,
) -> Option<String> {
    if workspace_names.contains(dependency) && !allowed_workspace_edges.contains(dependency) {
        return Some(format!(
            "forbidden workspace edge: {package} -> {dependency}"
        ));
    }
    if matches!(dependency, "clap" | "memmap2" | "anyhow")
        && !matches!(package, "macho-cli" | "xtask")
    {
        return Some(format!(
            "delivery dependency {dependency} is owned by {package}"
        ));
    }
    if dependency == "termosaic" && package != "macho-cli" {
        return Some(format!(
            "presentation dependency termosaic is owned by macho-cli, not {package}"
        ));
    }
    if matches!(
        dependency,
        "cpp_demangle" | "rustc-demangle" | "swift-demangler"
    ) && package != "macho-demangle"
    {
        return Some(format!(
            "symbol-demangling dependency {dependency} is owned by macho-demangle, not {package}"
        ));
    }
    if dependency == "apple-codesign" && package != "macho-mutate" {
        return Some(format!(
            "signing dependency apple-codesign is owned by macho-mutate, not {package}"
        ));
    }
    None
}

fn check_feature_authority(features: &BTreeMap<String, Vec<String>>) -> Result<()> {
    let actual = features
        .iter()
        .map(|(name, values)| (name.as_str(), values.iter().map(String::as_str).collect()))
        .collect::<BTreeMap<&str, BTreeSet<&str>>>();
    let expected = BTreeMap::from([
        ("default", BTreeSet::from(["analysis"])),
        (
            "metadata",
            BTreeSet::from([
                "dep:macho-codesign",
                "dep:macho-cpp",
                "dep:macho-dwarf",
                "dep:macho-dyld",
                "dep:macho-evidence",
                "dep:macho-objc",
                "dep:macho-swift",
                "dep:macho-symbols",
                "dep:macho-header-syntax",
            ]),
        ),
        (
            "analysis",
            BTreeSet::from(["dep:macho-analysis", "dep:macho-insn", "metadata"]),
        ),
        (
            "mutation",
            BTreeSet::from([
                "dep:macho-codesign",
                "dep:macho-dyld",
                "dep:macho-insn",
                "dep:macho-mutate",
                "dep:macho-patch",
            ]),
        ),
        (
            "workflow",
            BTreeSet::from(["analysis", "dep:macho-workflow", "mutation"]),
        ),
        ("dyld-cache", BTreeSet::from(["dep:macho-dyld-cache"])),
        (
            "header-infer",
            BTreeSet::from(["analysis", "dep:macho-header-infer"]),
        ),
        (
            "full",
            BTreeSet::from([
                "analysis",
                "dyld-cache",
                "header-infer",
                "mutation",
                "workflow",
            ]),
        ),
    ]);
    if actual == expected {
        Ok(())
    } else {
        bail!("macho feature authority mismatch\nexpected: {expected:?}\nactual: {actual:?}")
    }
}

fn permitted_edges() -> BTreeMap<&'static str, BTreeSet<&'static str>> {
    let rows: &[(&str, &[&str])] = &[
        ("macho-core", &[]),
        ("macho-header-syntax", &[]),
        ("macho-insn", &[]),
        ("macho-demangle", &[]),
        ("macho-dyld", &["macho-core"]),
        ("macho-symbols", &["macho-core", "macho-demangle"]),
        ("macho-codesign", &["macho-core"]),
        ("macho-dwarf", &["macho-core"]),
        ("macho-objc", &["macho-core", "macho-dyld"]),
        (
            "macho-swift",
            &["macho-core", "macho-demangle", "macho-dyld"],
        ),
        (
            "macho-cpp",
            &["macho-core", "macho-insn", "macho-demangle", "macho-dyld"],
        ),
        (
            "macho-evidence",
            &[
                "macho-core",
                "macho-dyld",
                "macho-objc",
                "macho-swift",
                "macho-cpp",
            ],
        ),
        (
            "macho-analysis",
            &[
                "macho-core",
                "macho-insn",
                "macho-symbols",
                "macho-dyld",
                "macho-codesign",
                "macho-dwarf",
                "macho-objc",
                "macho-swift",
                "macho-cpp",
                "macho-header-syntax",
            ],
        ),
        ("macho-mutate", &["macho-core", "macho-codesign"]),
        ("macho-patch", &["macho-core", "macho-insn"]),
        ("macho-dyld-cache", &["macho-core", "macho-dyld"]),
        (
            "macho-header-infer",
            &["macho-analysis", "macho-header-syntax"],
        ),
        (
            "macho-workflow",
            &["macho-core", "macho-analysis", "macho-mutate"],
        ),
        (
            "macho",
            &[
                "macho-core",
                "macho-insn",
                "macho-symbols",
                "macho-dyld",
                "macho-codesign",
                "macho-dwarf",
                "macho-objc",
                "macho-swift",
                "macho-cpp",
                "macho-evidence",
                "macho-analysis",
                "macho-mutate",
                "macho-patch",
                "macho-workflow",
                "macho-dyld-cache",
                "macho-header-infer",
                "macho-header-syntax",
            ],
        ),
        ("macho-cli", &["macho"]),
        ("xtask", &["macho-cli"]),
        ("macho-test-support", &[]),
    ];
    rows.iter()
        .map(|(name, edges)| (*name, edges.iter().copied().collect()))
        .collect()
}

fn scan_workspace_sources(root: &Path) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for entry in WalkDir::new(root.join("crates"))
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "target")
    {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type().is_file() || path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let relative = path.strip_prefix(root).unwrap_or(path);
        let crate_name = relative
            .components()
            .nth(1)
            .and_then(|component| component.as_os_str().to_str())
            .unwrap_or_default();
        let source =
            fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        violations.extend(scan_source(crate_name, relative, &source));
    }
    Ok(violations)
}

#[derive(Default)]
struct SourceFacts {
    process_call: bool,
    output_macro: bool,
    system_io_call: bool,
    mutation_analysis_path: bool,
    mutation_string_result: bool,
    public_vec_reference: bool,
    first_mach_call: bool,
    silent_decode_discard: bool,
    image_inspector: bool,
    removed_format_flag: bool,
}

impl<'ast> Visit<'ast> for SourceFacts {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if has_cfg_test(&item.attrs) {
            return;
        }
        visit::visit_item_mod(self, item);
    }

    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = expression.func.as_ref() {
            let segments = function.path.segments.iter().collect::<Vec<_>>();
            self.process_call |= segments.len() >= 2
                && segments[segments.len() - 2].ident == "Command"
                && segments[segments.len() - 1].ident == "new";
            self.system_io_call |= segments.last().is_some_and(|segment| {
                matches!(segment.ident.to_string().as_str(), "stdout" | "stderr")
            });
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.first_mach_call |= expression.method == "first_mach";
        if expression.method == "filter_map" {
            let mut filter = FilterMapFacts::default();
            for argument in &expression.args {
                filter.visit_expr(argument);
            }
            self.silent_decode_discard |= filter.result_ok || filter.ok_call && filter.decode_use;
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        self.output_macro |= invocation.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "print" | "println" | "eprint" | "eprintln"
            )
        });
        visit::visit_macro(self, invocation);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.mutation_analysis_path |= path
            .segments
            .iter()
            .any(|segment| segment.ident == "macho_analysis");
        self.image_inspector |= path
            .segments
            .iter()
            .any(|segment| segment.ident == "ImageInspector");
        visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.mutation_analysis_path |= use_tree_contains(&item.tree, "macho_analysis");
        visit::visit_item_use(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        self.image_inspector |= item.ident == "ImageInspector";
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        self.image_inspector |= item.ident == "ImageInspector";
        visit::visit_item_enum(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.image_inspector |= item.ident == "ImageInspector";
        visit::visit_item_type(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.public_vec_reference |=
            is_public(&item.vis) && returns_vec_reference(&item.sig.output);
        self.mutation_string_result |= returns_string_error(&item.sig.output);
        visit::visit_item_fn(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.public_vec_reference |=
            is_public(&item.vis) && returns_vec_reference(&item.sig.output);
        self.mutation_string_result |= returns_string_error(&item.sig.output);
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        self.public_vec_reference |= returns_vec_reference(&item.sig.output);
        self.mutation_string_result |= returns_string_error(&item.sig.output);
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.removed_format_flag |= matches!(literal.value().as_str(), "--json" | "--sarif");
        visit::visit_lit_str(self, literal);
    }
}

#[derive(Default)]
struct FilterMapFacts {
    result_ok: bool,
    ok_call: bool,
    decode_use: bool,
}

impl<'ast> Visit<'ast> for FilterMapFacts {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let names = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        self.result_ok |= names.ends_with(&["Result".to_owned(), "ok".to_owned()]);
        self.decode_use |= names.iter().any(|name| name.contains("decode"));
        visit::visit_path(self, path);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.ok_call |= expression.method == "ok";
        self.decode_use |= expression.method.to_string().contains("decode");
        visit::visit_expr_method_call(self, expression);
    }
}

fn is_public(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

fn has_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && matches!(&attribute.meta, syn::Meta::List(list) if list.tokens.to_string() == "test")
    })
}

struct TestLineRanges {
    ranges: Vec<std::ops::RangeInclusive<usize>>,
}

impl<'ast> Visit<'ast> for TestLineRanges {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if has_cfg_test(&item.attrs) {
            let span = item.span();
            self.ranges.push(span.start().line..=span.end().line);
            return;
        }
        visit::visit_item_mod(self, item);
    }
}

fn production_line_count(source: &str, syntax: &syn::File) -> usize {
    let mut tests = TestLineRanges { ranges: Vec::new() };
    tests.visit_file(syntax);
    let tokens = source
        .parse::<proc_macro2::TokenStream>()
        .expect("syn already accepted this Rust source");
    let mut code_lines = BTreeSet::new();
    collect_token_lines(tokens, &mut code_lines);
    code_lines
        .into_iter()
        .filter(|line| !tests.ranges.iter().any(|range| range.contains(line)))
        .count()
}

fn collect_token_lines(tokens: proc_macro2::TokenStream, lines: &mut BTreeSet<usize>) {
    for token in tokens {
        match token {
            proc_macro2::TokenTree::Group(group) => {
                lines.insert(group.span_open().start().line);
                lines.insert(group.span_close().end().line);
                collect_token_lines(group.stream(), lines);
            }
            token => {
                let span = token.span();
                lines.extend(span.start().line..=span.end().line);
            }
        }
    }
}

fn use_tree_contains(tree: &syn::UseTree, expected: &str) -> bool {
    match tree {
        syn::UseTree::Path(path) => {
            path.ident == expected || use_tree_contains(path.tree.as_ref(), expected)
        }
        syn::UseTree::Name(name) => name.ident == expected,
        syn::UseTree::Rename(rename) => rename.ident == expected || rename.rename == expected,
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_contains(item, expected)),
        syn::UseTree::Glob(_) => false,
    }
}

fn returns_vec_reference(output: &syn::ReturnType) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    let syn::Type::Reference(reference) = ty.as_ref() else {
        return false;
    };
    let syn::Type::Path(path) = reference.elem.as_ref() else {
        return false;
    };
    path.path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "Vec")
}

fn returns_string_error(output: &syn::ReturnType) -> bool {
    let syn::ReturnType::Type(_, ty) = output else {
        return false;
    };
    let syn::Type::Path(path) = ty.as_ref() else {
        return false;
    };
    let Some(result) = path
        .path
        .segments
        .last()
        .filter(|segment| segment.ident == "Result")
    else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &result.arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(syn::Type::Path(error))) = arguments.args.iter().nth(1)
    else {
        return false;
    };
    error
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "String")
}

fn scan_source(crate_name: &str, relative: &Path, source: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if crate_name == "xtask" {
        return violations;
    }
    let path = relative.to_string_lossy();
    let is_test = path.contains("/tests/") || path.ends_with("/tests.rs");
    let syntax = match syn::parse_file(source) {
        Ok(syntax) => syntax,
        Err(error) => {
            return vec![format!("cannot syntax-scan {path}: {error}")];
        }
    };
    let mut facts = SourceFacts::default();
    facts.visit_file(&syntax);
    let allowed_process = crate_name == "xtask" || is_test;
    if !allowed_process && facts.process_call {
        violations.push(format!(
            "host process reference outside adapters/tooling/tests: {path}"
        ));
    }
    if crate_name == "macho-cli"
        && path.contains("/src/commands/")
        && (facts.output_macro || facts.system_io_call)
    {
        violations.push(format!("CLI output bypasses injected writers: {path}"));
    }
    if crate_name == "macho-cli"
        && !is_test
        && path != "crates/macho-cli/src/main.rs"
        && (facts.output_macro || facts.system_io_call)
    {
        violations.push(format!(
            "system I/O construction outside CLI main entry point: {path}"
        ));
    }
    if crate_name == "macho-mutate" && facts.mutation_analysis_path {
        violations.push(format!("mutation references analysis: {path}"));
    }
    if crate_name == "macho-mutate" && facts.mutation_string_result {
        violations.push(format!(
            "mutation exposes a string-bucket result instead of MutationError: {path}"
        ));
    }
    if crate_name == "macho" && (path.contains("/src/commands") || path.contains("/src/inputs")) {
        violations.push(format!("façade owns delivery module: {path}"));
    }
    if facts.public_vec_reference {
        violations.push(format!("public Vec reference return detected: {path}"));
    }
    if facts.first_mach_call {
        violations.push(format!("removed first_mach() API or call detected: {path}"));
    }
    if facts.silent_decode_discard {
        violations.push(format!("possible silent decode-result discard: {path}"));
    }
    if facts.image_inspector {
        violations.push(format!("removed ImageInspector surface detected: {path}"));
    }
    if facts.removed_format_flag {
        violations.push(format!("removed format flag detected: {path}"));
    }
    if !is_test {
        let production_lines = production_line_count(source, &syntax);
        if production_lines > 800 {
            violations.push(format!(
                "production file exceeds 800 non-blank non-comment lines ({production_lines}): {path}"
            ));
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_graph_contains_every_required_package() {
        let graph = permitted_edges();
        for name in PRODUCT_CRATES
            .iter()
            .chain([&"xtask", &"macho-test-support"])
        {
            assert!(graph.contains_key(*name), "missing graph row for {name}");
        }
        assert!(graph["macho-core"].is_empty());
        assert_eq!(graph["macho-cli"], BTreeSet::from(["macho"]));

        let workspace_names = graph.keys().copied().collect();
        for (package, allowed) in &graph {
            for dependency in allowed {
                assert_eq!(
                    dependency_violation(package, dependency, &workspace_names, allowed),
                    None,
                    "valid edge rejected: {package} -> {dependency}"
                );
            }
        }
    }

    #[test]
    fn every_forbidden_workspace_edge_has_a_negative_fixture() {
        let graph = permitted_edges();
        let workspace_names: BTreeSet<_> = graph.keys().copied().collect();
        for (package, allowed) in &graph {
            for dependency in &workspace_names {
                if allowed.contains(dependency) {
                    continue;
                }
                assert!(
                    dependency_violation(package, dependency, &workspace_names, allowed).is_some(),
                    "forbidden edge was accepted: {package} -> {dependency}"
                );
            }
        }
    }

    #[test]
    fn owned_third_party_dependencies_have_positive_and_negative_fixtures() {
        let workspace_names = BTreeSet::new();
        let allowed = BTreeSet::new();
        for dependency in ["clap", "memmap2", "anyhow"] {
            assert!(
                dependency_violation("macho-core", dependency, &workspace_names, &allowed)
                    .is_some()
            );
            assert_eq!(
                dependency_violation("macho-cli", dependency, &workspace_names, &allowed),
                None
            );
        }
        assert!(
            dependency_violation("macho-core", "termosaic", &workspace_names, &allowed).is_some()
        );
        assert_eq!(
            dependency_violation("macho-cli", "termosaic", &workspace_names, &allowed),
            None
        );
        for dependency in ["cpp_demangle", "rustc-demangle", "swift-demangler"] {
            assert!(
                dependency_violation("macho-analysis", dependency, &workspace_names, &allowed)
                    .is_some()
            );
            assert_eq!(
                dependency_violation("macho-demangle", dependency, &workspace_names, &allowed),
                None
            );
        }
        assert!(
            dependency_violation("macho-cli", "apple-codesign", &workspace_names, &allowed)
                .is_some()
        );
        assert_eq!(
            dependency_violation("macho-mutate", "apple-codesign", &workspace_names, &allowed),
            None
        );
    }

    #[test]
    fn forbidden_source_patterns_have_negative_fixtures() {
        let fixtures = [
            (
                "macho-core",
                "crates/macho-core/src/x.rs",
                "fn fixture() { Command::new(\"xcrun\"); }",
            ),
            (
                "macho-cli",
                "crates/macho-cli/src/commands/x.rs",
                "fn fixture() { Command::new(\"xcrun\"); }",
            ),
            (
                "macho-cli",
                "crates/macho-cli/src/adapters.rs",
                "fn fixture() { Command::new(\"xcrun\"); }",
            ),
            (
                "macho-cli",
                "crates/macho-cli/src/adapters/signing.rs",
                "fn fixture() { std::process::Command::new(\"codesign\"); }",
            ),
            (
                "macho-cli",
                "crates/macho-cli/src/commands/x.rs",
                "fn fixture() { println!(\"x\"); }",
            ),
            (
                "macho-cli",
                "crates/macho-cli/src/lib.rs",
                "fn fixture() { let output = std::io::stdout(); }",
            ),
            (
                "macho-mutate",
                "crates/macho-mutate/src/x.rs",
                "use macho_analysis::Analyzer;",
            ),
            (
                "macho-mutate",
                "crates/macho-mutate/src/x.rs",
                "pub fn patch() -> Result<Vec<u8>, String> { todo!() }",
            ),
            ("macho", "crates/macho/src/commands.rs", "pub fn run() {}"),
            (
                "macho-core",
                "crates/macho-core/src/x.rs",
                "pub fn x() -> &'static Vec<u8> { todo!() }",
            ),
            (
                "macho-core",
                "crates/macho-core/src/x.rs",
                "fn fixture() { container.first_mach(); }",
            ),
            (
                "macho-analysis",
                "crates/macho-analysis/src/x.rs",
                "pub struct ImageInspector;",
            ),
            (
                "macho-analysis",
                "crates/macho-analysis/src/x.rs",
                "fn fixture(input: impl Iterator<Item = Result<u8, ()>>) { let _ = input.filter_map(Result::ok); }",
            ),
            (
                "macho-cli",
                "crates/macho-cli/tests/x.rs",
                "fn fixture() { let arg = \"--json\"; }",
            ),
        ];
        for (crate_name, path, source) in fixtures {
            assert!(
                !scan_source(crate_name, Path::new(path), source).is_empty(),
                "fixture did not fail: {source}"
            );
        }
    }

    #[test]
    fn valid_source_fixture_is_accepted() {
        assert!(
            scan_source(
                "macho-core",
                Path::new("crates/macho-core/src/model.rs"),
                "pub fn values() -> &'static [u8] { &[] }"
            )
            .is_empty()
        );
    }

    #[test]
    fn feature_authority_rejects_drift() {
        let mut features = BTreeMap::new();
        features.insert("default".to_string(), vec!["full".to_string()]);
        assert!(check_feature_authority(&features).is_err());
    }

    #[test]
    fn module_size_check_excludes_cfg_test_modules_only() {
        let production = (0..801)
            .map(|index| format!("pub const ITEM_{index}: usize = {index};"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            scan_source(
                "macho-core",
                Path::new("crates/macho-core/src/large.rs"),
                &production,
            )
            .iter()
            .any(|violation| violation.contains("exceeds 800"))
        );

        let tests = (0..900)
            .map(|index| format!("const TEST_ITEM_{index}: usize = {index};"))
            .collect::<Vec<_>>()
            .join("\n");
        let mixed =
            format!("pub const PRODUCTION: usize = 1;\n#[cfg(test)]\nmod tests {{\n{tests}\n}}");
        assert!(
            scan_source(
                "macho-core",
                Path::new("crates/macho-core/src/mixed.rs"),
                &mixed,
            )
            .is_empty()
        );

        let comments = (0..900)
            .map(|index| format!("comment line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let comment_heavy = format!("/*\n{comments}\n*/\npub const PRODUCTION: usize = 1;");
        assert!(
            scan_source(
                "macho-core",
                Path::new("crates/macho-core/src/comments.rs"),
                &comment_heavy,
            )
            .is_empty()
        );
    }
}
