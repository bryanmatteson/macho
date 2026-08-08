//! Bounded semantic validation for typed headers.

mod redeclaration;

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::header_syntax::{
    Decl, IdentifierPath, ObjectiveCForwardKind, TranslationUnit, Type,
};
use redeclaration::{Redeclaration, declaration_identity, redeclaration};

/// Stable semantic validation diagnostic code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderValidationCode {
    /// Concrete syntax was invalid.
    SyntaxError,
    /// The same declaration was repeated.
    DuplicateDeclaration,
    /// Declarations with the same identity disagree.
    ConflictingRedeclaration,
    /// A tagged type has no declaration.
    UnresolvedType,
    /// A declaration owner has no declaration.
    UnresolvedOwner,
    /// The declared linkage is incompatible with the language.
    InvalidLinkage,
    /// The storage class is incompatible with the declaration.
    InvalidStorage,
    /// The calling convention is incompatible with the language.
    InvalidCallingConvention,
    /// A template could not be represented completely.
    IncompleteTemplateContext,
    /// An Objective-C selector's colon count differs from its parameter count.
    SelectorArityMismatch,
    /// An Objective-C reference resolves to the wrong entity kind.
    ObjectiveCKindMismatch,
    /// The declaration dependency graph contains a cycle.
    DependencyCycle,
}

/// Diagnostic severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    /// Informational finding.
    Info,
    /// Recoverable weakness.
    Warning,
    /// Semantic validation failure.
    Error,
}

/// One semantic validation diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValidationDiagnostic {
    /// Stable diagnostic code.
    pub code: HeaderValidationCode,
    /// Severity.
    pub severity: Severity,
    /// Human-readable explanation.
    pub message: String,
    /// Top-level declaration index, when applicable.
    pub declaration_index: Option<u32>,
}

/// Complete syntax and semantic validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderValidationReport {
    /// Whether concrete syntax parsing succeeded.
    pub syntax_valid: bool,
    /// Whether all semantic checks succeeded.
    pub semantic_valid: bool,
    /// Ordered diagnostics.
    pub diagnostics: Vec<HeaderValidationDiagnostic>,
}

/// Hard resource bounds for recursive validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationLimits {
    /// Maximum nested type depth.
    pub max_type_depth: usize,
    /// Maximum nested declaration depth.
    pub max_declaration_depth: usize,
    /// Maximum number of template arguments or members on one node.
    pub max_items_per_node: usize,
    /// Maximum total AST nodes.
    pub max_total_nodes: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            max_type_depth: 64,
            max_declaration_depth: 64,
            max_items_per_node: 1_024,
            max_total_nodes: 1_000_000,
        }
    }
}

/// Typed validation limit failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    /// Type nesting exceeded the configured bound.
    #[error("type recursion depth {actual} exceeds limit {limit}")]
    TypeDepth {
        /// Configured maximum.
        limit: usize,
        /// Observed depth.
        actual: usize,
    },
    /// Declaration nesting exceeded the configured bound.
    #[error("declaration nesting depth {actual} exceeds limit {limit}")]
    DeclarationDepth {
        /// Configured maximum.
        limit: usize,
        /// Observed depth.
        actual: usize,
    },
    /// One node contained too many children.
    #[error("{kind} item count {actual} exceeds limit {limit}")]
    ItemsPerNode {
        /// Child collection name.
        kind: &'static str,
        /// Configured maximum.
        limit: usize,
        /// Observed count.
        actual: usize,
    },
    /// The total syntax tree was too large.
    #[error("AST node count exceeds limit {limit}")]
    TotalNodes {
        /// Configured maximum.
        limit: usize,
    },
}

/// Validates a parsed translation unit under the normative resource bounds.
pub fn validate(
    unit: &TranslationUnit,
    limits: ValidationLimits,
) -> Result<HeaderValidationReport, ValidationError> {
    let mut budget = Budget { limits, nodes: 0 };
    for declaration in &unit.declarations {
        budget.declaration(declaration, 1)?;
    }

    let mut diagnostics = Vec::new();
    let mut declarations = BTreeMap::<String, (usize, &Decl)>::new();
    let mut declared_tags = BTreeSet::new();
    let mut objc_classes = BTreeSet::new();
    let mut objc_protocols = BTreeSet::new();

    // `id`, `Class`, and `SEL` are supplied by the Objective-C runtime rather
    // than by a recovered image. They are valid in a standalone projected
    // header without needing an SDK preamble.
    if unit.language == crate::analysis::header_syntax::Language::ObjectiveC {
        declared_tags.extend(["id".to_owned(), "Class".to_owned(), "SEL".to_owned()]);
    }

    for (index, declaration) in unit.declarations.iter().enumerate() {
        if matches!(declaration, Decl::AccessSection { .. }) {
            diagnostics.push(diagnostic(
                HeaderValidationCode::SyntaxError,
                "C++ access section is invalid outside a record".to_owned(),
                index,
            ));
        }
        collect_declared_types(
            declaration,
            &mut declared_tags,
            &mut objc_classes,
            &mut objc_protocols,
        );
        collect_redeclarations(
            unit.language,
            declaration,
            index,
            "",
            &mut declarations,
            &mut diagnostics,
        );
    }

    // Tree-sitter represents Objective-C class pointer spellings such as
    // `NSString *` as named types.  An `@class NSString;` declaration is the
    // corresponding declaration authority, so make that namespace available
    // to named-type validation after the complete declaration pass.
    declared_tags.extend(objc_classes.iter().cloned());

    for (index, declaration) in unit.declarations.iter().enumerate() {
        validate_decl(
            declaration,
            index,
            &declared_tags,
            &objc_classes,
            &objc_protocols,
            &mut diagnostics,
        );
    }
    validate_cycles(&unit.declarations, &mut diagnostics);
    diagnostics.sort_by_key(|diagnostic| {
        (
            diagnostic.declaration_index.unwrap_or(u32::MAX),
            diagnostic.code as u8,
            diagnostic.message.clone(),
        )
    });
    let semantic_valid = !diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error);
    Ok(HeaderValidationReport {
        syntax_valid: true,
        semantic_valid,
        diagnostics,
    })
}

fn collect_redeclarations<'a>(
    language: crate::analysis::header_syntax::Language,
    declaration: &'a Decl,
    index: usize,
    scope: &str,
    declarations: &mut BTreeMap<String, (usize, &'a Decl)>,
    diagnostics: &mut Vec<HeaderValidationDiagnostic>,
) {
    if let Decl::Namespace {
        path,
        declarations: nested,
    } = declaration
    {
        let namespace = qualified_in_scope(scope, &path_string(path));
        for declaration in nested {
            collect_redeclarations(
                language,
                declaration,
                index,
                &namespace,
                declarations,
                diagnostics,
            );
        }
        return;
    }

    let Some(identity) = declaration_identity(language, declaration) else {
        return;
    };
    let identity = qualified_in_scope(scope, &identity);
    if let Some((previous_index, previous)) = declarations.get(&identity) {
        match redeclaration(language, previous, declaration) {
            Redeclaration::Compatible { replace } => {
                diagnostics.push(diagnostic_with_severity(
                    HeaderValidationCode::DuplicateDeclaration,
                    Severity::Info,
                    format!("declaration `{identity}` is compatible with index {previous_index}"),
                    index,
                ));
                if replace {
                    declarations.insert(identity, (index, declaration));
                }
            }
            Redeclaration::Duplicate => diagnostics.push(diagnostic(
                HeaderValidationCode::DuplicateDeclaration,
                format!("declaration `{identity}` duplicates index {previous_index}"),
                index,
            )),
            Redeclaration::Conflict => diagnostics.push(diagnostic(
                HeaderValidationCode::ConflictingRedeclaration,
                format!("declaration `{identity}` conflicts with index {previous_index}"),
                index,
            )),
        }
    } else {
        declarations.insert(identity, (index, declaration));
    }
}

fn qualified_in_scope(scope: &str, name: &str) -> String {
    if scope.is_empty() {
        name.to_owned()
    } else {
        format!("{scope}::{name}")
    }
}

struct Budget {
    limits: ValidationLimits,
    nodes: usize,
}

impl Budget {
    fn node(&mut self) -> Result<(), ValidationError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_total_nodes {
            Err(ValidationError::TotalNodes {
                limit: self.limits.max_total_nodes,
            })
        } else {
            Ok(())
        }
    }

    fn items(&self, kind: &'static str, actual: usize) -> Result<(), ValidationError> {
        if actual > self.limits.max_items_per_node {
            Err(ValidationError::ItemsPerNode {
                kind,
                limit: self.limits.max_items_per_node,
                actual,
            })
        } else {
            Ok(())
        }
    }

    fn declaration(&mut self, declaration: &Decl, depth: usize) -> Result<(), ValidationError> {
        if depth > self.limits.max_declaration_depth {
            return Err(ValidationError::DeclarationDepth {
                limit: self.limits.max_declaration_depth,
                actual: depth,
            });
        }
        self.node()?;
        match declaration {
            Decl::AccessSection { declarations, .. } => {
                self.items("access-section declarations", declarations.len())?;
                for declaration in declarations {
                    self.declaration(declaration, depth + 1)?;
                }
                Ok(())
            }
            Decl::Namespace { declarations, .. } => {
                self.items("namespace declarations", declarations.len())?;
                for declaration in declarations {
                    self.declaration(declaration, depth + 1)?;
                }
                Ok(())
            }
            Decl::Function { signature, .. } => self.ty(signature, 1),
            Decl::Variable { ty, .. } | Decl::Alias { target: ty, .. } => self.ty(ty, 1),
            Decl::Record {
                bases,
                fields,
                members,
                ..
            } => {
                self.items("record members", bases.len() + fields.len() + members.len())?;
                for base in bases {
                    self.node()?;
                    self.ty(&base.ty, 1)?;
                }
                for field in fields {
                    self.node()?;
                    self.ty(&field.ty, 1)?;
                }
                for member in members {
                    self.declaration(member, depth + 1)?;
                }
                Ok(())
            }
            Decl::Forward { .. } => Ok(()),
            Decl::ObjectiveCInterface {
                ivars,
                methods,
                properties,
                ..
            } => {
                self.items(
                    "Objective-C members",
                    ivars.len() + methods.len() + properties.len(),
                )?;
                for ivar in ivars {
                    self.node()?;
                    self.ty(&ivar.ty, 1)?;
                }
                self.objc_members(methods, properties)
            }
            Decl::ObjectiveCCategory {
                methods,
                properties,
                ..
            }
            | Decl::ObjectiveCProtocol {
                methods,
                properties,
                ..
            } => {
                self.items("Objective-C members", methods.len() + properties.len())?;
                self.objc_members(methods, properties)
            }
            Decl::ObjectiveCForward { names, .. } => {
                self.items("Objective-C forward names", names.len())
            }
        }
    }

    fn objc_members(
        &mut self,
        methods: &[crate::analysis::header_syntax::ObjectiveCMethod],
        properties: &[crate::analysis::header_syntax::ObjectiveCProperty],
    ) -> Result<(), ValidationError> {
        for method in methods {
            self.node()?;
            self.ty(&method.return_type, 1)?;
            self.items("Objective-C method parameters", method.parameters.len())?;
            for parameter in &method.parameters {
                self.node()?;
                self.ty(&parameter.ty, 1)?;
            }
        }
        for property in properties {
            self.node()?;
            self.ty(&property.ty, 1)?;
        }
        Ok(())
    }

    fn ty(&mut self, ty: &Type, depth: usize) -> Result<(), ValidationError> {
        if depth > self.limits.max_type_depth {
            return Err(ValidationError::TypeDepth {
                limit: self.limits.max_type_depth,
                actual: depth,
            });
        }
        self.node()?;
        match ty {
            Type::Builtin(_) => Ok(()),
            Type::Named {
                template_arguments, ..
            } => {
                self.items("template arguments", template_arguments.len())?;
                for argument in template_arguments {
                    self.node()?;
                    if let crate::analysis::header_syntax::TemplateArgument::Type(ty) = argument {
                        self.ty(ty, depth + 1)?;
                    }
                }
                Ok(())
            }
            Type::Pointer { pointee, .. }
            | Type::Reference {
                target: pointee, ..
            }
            | Type::Array {
                element: pointee, ..
            }
            | Type::ObjectiveCBlock(pointee) => self.ty(pointee, depth + 1),
            Type::Function {
                return_type,
                parameters,
                ..
            } => {
                self.items("function parameters", parameters.len())?;
                self.ty(return_type, depth + 1)?;
                for parameter in parameters {
                    self.node()?;
                    self.ty(&parameter.ty, depth + 1)?;
                }
                Ok(())
            }
            Type::ObjectiveCObject { protocols, .. } => {
                self.items("Objective-C protocols", protocols.len())
            }
        }
    }
}

fn collect_declared_types(
    declaration: &Decl,
    tags: &mut BTreeSet<String>,
    classes: &mut BTreeSet<String>,
    protocols: &mut BTreeSet<String>,
) {
    match declaration {
        Decl::AccessSection { declarations, .. } => {
            for declaration in declarations {
                collect_declared_types(declaration, tags, classes, protocols);
            }
        }
        Decl::Namespace { path, declarations } => {
            let prefix = path_string(path);
            for declaration in declarations {
                collect_declared_types_in_namespace(declaration, &prefix, tags, classes, protocols);
            }
        }
        Decl::Record { path, members, .. } => {
            tags.insert(path_string(path));
            for member in members {
                collect_declared_types(member, tags, classes, protocols);
            }
        }
        Decl::Forward { path, .. } | Decl::Alias { path, .. } => {
            tags.insert(path_string(path));
        }
        Decl::ObjectiveCInterface { name, .. } => {
            classes.insert(name.to_string());
        }
        Decl::ObjectiveCProtocol { name, .. } => {
            protocols.insert(name.to_string());
        }
        Decl::ObjectiveCForward { kind, names } => {
            let destination = match kind {
                ObjectiveCForwardKind::Class => classes,
                ObjectiveCForwardKind::Protocol => protocols,
            };
            destination.extend(names.iter().map(ToString::to_string));
        }
        Decl::Function { .. } | Decl::Variable { .. } | Decl::ObjectiveCCategory { .. } => {}
    }
}

fn collect_declared_types_in_namespace(
    declaration: &Decl,
    namespace: &str,
    tags: &mut BTreeSet<String>,
    classes: &mut BTreeSet<String>,
    protocols: &mut BTreeSet<String>,
) {
    match declaration {
        Decl::AccessSection { declarations, .. } => {
            for declaration in declarations {
                collect_declared_types_in_namespace(
                    declaration,
                    namespace,
                    tags,
                    classes,
                    protocols,
                );
            }
        }
        Decl::Namespace { path, declarations } => {
            let namespace = format!("{namespace}::{}", path_string(path));
            for declaration in declarations {
                collect_declared_types_in_namespace(
                    declaration,
                    &namespace,
                    tags,
                    classes,
                    protocols,
                );
            }
        }
        Decl::Record { path, members, .. } => {
            let path = path_string(path);
            tags.insert(path.clone());
            tags.insert(format!("{namespace}::{path}"));
            for member in members {
                collect_declared_types_in_namespace(member, namespace, tags, classes, protocols);
            }
        }
        Decl::Forward { path, .. } | Decl::Alias { path, .. } => {
            let path = path_string(path);
            tags.insert(path.clone());
            tags.insert(format!("{namespace}::{path}"));
        }
        _ => collect_declared_types(declaration, tags, classes, protocols),
    }
}

fn validate_decl(
    declaration: &Decl,
    index: usize,
    tags: &BTreeSet<String>,
    classes: &BTreeSet<String>,
    protocols: &BTreeSet<String>,
    diagnostics: &mut Vec<HeaderValidationDiagnostic>,
) {
    match declaration {
        Decl::AccessSection { declarations, .. } => {
            for declaration in declarations {
                validate_decl(declaration, index, tags, classes, protocols, diagnostics);
            }
        }
        Decl::Namespace { declarations, .. } => {
            for declaration in declarations {
                validate_decl(declaration, index, tags, classes, protocols, diagnostics);
            }
        }
        Decl::Function { signature, .. } => {
            validate_type(signature, index, tags, protocols, diagnostics)
        }
        Decl::Variable { ty, .. } | Decl::Alias { target: ty, .. } => {
            validate_type(ty, index, tags, protocols, diagnostics)
        }
        Decl::Record {
            bases,
            fields,
            members,
            ..
        } => {
            for base in bases {
                validate_type(&base.ty, index, tags, protocols, diagnostics);
            }
            for field in fields {
                validate_type(&field.ty, index, tags, protocols, diagnostics);
            }
            for member in members {
                validate_decl(member, index, tags, classes, protocols, diagnostics);
            }
        }
        Decl::Forward { .. } | Decl::ObjectiveCForward { .. } => {}
        Decl::ObjectiveCInterface {
            superclass,
            protocols: adopted,
            ivars,
            methods,
            properties,
            ..
        } => {
            if let Some(superclass) = superclass
                .as_ref()
                .filter(|name| !classes.contains(name.as_str()))
            {
                diagnostics.push(diagnostic(
                    HeaderValidationCode::UnresolvedOwner,
                    format!("Objective-C superclass `{superclass}` is not declared"),
                    index,
                ));
            }
            for ivar in ivars {
                validate_type(&ivar.ty, index, tags, protocols, diagnostics);
            }
            validate_objc_members(
                adopted,
                methods,
                properties,
                index,
                tags,
                protocols,
                diagnostics,
            );
        }
        Decl::ObjectiveCCategory {
            extended_class,
            protocols: adopted,
            methods,
            properties,
            ..
        } => {
            if !classes.contains(extended_class.as_str()) {
                diagnostics.push(diagnostic(
                    HeaderValidationCode::UnresolvedOwner,
                    format!("Objective-C category owner `{extended_class}` is not declared"),
                    index,
                ));
            }
            validate_objc_members(
                adopted,
                methods,
                properties,
                index,
                tags,
                protocols,
                diagnostics,
            );
        }
        Decl::ObjectiveCProtocol {
            protocols: adopted,
            methods,
            properties,
            ..
        } => validate_objc_members(
            adopted,
            methods,
            properties,
            index,
            tags,
            protocols,
            diagnostics,
        ),
    }
}

fn validate_objc_members(
    adopted: &[crate::analysis::header_syntax::Identifier],
    methods: &[crate::analysis::header_syntax::ObjectiveCMethod],
    properties: &[crate::analysis::header_syntax::ObjectiveCProperty],
    index: usize,
    tags: &BTreeSet<String>,
    protocols: &BTreeSet<String>,
    diagnostics: &mut Vec<HeaderValidationDiagnostic>,
) {
    for protocol in adopted {
        if !protocols.contains(protocol.as_str()) {
            diagnostics.push(diagnostic(
                HeaderValidationCode::ObjectiveCKindMismatch,
                format!("Objective-C protocol `{protocol}` is not declared"),
                index,
            ));
        }
    }
    let mut identities = BTreeSet::new();
    for method in methods {
        let identity = format!("method:{:?}:{}", method.kind, method.selector);
        if !identities.insert(identity) {
            diagnostics.push(diagnostic(
                HeaderValidationCode::DuplicateDeclaration,
                format!("duplicate Objective-C method `{}`", method.selector),
                index,
            ));
        }
        let arity = method.selector.bytes().filter(|byte| *byte == b':').count();
        if arity != method.parameters.len() {
            diagnostics.push(diagnostic(
                HeaderValidationCode::SelectorArityMismatch,
                format!(
                    "selector `{}` has {arity} component(s) but {} parameter(s)",
                    method.selector,
                    method.parameters.len()
                ),
                index,
            ));
        }
        validate_type(&method.return_type, index, tags, protocols, diagnostics);
        for parameter in &method.parameters {
            validate_type(&parameter.ty, index, tags, protocols, diagnostics);
        }
    }
    for property in properties {
        if !identities.insert(format!("property:{}", property.name)) {
            diagnostics.push(diagnostic(
                HeaderValidationCode::DuplicateDeclaration,
                format!("duplicate Objective-C property `{}`", property.name),
                index,
            ));
        }
        validate_type(&property.ty, index, tags, protocols, diagnostics);
    }
}

fn validate_type(
    ty: &Type,
    index: usize,
    tags: &BTreeSet<String>,
    protocols: &BTreeSet<String>,
    diagnostics: &mut Vec<HeaderValidationDiagnostic>,
) {
    match ty {
        Type::Builtin(_) => {}
        Type::Named {
            tag,
            path,
            template_arguments,
        } => {
            let name = path_string(path);
            let resolved = if matches!(tag, crate::analysis::header_syntax::NamedTypeTag::Protocol)
            {
                protocols.contains(&name)
            } else {
                tags.contains(&name)
            };
            if !resolved {
                diagnostics.push(diagnostic(
                    HeaderValidationCode::UnresolvedType,
                    format!("named type `{name}` is not declared"),
                    index,
                ));
            }
            for argument in template_arguments {
                if let crate::analysis::header_syntax::TemplateArgument::Type(ty) = argument {
                    validate_type(ty, index, tags, protocols, diagnostics);
                }
            }
        }
        Type::Pointer { pointee, .. }
        | Type::Reference {
            target: pointee, ..
        }
        | Type::Array {
            element: pointee, ..
        }
        | Type::ObjectiveCBlock(pointee) => {
            validate_type(pointee, index, tags, protocols, diagnostics)
        }
        Type::Function {
            return_type,
            parameters,
            ..
        } => {
            validate_type(return_type, index, tags, protocols, diagnostics);
            for parameter in parameters {
                validate_type(&parameter.ty, index, tags, protocols, diagnostics);
            }
        }
        Type::ObjectiveCObject {
            name,
            protocols: used,
            ..
        } => {
            // Class names may originate in imported SDK headers and are opaque here.
            let _ = name;
            for protocol in used {
                if !protocols.contains(protocol.as_str()) {
                    diagnostics.push(diagnostic(
                        HeaderValidationCode::ObjectiveCKindMismatch,
                        format!("Objective-C protocol `{protocol}` is not declared"),
                        index,
                    ));
                }
            }
        }
    }
}

fn validate_cycles(declarations: &[Decl], diagnostics: &mut Vec<HeaderValidationDiagnostic>) {
    let mut graph = BTreeMap::new();
    let mut records = Vec::new();
    for (index, declaration) in declarations.iter().enumerate() {
        collect_record_dependencies(declaration, index, "", &mut graph, &mut records);
    }
    for (start, index) in records {
        if reaches(&graph, &start, &start, &mut BTreeSet::new()) {
            diagnostics.push(diagnostic(
                HeaderValidationCode::DependencyCycle,
                format!("record dependency cycle includes `{start}`"),
                index,
            ));
        }
    }
}

fn collect_record_dependencies(
    declaration: &Decl,
    index: usize,
    scope: &str,
    graph: &mut BTreeMap<String, BTreeSet<String>>,
    records: &mut Vec<(String, usize)>,
) {
    match declaration {
        Decl::AccessSection { declarations, .. } => {
            for declaration in declarations {
                collect_record_dependencies(declaration, index, scope, graph, records);
            }
        }
        Decl::Namespace { path, declarations } => {
            let namespace = qualified_in_scope(scope, &path_string(path));
            for declaration in declarations {
                collect_record_dependencies(declaration, index, &namespace, graph, records);
            }
        }
        Decl::Record { path, bases, .. } => {
            let start = qualified_in_scope(scope, &path_string(path));
            let dependencies = bases
                .iter()
                .filter_map(|base| match &base.ty {
                    Type::Named { path, .. } => {
                        let name = path_string(path);
                        Some(if name.contains("::") {
                            name
                        } else {
                            qualified_in_scope(scope, &name)
                        })
                    }
                    _ => None,
                })
                .collect();
            graph.insert(start.clone(), dependencies);
            records.push((start, index));
        }
        _ => {}
    }
}

fn reaches(
    graph: &BTreeMap<String, BTreeSet<String>>,
    current: &str,
    target: &str,
    seen: &mut BTreeSet<String>,
) -> bool {
    if !seen.insert(current.to_owned()) {
        return false;
    }
    graph.get(current).is_some_and(|dependencies| {
        dependencies
            .iter()
            .any(|dependency| dependency == target || reaches(graph, dependency, target, seen))
    })
}

fn diagnostic(
    code: HeaderValidationCode,
    message: String,
    index: usize,
) -> HeaderValidationDiagnostic {
    diagnostic_with_severity(code, Severity::Error, message, index)
}

fn diagnostic_with_severity(
    code: HeaderValidationCode,
    severity: Severity,
    message: String,
    index: usize,
) -> HeaderValidationDiagnostic {
    HeaderValidationDiagnostic {
        code,
        severity,
        message,
        declaration_index: u32::try_from(index).ok(),
    }
}

fn path_string(path: &IdentifierPath) -> String {
    path.components()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("::")
}

#[cfg(test)]
mod tests {
    use crate::analysis::header_syntax::{
        BuiltinType, CallingConvention, Decl, FunctionQualifiers, HeaderParser, Identifier,
        IdentifierPath, Language, Linkage, MethodKind, ObjectiveCMethod, Parameter, ParameterState,
        RecordKind, StorageClass, TranslationUnit, Type,
    };

    use super::*;

    #[test]
    fn duplicate_definitions_are_rejected() {
        let declaration = Decl::Record {
            kind: RecordKind::Struct,
            path: IdentifierPath::new(vec![Identifier::new("Value").unwrap()]).unwrap(),
            bases: Vec::new(),
            fields: Vec::new(),
            members: Vec::new(),
        };
        let report = validate(
            &TranslationUnit {
                language: Language::C,
                declarations: vec![declaration.clone(), declaration],
                declaration_spans: Vec::new(),
            },
            ValidationLimits::default(),
        )
        .unwrap();
        assert!(!report.semantic_valid);
        assert_eq!(
            report.diagnostics[0].code,
            HeaderValidationCode::DuplicateDeclaration
        );
    }

    #[test]
    fn conflicting_redeclarations_across_reopened_namespaces_are_rejected() {
        let unit = crate::analysis::header_syntax::TreeSitterHeaderParser
            .parse(
                Language::Cpp,
                "namespace sample { int transform(int value); }\n\
                 namespace sample { long transform(int value); }",
            )
            .unwrap();
        let report = validate(&unit, ValidationLimits::default()).unwrap();
        assert!(!report.semantic_valid);
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == HeaderValidationCode::ConflictingRedeclaration
        }));
    }

    #[test]
    fn compatible_function_redeclarations_are_accepted() {
        let function = |parameter_name: &str, return_type| Decl::Function {
            name: Identifier::new("transform").unwrap(),
            signature: Type::Function {
                return_type: Box::new(Type::Builtin(return_type)),
                parameters: vec![Parameter {
                    name: Identifier::new(parameter_name).unwrap(),
                    ty: Type::Builtin(BuiltinType::Int),
                }],
                parameter_state: ParameterState::Known,
                variadic: false,
                calling_convention: CallingConvention::C,
                qualifiers: FunctionQualifiers::default(),
            },
            storage: StorageClass::Extern,
            linkage: Linkage::C,
        };
        let report = validate(
            &TranslationUnit {
                language: Language::C,
                declarations: vec![
                    function("input", BuiltinType::Int),
                    function("value", BuiltinType::Int),
                ],
                declaration_spans: Vec::new(),
            },
            ValidationLimits::default(),
        )
        .unwrap();
        assert!(report.semantic_valid);
        assert_eq!(report.diagnostics[0].severity, Severity::Info);
    }

    #[test]
    fn conflicting_function_redeclarations_are_rejected() {
        let function = |return_type| Decl::Function {
            name: Identifier::new("transform").unwrap(),
            signature: Type::Function {
                return_type: Box::new(Type::Builtin(return_type)),
                parameters: Vec::new(),
                parameter_state: ParameterState::Known,
                variadic: false,
                calling_convention: CallingConvention::C,
                qualifiers: FunctionQualifiers::default(),
            },
            storage: StorageClass::Extern,
            linkage: Linkage::C,
        };
        let report = validate(
            &TranslationUnit {
                language: Language::C,
                declarations: vec![function(BuiltinType::Int), function(BuiltinType::Long)],
                declaration_spans: Vec::new(),
            },
            ValidationLimits::default(),
        )
        .unwrap();
        assert!(!report.semantic_valid);
        assert_eq!(
            report.diagnostics[0].code,
            HeaderValidationCode::ConflictingRedeclaration
        );
    }

    #[test]
    fn selector_arity_is_checked() {
        let report = validate(
            &TranslationUnit {
                language: Language::ObjectiveC,
                declarations: vec![Decl::ObjectiveCProtocol {
                    name: Identifier::new("Widget").unwrap(),
                    protocols: Vec::new(),
                    methods: vec![ObjectiveCMethod {
                        kind: MethodKind::Instance,
                        selector: "setValue:".to_owned(),
                        return_type: Type::Builtin(BuiltinType::Void),
                        parameters: Vec::new(),
                        required: Some(true),
                    }],
                    properties: Vec::new(),
                }],
                declaration_spans: Vec::new(),
            },
            ValidationLimits::default(),
        )
        .unwrap();
        assert_eq!(
            report.diagnostics[0].code,
            HeaderValidationCode::SelectorArityMismatch
        );
    }

    #[test]
    fn objc_class_forward_resolves_reparsed_named_pointer_types() {
        let unit = crate::analysis::header_syntax::TreeSitterHeaderParser
            .parse(
                Language::ObjectiveC,
                "@class NSString;\n@interface Widget\n@property NSString * name;\n@end\n",
            )
            .unwrap();
        let report = validate(&unit, ValidationLimits::default()).unwrap();
        assert!(report.semantic_valid, "{:?}", report.diagnostics);
    }

    #[test]
    fn type_depth_is_bounded() {
        let mut ty = Type::Builtin(BuiltinType::Int);
        for _ in 0..65 {
            ty = Type::Pointer {
                pointee: Box::new(ty),
                qualifiers: Default::default(),
            };
        }
        let error = validate(
            &TranslationUnit {
                language: Language::C,
                declarations: vec![Decl::Variable {
                    name: Identifier::new("value").unwrap(),
                    ty,
                    storage: StorageClass::None,
                    linkage: Linkage::C,
                }],
                declaration_spans: Vec::new(),
            },
            ValidationLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ValidationError::TypeDepth { .. }));
    }
}
