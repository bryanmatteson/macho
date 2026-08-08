//! Deterministic rendering from typed header syntax.

use std::fmt::Write;

use crate::analysis::header_syntax::{
    Access, BuiltinType, Decl, FunctionQualifiers, Language, Linkage, MethodKind, NamedTypeTag,
    ObjectiveCForwardKind, Parameter, ParameterState, RecordKind, ReferenceKind, StorageClass,
    TemplateArgument, TranslationUnit, Type, TypeQualifiers,
};

/// Rendering failure for a semantically incompatible AST.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RenderError {
    /// A declaration cannot be expressed in the selected language.
    #[error("{construct} cannot be rendered as {language:?}")]
    LanguageMismatch {
        /// Selected language.
        language: Language,
        /// Incompatible construct.
        construct: &'static str,
    },
    /// A function declaration did not contain a function type.
    #[error("function declaration has a non-function signature")]
    InvalidFunctionSignature,
    /// An Objective-C selector and parameter list disagree.
    #[error("Objective-C selector arity does not match its parameter list")]
    SelectorArity,
}

/// Renders a complete translation unit deterministically.
pub fn render(unit: &TranslationUnit) -> Result<String, RenderError> {
    let mut output = String::new();
    for declaration in &unit.declarations {
        render_decl(declaration, unit.language, 0, &mut output)?;
    }
    Ok(output)
}

fn render_decl(
    declaration: &Decl,
    language: Language,
    indent: usize,
    output: &mut String,
) -> Result<(), RenderError> {
    let prefix = "    ".repeat(indent);
    match declaration {
        Decl::AccessSection {
            access,
            declarations,
        } => {
            if language != Language::Cpp || indent == 0 {
                return Err(RenderError::LanguageMismatch {
                    language,
                    construct: "record access section",
                });
            }
            writeln!(output, "{prefix}{}:", render_access(*access)).unwrap();
            for declaration in declarations {
                render_decl(declaration, language, indent + 1, output)?;
            }
        }
        Decl::Namespace { path, declarations } => {
            if language != Language::Cpp {
                return Err(RenderError::LanguageMismatch {
                    language,
                    construct: "namespace",
                });
            }
            writeln!(output, "{prefix}namespace {} {{", render_path(path)).unwrap();
            for declaration in declarations {
                render_decl(declaration, language, indent + 1, output)?;
            }
            writeln!(output, "{prefix}}}").unwrap();
        }
        Decl::Function {
            name,
            signature,
            storage,
            linkage,
        } => {
            ensure_linkage(language, *linkage)?;
            let Type::Function {
                return_type,
                parameters,
                parameter_state,
                variadic,
                qualifiers,
                ..
            } = signature
            else {
                return Err(RenderError::InvalidFunctionSignature);
            };
            write!(output, "{prefix}{}", render_storage(*storage)).unwrap();
            render_type(return_type, language, output)?;
            write!(output, " {name}(").unwrap();
            render_parameters(parameters, *parameter_state, *variadic, language, output)?;
            writeln!(output, "){};", render_function_qualifiers(*qualifiers)).unwrap();
        }
        Decl::Variable {
            name,
            ty,
            storage,
            linkage,
        } => {
            ensure_linkage(language, *linkage)?;
            write!(output, "{prefix}{}", render_storage(*storage)).unwrap();
            render_type(ty, language, output)?;
            writeln!(output, " {name};").unwrap();
        }
        Decl::Record {
            kind,
            path,
            bases,
            fields,
            members,
        } => {
            if *kind == RecordKind::Class && language != Language::Cpp {
                return Err(RenderError::LanguageMismatch {
                    language,
                    construct: "class",
                });
            }
            write!(
                output,
                "{prefix}{} {}",
                render_record_kind(*kind),
                render_path(path)
            )
            .unwrap();
            if !bases.is_empty() {
                output.push_str(" : ");
                for (index, base) in bases.iter().enumerate() {
                    if index != 0 {
                        output.push_str(", ");
                    }
                    if base.is_virtual {
                        output.push_str("virtual ");
                    }
                    write!(output, "{} ", render_access(base.access)).unwrap();
                    render_type(&base.ty, language, output)?;
                }
            }
            output.push_str(" {\n");
            for field in fields {
                write!(output, "{prefix}    ").unwrap();
                render_type(&field.ty, language, output)?;
                write!(output, " {}", field.name).unwrap();
                if let Some(width) = field.bit_width {
                    write!(output, " : {width}").unwrap();
                }
                output.push_str(";\n");
            }
            for member in members {
                render_decl(member, language, indent + 1, output)?;
            }
            writeln!(output, "{prefix}}};").unwrap();
        }
        Decl::Forward { kind, path } => {
            writeln!(
                output,
                "{prefix}{} {};",
                render_record_kind(*kind),
                render_path(path)
            )
            .unwrap();
        }
        Decl::Alias { path, target } => {
            if language == Language::Cpp {
                write!(output, "{prefix}using {} = ", render_path(path)).unwrap();
                render_type(target, language, output)?;
                output.push_str(";\n");
            } else {
                write!(output, "{prefix}typedef ").unwrap();
                render_type(target, language, output)?;
                writeln!(output, " {};", render_path(path)).unwrap();
            }
        }
        Decl::ObjectiveCInterface {
            name,
            superclass,
            protocols,
            ivars,
            methods,
            properties,
        } => {
            ensure_objc(language, "Objective-C interface")?;
            write!(output, "{prefix}@interface {name}").unwrap();
            if let Some(superclass) = superclass {
                write!(output, " : {superclass}").unwrap();
            }
            render_protocol_list(protocols, output);
            output.push('\n');
            if !ivars.is_empty() {
                output.push_str("{\n");
                let mut access = None;
                for ivar in ivars {
                    if access != Some(ivar.access) {
                        writeln!(output, "{}", render_objc_access(ivar.access)).unwrap();
                        access = Some(ivar.access);
                    }
                    output.push_str("    ");
                    render_type(&ivar.ty, Language::ObjectiveC, output)?;
                    writeln!(output, " {};", ivar.name).unwrap();
                }
                output.push_str("}\n");
            }
            for property in properties {
                render_objc_property(property, output)?;
            }
            for method in methods {
                render_objc_method(method, output)?;
            }
            output.push_str("@end\n");
        }
        Decl::ObjectiveCCategory {
            name,
            extended_class,
            protocols,
            methods,
            properties,
        } => {
            ensure_objc(language, "Objective-C category")?;
            write!(output, "{prefix}@interface {extended_class} ({name})").unwrap();
            render_protocol_list(protocols, output);
            output.push('\n');
            for property in properties {
                render_objc_property(property, output)?;
            }
            for method in methods {
                render_objc_method(method, output)?;
            }
            output.push_str("@end\n");
        }
        Decl::ObjectiveCProtocol {
            name,
            protocols,
            methods,
            properties,
        } => {
            ensure_objc(language, "Objective-C protocol")?;
            write!(output, "{prefix}@protocol {name}").unwrap();
            render_protocol_list(protocols, output);
            output.push('\n');
            for property in properties {
                render_objc_property(property, output)?;
            }
            for method in methods {
                render_objc_method(method, output)?;
            }
            output.push_str("@end\n");
        }
        Decl::ObjectiveCForward { kind, names } => {
            ensure_objc(language, "Objective-C forward declaration")?;
            let keyword = match kind {
                ObjectiveCForwardKind::Class => "@class",
                ObjectiveCForwardKind::Protocol => "@protocol",
            };
            write!(output, "{prefix}{keyword} ").unwrap();
            for (index, name) in names.iter().enumerate() {
                if index != 0 {
                    output.push_str(", ");
                }
                write!(output, "{name}").unwrap();
            }
            output.push_str(";\n");
        }
    }
    Ok(())
}

fn render_type(ty: &Type, language: Language, output: &mut String) -> Result<(), RenderError> {
    match ty {
        Type::Builtin(builtin) => output.push_str(render_builtin(*builtin)),
        Type::Named {
            tag,
            path,
            template_arguments,
        } => {
            if !matches!(tag, NamedTypeTag::Typedef) {
                output.push_str(render_named_tag(*tag));
                output.push(' ');
            }
            output.push_str(&render_path(path));
            if !template_arguments.is_empty() {
                ensure_cpp(language, "template argument")?;
                output.push('<');
                for (index, argument) in template_arguments.iter().enumerate() {
                    if index != 0 {
                        output.push_str(", ");
                    }
                    match argument {
                        TemplateArgument::Type(ty) => render_type(ty, language, output)?,
                        TemplateArgument::Integer(value) => write!(output, "{value}").unwrap(),
                        TemplateArgument::Identifier(path) => output.push_str(&render_path(path)),
                    }
                }
                output.push('>');
            }
        }
        Type::Pointer {
            pointee,
            qualifiers,
        } => {
            render_type(pointee, language, output)?;
            output.push_str(" *");
            render_qualifiers(*qualifiers, output);
        }
        Type::Reference { target, kind } => {
            ensure_cpp(language, "reference")?;
            render_type(target, language, output)?;
            output.push_str(match kind {
                ReferenceKind::Lvalue => " &",
                ReferenceKind::Rvalue => " &&",
            });
        }
        Type::Array { element, count } => {
            render_type(element, language, output)?;
            match count {
                Some(count) => write!(output, "[{count}]").unwrap(),
                None => output.push_str("[]"),
            }
        }
        Type::Function {
            return_type,
            parameters,
            parameter_state,
            variadic,
            qualifiers,
            ..
        } => {
            render_type(return_type, language, output)?;
            output.push_str(" (");
            render_parameters(parameters, *parameter_state, *variadic, language, output)?;
            output.push(')');
            output.push_str(&render_function_qualifiers(*qualifiers));
        }
        Type::ObjectiveCObject {
            name,
            protocols,
            qualifiers,
        } => {
            ensure_objc(language, "Objective-C object")?;
            if let Some(name) = name {
                write!(output, "{name}").unwrap();
            } else {
                output.push_str("id");
            }
            render_protocol_list(protocols, output);
            if name.is_some() {
                output.push_str(" *");
            }
            render_qualifiers(*qualifiers, output);
        }
        Type::ObjectiveCBlock(signature) => {
            ensure_objc(language, "Objective-C block")?;
            render_type(signature, language, output)?;
        }
    }
    Ok(())
}

fn render_parameters(
    parameters: &[Parameter],
    state: ParameterState,
    variadic: bool,
    language: Language,
    output: &mut String,
) -> Result<(), RenderError> {
    if parameters.is_empty() && state == ParameterState::Known && language == Language::C {
        output.push_str("void");
    }
    for (index, parameter) in parameters.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        render_type(&parameter.ty, language, output)?;
        write!(output, " {}", parameter.name).unwrap();
    }
    if variadic {
        if !parameters.is_empty() {
            output.push_str(", ");
        }
        output.push_str("...");
    }
    Ok(())
}

fn render_objc_method(
    method: &crate::analysis::header_syntax::ObjectiveCMethod,
    output: &mut String,
) -> Result<(), RenderError> {
    output.push_str(match method.kind {
        MethodKind::Instance => "- (",
        MethodKind::Class => "+ (",
    });
    render_type(&method.return_type, Language::ObjectiveC, output)?;
    output.push(')');
    let pieces = method.selector.split_terminator(':').collect::<Vec<_>>();
    if pieces.len() != method.parameters.len() {
        if method.parameters.is_empty() && !method.selector.contains(':') {
            output.push_str(&method.selector);
            output.push_str(";\n");
            return Ok(());
        }
        return Err(RenderError::SelectorArity);
    }
    for (piece, parameter) in pieces.into_iter().zip(&method.parameters) {
        write!(output, "{piece}:(").unwrap();
        render_type(&parameter.ty, Language::ObjectiveC, output)?;
        write!(output, "){} ", parameter.name).unwrap();
    }
    if output.ends_with(' ') {
        output.pop();
    }
    output.push_str(";\n");
    Ok(())
}

fn render_objc_property(
    property: &crate::analysis::header_syntax::ObjectiveCProperty,
    output: &mut String,
) -> Result<(), RenderError> {
    output.push_str("@property");
    if !property.attributes.is_empty() {
        output.push_str(" (");
        for (index, attribute) in property.attributes.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            output.push_str(render_objc_property_attribute(*attribute));
        }
        output.push(')');
    }
    output.push(' ');
    render_type(&property.ty, Language::ObjectiveC, output)?;
    writeln!(output, " {};", property.name).unwrap();
    Ok(())
}

fn render_objc_access(access: crate::analysis::header_syntax::ObjectiveCAccess) -> &'static str {
    match access {
        crate::analysis::header_syntax::ObjectiveCAccess::Public => "@public",
        crate::analysis::header_syntax::ObjectiveCAccess::Protected => "@protected",
        crate::analysis::header_syntax::ObjectiveCAccess::Private => "@private",
        crate::analysis::header_syntax::ObjectiveCAccess::Package => "@package",
    }
}

fn render_objc_property_attribute(
    attribute: crate::analysis::header_syntax::ObjectiveCPropertyAttribute,
) -> &'static str {
    use crate::analysis::header_syntax::ObjectiveCPropertyAttribute as Attribute;
    match attribute {
        Attribute::Readonly => "readonly",
        Attribute::Readwrite => "readwrite",
        Attribute::Copy => "copy",
        Attribute::Retain => "retain",
        Attribute::Strong => "strong",
        Attribute::Weak => "weak",
        Attribute::Assign => "assign",
        Attribute::Atomic => "atomic",
        Attribute::Nonatomic => "nonatomic",
        Attribute::Dynamic => "dynamic",
        Attribute::Class => "class",
    }
}

fn ensure_linkage(language: Language, linkage: Linkage) -> Result<(), RenderError> {
    let compatible = matches!(
        (language, linkage),
        (Language::C, Linkage::C)
            | (Language::Cpp, Linkage::C | Linkage::Cpp)
            | (Language::ObjectiveC, Linkage::C | Linkage::ObjectiveC)
    );
    if compatible {
        Ok(())
    } else {
        Err(RenderError::LanguageMismatch {
            language,
            construct: "language linkage",
        })
    }
}

fn ensure_cpp(language: Language, construct: &'static str) -> Result<(), RenderError> {
    if language == Language::Cpp {
        Ok(())
    } else {
        Err(RenderError::LanguageMismatch {
            language,
            construct,
        })
    }
}

fn ensure_objc(language: Language, construct: &'static str) -> Result<(), RenderError> {
    if language == Language::ObjectiveC {
        Ok(())
    } else {
        Err(RenderError::LanguageMismatch {
            language,
            construct,
        })
    }
}

fn render_storage(storage: StorageClass) -> &'static str {
    match storage {
        StorageClass::None => "",
        StorageClass::Extern => "extern ",
        StorageClass::Static => "static ",
        StorageClass::ThreadLocal => "thread_local ",
    }
}

fn render_record_kind(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Struct => "struct",
        RecordKind::Union => "union",
        RecordKind::Class => "class",
        RecordKind::Enum => "enum",
    }
}

fn render_named_tag(tag: NamedTypeTag) -> &'static str {
    match tag {
        NamedTypeTag::Typedef => "",
        NamedTypeTag::Struct => "struct",
        NamedTypeTag::Union => "union",
        NamedTypeTag::Enum => "enum",
        NamedTypeTag::Class => "class",
        NamedTypeTag::Protocol => "protocol",
    }
}

fn render_builtin(builtin: BuiltinType) -> &'static str {
    match builtin {
        BuiltinType::Void => "void",
        BuiltinType::Bool => "bool",
        BuiltinType::Char => "char",
        BuiltinType::SignedChar => "signed char",
        BuiltinType::UnsignedChar => "unsigned char",
        BuiltinType::Short => "short",
        BuiltinType::UnsignedShort => "unsigned short",
        BuiltinType::Int => "int",
        BuiltinType::UnsignedInt => "unsigned int",
        BuiltinType::Long => "long",
        BuiltinType::UnsignedLong => "unsigned long",
        BuiltinType::LongLong => "long long",
        BuiltinType::UnsignedLongLong => "unsigned long long",
        BuiltinType::Int128 => "__int128",
        BuiltinType::UnsignedInt128 => "unsigned __int128",
        BuiltinType::Float => "float",
        BuiltinType::Double => "double",
        BuiltinType::LongDouble => "long double",
    }
}

fn render_qualifiers(qualifiers: TypeQualifiers, output: &mut String) {
    if qualifiers.is_const {
        output.push_str(" const");
    }
    if qualifiers.is_volatile {
        output.push_str(" volatile");
    }
    if qualifiers.is_restrict {
        output.push_str(" restrict");
    }
}

fn render_function_qualifiers(qualifiers: FunctionQualifiers) -> String {
    let mut output = String::new();
    if qualifiers.is_const {
        output.push_str(" const");
    }
    if qualifiers.is_volatile {
        output.push_str(" volatile");
    }
    if let Some(reference) = qualifiers.reference {
        output.push_str(match reference {
            ReferenceKind::Lvalue => " &",
            ReferenceKind::Rvalue => " &&",
        });
    }
    if let Some(noexcept) = qualifiers.noexcept {
        output.push_str(if noexcept {
            " noexcept"
        } else {
            " noexcept(false)"
        });
    }
    output
}

fn render_protocol_list(
    protocols: &[crate::analysis::header_syntax::Identifier],
    output: &mut String,
) {
    if protocols.is_empty() {
        return;
    }
    output.push('<');
    for (index, protocol) in protocols.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        write!(output, "{protocol}").unwrap();
    }
    output.push('>');
}

fn render_access(access: Access) -> &'static str {
    match access {
        Access::Public => "public",
        Access::Protected => "protected",
        Access::Private => "private",
        Access::Unspecified => "public",
    }
}

fn render_path(path: &crate::analysis::header_syntax::IdentifierPath) -> String {
    path.components()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("::")
}

#[cfg(test)]
mod tests {
    use crate::analysis::header_syntax::{HeaderParser, TreeSitterHeaderParser};

    use super::*;

    #[test]
    fn rendered_c_reparses() {
        let source = "struct Point { int x; int y; };\nint distance(struct Point *point);";
        let unit = TreeSitterHeaderParser.parse(Language::C, source).unwrap();
        let rendered = render(&unit).unwrap();
        TreeSitterHeaderParser
            .parse(Language::C, &rendered)
            .unwrap();
    }

    #[test]
    fn rendered_cpp_namespace_reparses_with_ownership() {
        let source = "namespace sample { class Widget; int run(int value); }";
        let unit = TreeSitterHeaderParser.parse(Language::Cpp, source).unwrap();
        let rendered = render(&unit).unwrap();
        assert!(rendered.contains("namespace sample {"), "{rendered}");
        let reparsed = TreeSitterHeaderParser
            .parse(Language::Cpp, &rendered)
            .unwrap();
        assert!(matches!(
            reparsed.declarations.as_slice(),
            [Decl::Namespace { .. }]
        ));
    }

    #[test]
    fn rendered_cpp_record_preserves_member_access() {
        let source = "class Widget { public: int run(int value) const; protected: int reset(); };";
        let unit = TreeSitterHeaderParser.parse(Language::Cpp, source).unwrap();
        let rendered = render(&unit).unwrap();
        assert!(rendered.contains("public:"), "{rendered}");
        assert!(rendered.contains("protected:"), "{rendered}");
        let reparsed = TreeSitterHeaderParser
            .parse(Language::Cpp, &rendered)
            .unwrap();
        assert_eq!(unit.declarations, reparsed.declarations);
    }

    #[test]
    fn rendered_objective_c_reparses() {
        let source = "@interface Widget : NSObject\n- (int)value;\n@end";
        let unit = TreeSitterHeaderParser
            .parse(Language::ObjectiveC, source)
            .unwrap();
        let rendered = render(&unit).unwrap();
        TreeSitterHeaderParser
            .parse(Language::ObjectiveC, &rendered)
            .unwrap();
    }
}
