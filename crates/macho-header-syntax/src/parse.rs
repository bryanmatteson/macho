//! Tree-sitter-backed header parsing and typed lowering.

mod declaration;
mod diagnostics;
mod type_parse;

use declaration::{lower_declaration, lower_record};
pub(super) use type_parse::parse_type;

use tree_sitter::{Node, Parser};

use crate::{
    Decl, FunctionQualifiers, Identifier, IdentifierPath, Language, Linkage, MethodKind,
    NamedTypeTag, ObjectiveCForwardKind, ObjectiveCMethod, Parameter, ParameterState, RecordKind,
    StorageClass, TranslationUnit,
};

/// A source span reported by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceSpan {
    /// Zero-based starting byte offset.
    pub start: usize,
    /// Exclusive ending byte offset.
    pub end: usize,
    /// One-based line number.
    pub line: usize,
    /// One-based column number.
    pub column: usize,
}

/// A concrete syntax issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxIssue {
    /// Tree-sitter node kind.
    pub kind: String,
    /// Source location.
    pub span: SourceSpan,
}

/// Header parsing failure.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The selected grammar could not be installed.
    #[error("failed to initialize {0:?} header grammar")]
    Grammar(Language),
    /// Tree-sitter could not produce a tree.
    #[error("header parser did not produce a syntax tree")]
    NoTree,
    /// Concrete syntax errors were found.
    #[error("header contains syntax errors: {}", diagnostics::format_syntax_issues(.0))]
    Syntax(Vec<SyntaxIssue>),
    /// A syntactically valid construct cannot be represented by the typed AST.
    #[error("unsupported header construct `{kind}` at byte {span_start}")]
    Unsupported {
        /// Tree-sitter construct name.
        kind: String,
        /// Starting byte offset.
        span_start: usize,
    },
    /// A declaration was syntactically present but not structurally valid.
    #[error("invalid declaration: {0}")]
    InvalidDeclaration(String),
}

/// Process-free parser for C-family headers.
pub trait HeaderParser {
    /// Parses a complete header translation unit.
    fn parse(&self, language: Language, source: &str) -> Result<TranslationUnit, ParseError>;
}

/// Tree-sitter implementation of [`HeaderParser`].
#[derive(Debug, Default, Clone, Copy)]
pub struct TreeSitterHeaderParser;

impl HeaderParser for TreeSitterHeaderParser {
    fn parse(&self, language: Language, source: &str) -> Result<TranslationUnit, ParseError> {
        let mut parser = Parser::new();
        let grammar = match language {
            Language::C => tree_sitter_c::LANGUAGE,
            Language::Cpp => tree_sitter_cpp::LANGUAGE,
            Language::ObjectiveC => tree_sitter_objc::LANGUAGE,
        };
        parser
            .set_language(&grammar.into())
            .map_err(|_| ParseError::Grammar(language))?;
        let tree = parser.parse(source, None).ok_or(ParseError::NoTree)?;
        let root = tree.root_node();
        if root.has_error() {
            let mut issues = Vec::new();
            collect_syntax_issues(root, &mut issues);
            return Err(ParseError::Syntax(issues));
        }

        let mut declarations = Vec::new();
        let mut declaration_spans = Vec::new();
        lower_children(
            root,
            source,
            language,
            &mut declarations,
            &mut declaration_spans,
        )?;
        Ok(TranslationUnit {
            language,
            declarations,
            declaration_spans,
        })
    }
}

fn collect_syntax_issues(node: Node<'_>, issues: &mut Vec<SyntaxIssue>) {
    if node.is_error() || node.is_missing() {
        let point = node.start_position();
        issues.push(SyntaxIssue {
            kind: if node.is_missing() {
                format!("missing {}", node.kind())
            } else {
                node.kind().to_owned()
            },
            span: SourceSpan {
                start: node.start_byte(),
                end: node.end_byte(),
                line: point.row + 1,
                column: point.column + 1,
            },
        });
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_syntax_issues(child, issues);
    }
}

fn lower_children(
    node: Node<'_>,
    source: &str,
    language: Language,
    declarations: &mut Vec<Decl>,
    declaration_spans: &mut Vec<SourceSpan>,
) -> Result<(), ParseError> {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        let text = child
            .utf8_text(source.as_bytes())
            .map_err(|_| ParseError::InvalidDeclaration("header is not valid UTF-8".to_owned()))?;
        match child.kind() {
            "comment"
            | "preproc_include"
            | "preproc_def"
            | "preproc_function_def"
            | "preproc_call"
            | "preproc_if"
            | "preproc_ifdef" => {}
            "declaration" | "type_definition" | "alias_declaration" => {
                extend_declarations(
                    declarations,
                    declaration_spans,
                    lower_declaration(text, language)?,
                    source_span(child),
                );
            }
            "struct_specifier" | "union_specifier" | "class_specifier" | "enum_specifier" => {
                declarations.push(lower_record(text, language)?);
                declaration_spans.push(source_span(child));
            }
            "namespace_definition" => {
                // Namespace ownership is represented on lowered declaration paths/report
                // owners, not as a source-text node.  Only the declaration body is a
                // declaration; the grammar's `namespace_identifier` is metadata.
                let body = child
                    .child_by_field_name("body")
                    .or_else(|| named_child_of_kind(child, "declaration_list"))
                    .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
                lower_children(body, source, language, declarations, declaration_spans)?;
            }
            "linkage_specification" => {
                // Ignore the grammar's string literal and lower the declaration/body.
                let mut nested = child.walk();
                for declaration in child
                    .named_children(&mut nested)
                    .filter(|node| matches!(node.kind(), "declaration" | "declaration_list"))
                {
                    if declaration.kind() == "declaration_list" {
                        lower_children(
                            declaration,
                            source,
                            language,
                            declarations,
                            declaration_spans,
                        )?;
                    } else {
                        let text = declaration.utf8_text(source.as_bytes()).map_err(|_| {
                            ParseError::InvalidDeclaration("header is not valid UTF-8".to_owned())
                        })?;
                        extend_declarations(
                            declarations,
                            declaration_spans,
                            lower_declaration(text, language)?,
                            source_span(declaration),
                        );
                    }
                }
            }
            "declaration_list" => {
                lower_children(child, source, language, declarations, declaration_spans)?
            }
            "class_interface" => {
                declarations.push(lower_objc_interface(text)?);
                declaration_spans.push(source_span(child));
            }
            "protocol_declaration" | "qualified_protocol_interface_declaration" => {
                declarations.push(lower_objc_protocol(text)?);
                declaration_spans.push(source_span(child));
            }
            "class_forward_declaration" | "class_declaration" => {
                declarations.push(lower_objc_forward(text, ObjectiveCForwardKind::Class)?);
                declaration_spans.push(source_span(child));
            }
            "protocol_forward_declaration" | "protocol_forward_declaration_list" => {
                declarations.push(lower_objc_forward(text, ObjectiveCForwardKind::Protocol)?);
                declaration_spans.push(source_span(child));
            }
            // Empty declarations and compiler pragmas carry no recoverable declaration.
            ";" | "preproc_directive" => {}
            kind => {
                return Err(ParseError::Unsupported {
                    kind: kind.to_owned(),
                    span_start: child.start_byte(),
                });
            }
        }
    }
    Ok(())
}

fn extend_declarations(
    declarations: &mut Vec<Decl>,
    spans: &mut Vec<SourceSpan>,
    lowered: Vec<Decl>,
    span: SourceSpan,
) {
    spans.extend(std::iter::repeat_n(span, lowered.len()));
    declarations.extend(lowered);
}

fn source_span(node: Node<'_>) -> SourceSpan {
    let point = node.start_position();
    SourceSpan {
        start: node.start_byte(),
        end: node.end_byte(),
        line: point.row + 1,
        column: point.column + 1,
    }
}

fn named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn lower_objc_interface(text: &str) -> Result<Decl, ParseError> {
    let header = text
        .lines()
        .next()
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?
        .trim()
        .trim_start_matches("@interface")
        .trim();
    let head = header.split('{').next().unwrap_or(header).trim();
    let (before_protocols, protocols) = parse_objc_protocols(head)?;
    if let Some(open) = before_protocols.find('(') {
        let close = before_protocols[open + 1..]
            .find(')')
            .map(|offset| open + 1 + offset)
            .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
        let extended_class = parse_identifier(before_protocols[..open].trim())?;
        let name = parse_identifier(before_protocols[open + 1..close].trim())?;
        let (methods, properties) = parse_objc_members(text)?;
        return Ok(Decl::ObjectiveCCategory {
            name,
            extended_class,
            protocols,
            methods,
            properties,
        });
    }
    let (name, superclass) = if let Some((name, superclass)) = before_protocols.split_once(':') {
        (
            parse_identifier(name.trim())?,
            Some(parse_identifier(superclass.trim())?),
        )
    } else {
        (parse_identifier(before_protocols.trim())?, None)
    };
    let (methods, properties) = parse_objc_members(text)?;
    Ok(Decl::ObjectiveCInterface {
        name,
        superclass,
        protocols,
        ivars: parse_objc_ivars(text)?,
        methods,
        properties,
    })
}

fn lower_objc_protocol(text: &str) -> Result<Decl, ParseError> {
    let header = text
        .lines()
        .next()
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?
        .trim()
        .trim_start_matches("@protocol")
        .trim();
    let (name, protocols) = parse_objc_protocols(header)?;
    let (methods, properties) = parse_objc_members(text)?;
    Ok(Decl::ObjectiveCProtocol {
        name: parse_identifier(name.trim())?,
        protocols,
        methods,
        properties,
    })
}

fn lower_objc_forward(text: &str, kind: ObjectiveCForwardKind) -> Result<Decl, ParseError> {
    let keyword = match kind {
        ObjectiveCForwardKind::Class => "@class",
        ObjectiveCForwardKind::Protocol => "@protocol",
    };
    let names = text
        .trim()
        .trim_start_matches(keyword)
        .trim_end_matches(';')
        .split(',')
        .map(str::trim)
        .map(parse_identifier)
        .collect::<Result<Vec<_>, _>>()?;
    if names.is_empty() {
        return Err(ParseError::InvalidDeclaration(text.to_owned()));
    }
    Ok(Decl::ObjectiveCForward { kind, names })
}

fn parse_objc_protocols(text: &str) -> Result<(&str, Vec<Identifier>), ParseError> {
    let Some(open) = text.find('<') else {
        return Ok((text, Vec::new()));
    };
    let close = text[open + 1..]
        .find('>')
        .map(|offset| open + 1 + offset)
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let protocols = text[open + 1..close]
        .split(',')
        .map(str::trim)
        .map(parse_identifier)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((text[..open].trim(), protocols))
}

fn parse_objc_members(
    text: &str,
) -> Result<(Vec<ObjectiveCMethod>, Vec<crate::ObjectiveCProperty>), ParseError> {
    let mut without_ivars = text.to_owned();
    if let Some(open) = without_ivars.find('{')
        && let Some(close) = matching_delimiter(&without_ivars, open, '{', '}')
    {
        without_ivars.replace_range(open..=close, "");
    }
    let mut body = without_ivars.lines().skip(1).collect::<Vec<_>>().join("\n");
    body = body.replace("@end", "");
    let mut required = None;
    let mut methods = Vec::new();
    let mut properties = Vec::new();
    for raw in split_top_level(&body, ';') {
        let mut value = raw.trim();
        for (directive, state) in [("@required", Some(true)), ("@optional", Some(false))] {
            if let Some(rest) = value.strip_prefix(directive) {
                required = state;
                value = rest.trim();
            }
        }
        if value.starts_with('-') || value.starts_with('+') {
            let mut method = parse_objc_method(value)?;
            method.required = required;
            methods.push(method);
        } else if value.starts_with("@property") {
            properties.push(parse_objc_property(value)?);
        }
    }
    Ok((methods, properties))
}

fn parse_objc_ivars(text: &str) -> Result<Vec<crate::ObjectiveCIvar>, ParseError> {
    let Some(open) = text.find('{') else {
        return Ok(Vec::new());
    };
    let close = matching_delimiter(text, open, '{', '}')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let mut access = crate::ObjectiveCAccess::Protected;
    let mut ivars = Vec::new();
    for raw in split_top_level(&text[open + 1..close], ';') {
        let mut value = raw.trim();
        for (directive, next) in [
            ("@public", crate::ObjectiveCAccess::Public),
            ("@protected", crate::ObjectiveCAccess::Protected),
            ("@private", crate::ObjectiveCAccess::Private),
            ("@package", crate::ObjectiveCAccess::Package),
        ] {
            if let Some(rest) = value.strip_prefix(directive) {
                access = next;
                value = rest.trim();
            }
        }
        if value.is_empty() {
            continue;
        }
        let (ty, name) = split_type_and_name(value)?;
        ivars.push(crate::ObjectiveCIvar {
            name: parse_identifier(name.trim_start_matches('*').trim())?,
            ty: parse_type(ty, Language::ObjectiveC)?,
            access,
        });
    }
    Ok(ivars)
}

fn parse_objc_property(text: &str) -> Result<crate::ObjectiveCProperty, ParseError> {
    let mut value = text.trim_start_matches("@property").trim();
    let mut attributes = Vec::new();
    if value.starts_with('(') {
        let close = matching_delimiter(value, 0, '(', ')')
            .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
        attributes = value[1..close]
            .split(',')
            .map(str::trim)
            .map(parse_objc_property_attribute)
            .collect::<Result<Vec<_>, _>>()?;
        value = value[close + 1..].trim();
    }
    let (ty, name) = split_type_and_name(value)?;
    Ok(crate::ObjectiveCProperty {
        name: parse_identifier(name.trim_start_matches('*').trim())?,
        ty: parse_type(ty, Language::ObjectiveC)?,
        attributes,
    })
}

fn parse_objc_property_attribute(
    value: &str,
) -> Result<crate::ObjectiveCPropertyAttribute, ParseError> {
    use crate::ObjectiveCPropertyAttribute as Attribute;
    match value {
        "readonly" => Ok(Attribute::Readonly),
        "readwrite" => Ok(Attribute::Readwrite),
        "copy" => Ok(Attribute::Copy),
        "retain" => Ok(Attribute::Retain),
        "strong" => Ok(Attribute::Strong),
        "weak" => Ok(Attribute::Weak),
        "assign" => Ok(Attribute::Assign),
        "atomic" => Ok(Attribute::Atomic),
        "nonatomic" => Ok(Attribute::Nonatomic),
        "dynamic" => Ok(Attribute::Dynamic),
        "class" => Ok(Attribute::Class),
        _ => Err(ParseError::InvalidDeclaration(format!(
            "unknown Objective-C property attribute `{value}`"
        ))),
    }
}

fn parse_objc_method(text: &str) -> Result<ObjectiveCMethod, ParseError> {
    let kind = if text.starts_with('+') {
        MethodKind::Class
    } else {
        MethodKind::Instance
    };
    let rest = text[1..].trim();
    let return_open = rest
        .find('(')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let return_close = matching_delimiter(rest, return_open, '(', ')')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let return_type = parse_type(&rest[return_open + 1..return_close], Language::ObjectiveC)?;
    let tail = rest[return_close + 1..].trim();
    if !tail.contains(':') {
        return Ok(ObjectiveCMethod {
            kind,
            selector: tail.to_owned(),
            return_type,
            parameters: Vec::new(),
            required: None,
        });
    }
    let mut selector = String::new();
    let mut parameters = Vec::new();
    let mut remaining = tail;
    let mut index = 0usize;
    while let Some(colon) = remaining.find(':') {
        let piece = remaining[..colon]
            .split_whitespace()
            .last()
            .unwrap_or_default();
        selector.push_str(piece);
        selector.push(':');
        remaining = remaining[colon + 1..].trim_start();
        let open = remaining
            .find('(')
            .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
        let close = matching_delimiter(remaining, open, '(', ')')
            .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
        let ty = parse_type(&remaining[open + 1..close], Language::ObjectiveC)?;
        remaining = remaining[close + 1..].trim_start();
        let end = remaining
            .find(char::is_whitespace)
            .unwrap_or(remaining.len());
        let candidate = &remaining[..end];
        let name = Identifier::new(candidate).unwrap_or_else(|| {
            Identifier::new(format!("arg{index}")).expect("generated identifier is valid")
        });
        index += 1;
        parameters.push(Parameter { name, ty });
        remaining = remaining[end..].trim_start();
    }
    Ok(ObjectiveCMethod {
        kind,
        selector,
        return_type,
        parameters,
        required: None,
    })
}

pub(super) fn parse_parameters(
    text: &str,
    language: Language,
) -> Result<(Vec<Parameter>, bool, ParameterState), ParseError> {
    let text = text.trim();
    if text.is_empty() {
        return Ok((Vec::new(), false, ParameterState::Unspecified));
    }
    if text == "void" {
        return Ok((Vec::new(), false, ParameterState::Known));
    }
    let mut parameters = Vec::new();
    let mut variadic = false;
    for (index, parameter) in split_top_level(text, ',').into_iter().enumerate() {
        let parameter = parameter.trim();
        if parameter == "..." {
            variadic = true;
            continue;
        }
        let (ty, name) = split_type_and_name(parameter).unwrap_or((parameter, ""));
        let name = Identifier::new(name.trim_start_matches('*').trim()).unwrap_or_else(|| {
            Identifier::new(format!("arg{index}")).expect("generated identifier is valid")
        });
        parameters.push(Parameter {
            name,
            ty: parse_type(ty, language)?,
        });
    }
    Ok((parameters, variadic, ParameterState::Known))
}

pub(super) fn split_type_and_declarators(text: &str) -> Result<(&str, Vec<&str>), ParseError> {
    let parts = split_top_level(text, ',');
    let first = parts
        .first()
        .copied()
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let (ty, first_name) = split_type_and_name(first)?;
    let mut names = vec![first_name];
    names.extend(parts.into_iter().skip(1));
    Ok((ty, names))
}

pub(super) fn split_type_and_name(text: &str) -> Result<(&str, &str), ParseError> {
    let text = text.trim();
    let end = text
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
        .map(|(index, ch)| index + ch.len_utf8())
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let start = text[..end]
        .char_indices()
        .rev()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
        .last()
        .map(|(index, _)| index)
        .unwrap_or(0);
    let name = &text[start..end];
    let ty = text[..start].trim();
    if ty.is_empty() || Identifier::new(name).is_none() {
        return Err(ParseError::InvalidDeclaration(text.to_owned()));
    }
    Ok((ty, name))
}

pub(super) fn parse_identifier(text: &str) -> Result<Identifier, ParseError> {
    Identifier::new(text.trim())
        .ok_or_else(|| ParseError::InvalidDeclaration(format!("invalid identifier `{text}`")))
}

pub(super) fn parse_path(text: &str) -> Result<IdentifierPath, ParseError> {
    IdentifierPath::parse(text)
        .ok_or_else(|| ParseError::InvalidDeclaration(format!("invalid name `{text}`")))
}

pub(super) fn parse_storage(text: &str) -> StorageClass {
    if text.split_whitespace().any(|word| word == "extern") {
        StorageClass::Extern
    } else if text.split_whitespace().any(|word| word == "static") {
        StorageClass::Static
    } else if text
        .split_whitespace()
        .any(|word| matches!(word, "thread_local" | "_Thread_local" | "__thread"))
    {
        StorageClass::ThreadLocal
    } else {
        StorageClass::None
    }
}

pub(super) fn parse_function_qualifiers(text: &str) -> FunctionQualifiers {
    FunctionQualifiers {
        is_const: text.split_whitespace().any(|word| word == "const"),
        is_volatile: text.split_whitespace().any(|word| word == "volatile"),
        reference: if text.contains("&&") {
            Some(crate::ReferenceKind::Rvalue)
        } else if text.contains('&') {
            Some(crate::ReferenceKind::Lvalue)
        } else {
            None
        },
        noexcept: text.contains("noexcept").then_some(true),
    }
}

pub(super) fn linkage(language: Language) -> Linkage {
    match language {
        Language::C => Linkage::C,
        Language::Cpp => Linkage::Cpp,
        Language::ObjectiveC => Linkage::ObjectiveC,
    }
}

pub(super) fn record_tag(kind: RecordKind) -> NamedTypeTag {
    match kind {
        RecordKind::Struct => NamedTypeTag::Struct,
        RecordKind::Union => NamedTypeTag::Union,
        RecordKind::Class => NamedTypeTag::Class,
        RecordKind::Enum => NamedTypeTag::Enum,
    }
}

pub(super) fn starts_with_record(text: &str) -> bool {
    ["struct ", "union ", "class ", "enum "]
        .into_iter()
        .any(|prefix| text.starts_with(prefix))
}

pub(super) fn contains_record_body(text: &str) -> bool {
    text.contains('{')
        && ["struct", "union", "class", "enum"]
            .iter()
            .any(|kind| text.contains(kind))
}

pub(super) fn strip_attributes(mut text: &str) -> &str {
    for prefix in ["extern ", "static ", "inline ", "__inline ", "__inline__ "] {
        if let Some(rest) = text.strip_prefix(prefix) {
            text = rest.trim_start();
        }
    }
    text
}

pub(super) fn find_top_level(text: &str, needle: char) -> Option<usize> {
    let mut angles = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '<' => angles += 1,
            '>' => angles = angles.saturating_sub(1),
            _ if ch == needle && angles == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

pub(super) fn matching_delimiter(
    text: &str,
    open: usize,
    left: char,
    right: char,
) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, ch) in text[open..].char_indices() {
        if ch == left {
            depth += 1;
        } else if ch == right {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}

pub(super) fn split_top_level(text: &str, separator: char) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut round = 0usize;
    let mut angle = 0usize;
    let mut square = 0usize;
    let mut brace = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '(' => round += 1,
            ')' => round = round.saturating_sub(1),
            '<' => angle += 1,
            '>' => angle = angle.saturating_sub(1),
            '[' => square += 1,
            ']' => square = square.saturating_sub(1),
            '{' => brace += 1,
            '}' => brace = brace.saturating_sub(1),
            _ => {}
        }
        if ch == separator && round == 0 && angle == 0 && square == 0 && brace == 0 {
            result.push(&text[start..index]);
            start = index + ch.len_utf8();
        }
    }
    result.push(&text[start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_c_function_and_record() {
        let unit = TreeSitterHeaderParser
            .parse(
                Language::C,
                "struct Point { int x; int y; };\nextern int distance(struct Point *point);",
            )
            .unwrap();
        assert_eq!(unit.declarations.len(), 2);
        assert!(matches!(unit.declarations[0], Decl::Record { .. }));
        assert!(matches!(unit.declarations[1], Decl::Function { .. }));
    }

    #[test]
    fn parses_cpp_alias_and_template_type() {
        let unit = TreeSitterHeaderParser
            .parse(
                Language::Cpp,
                "using Names = std::vector<int>;\nNames names();",
            )
            .unwrap();
        assert_eq!(unit.declarations.len(), 2);
    }

    #[test]
    fn rejects_syntax_error() {
        let error = TreeSitterHeaderParser
            .parse(Language::C, "int broken(;")
            .unwrap_err();
        assert!(matches!(error, ParseError::Syntax(_)));
    }

    #[test]
    fn parses_objective_c_interface() {
        let unit = TreeSitterHeaderParser
            .parse(
                Language::ObjectiveC,
                "@interface Widget : NSObject\n- (int)value;\n@end",
            )
            .unwrap();
        assert!(matches!(
            unit.declarations.as_slice(),
            [Decl::ObjectiveCInterface { .. }]
        ));
    }
}
