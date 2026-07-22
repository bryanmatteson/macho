use crate::{CallingConvention, Decl, Language, RecordKind, Type};

use super::{
    ParseError, contains_record_body, find_top_level, linkage, matching_delimiter,
    parse_function_qualifiers, parse_identifier, parse_parameters, parse_path, parse_storage,
    parse_type, record_tag, split_top_level, split_type_and_declarators, split_type_and_name,
    starts_with_record, strip_attributes,
};

pub(super) fn lower_declaration(text: &str, language: Language) -> Result<Vec<Decl>, ParseError> {
    let trimmed = strip_attributes(text.trim().trim_end_matches(';').trim());
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(using) = trimmed.strip_prefix("using ") {
        let (name, target) = using
            .split_once('=')
            .ok_or_else(|| ParseError::InvalidDeclaration(trimmed.to_owned()))?;
        return Ok(vec![Decl::Alias {
            path: parse_path(name)?,
            target: parse_type(target, language)?,
        }]);
    }
    if let Some(typedef) = trimmed.strip_prefix("typedef ") {
        if contains_record_body(trimmed) {
            return lower_typedef_record(trimmed, language);
        }
        let rest = typedef.trim();
        let (target, name) = split_type_and_name(rest)?;
        return Ok(vec![Decl::Alias {
            path: parse_path(name)?,
            target: parse_type(target, language)?,
        }]);
    }
    if starts_with_record(trimmed) {
        return Ok(vec![lower_record(trimmed, language)?]);
    }
    if let Some(open) = find_top_level(trimmed, '(')
        && let Some(close) = matching_delimiter(trimmed, open, '(', ')')
    {
        let prefix = trimmed[..open].trim();
        let (return_text, name_text) = split_type_and_name(prefix)?;
        let name = parse_identifier(name_text)?;
        let (parameters, variadic, parameter_state) =
            parse_parameters(&trimmed[open + 1..close], language)?;
        let signature = Type::Function {
            return_type: Box::new(parse_type(return_text, language)?),
            parameters,
            parameter_state,
            variadic,
            calling_convention: CallingConvention::C,
            qualifiers: parse_function_qualifiers(&trimmed[close + 1..]),
        };
        return Ok(vec![Decl::Function {
            name,
            signature,
            storage: parse_storage(trimmed),
            linkage: linkage(language),
        }]);
    }
    let (ty, names) = split_type_and_declarators(trimmed)?;
    let storage = parse_storage(trimmed);
    let ty = parse_type(ty, language)?;
    names
        .into_iter()
        .map(|name| {
            Ok(Decl::Variable {
                name: parse_identifier(name.trim_start_matches('*').trim())?,
                ty: ty.clone(),
                storage,
                linkage: linkage(language),
            })
        })
        .collect()
}

fn lower_typedef_record(text: &str, language: Language) -> Result<Vec<Decl>, ParseError> {
    let open = text
        .find('{')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let close = matching_delimiter(text, open, '{', '}')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let before = text[..open].trim_start_matches("typedef").trim();
    let record = lower_record(&text[text.find(before).unwrap_or(0)..=close], language)?;
    let alias = text[close + 1..].trim();
    if alias.is_empty() {
        return Ok(vec![record]);
    }
    let target_path = match &record {
        Decl::Record { path, .. } => path.clone(),
        _ => unreachable!(),
    };
    let kind = match &record {
        Decl::Record { kind, .. } => record_tag(*kind),
        _ => unreachable!(),
    };
    Ok(vec![
        record,
        Decl::Alias {
            path: parse_path(alias)?,
            target: Type::Named {
                tag: kind,
                path: target_path,
                template_arguments: Vec::new(),
            },
        },
    ])
}

pub(super) fn lower_record(text: &str, language: Language) -> Result<Decl, ParseError> {
    let text = text.trim().trim_end_matches(';').trim();
    let (kind, keyword) = if text.starts_with("struct ") {
        (RecordKind::Struct, "struct")
    } else if text.starts_with("union ") {
        (RecordKind::Union, "union")
    } else if text.starts_with("class ") {
        (RecordKind::Class, "class")
    } else if text.starts_with("enum ") {
        (RecordKind::Enum, "enum")
    } else {
        return Err(ParseError::InvalidDeclaration(text.to_owned()));
    };
    let rest = text[keyword.len()..].trim();
    let name_end = rest
        .find(|ch: char| ch.is_whitespace() || ch == '{' || ch == ':')
        .unwrap_or(rest.len());
    let path = parse_path(&rest[..name_end])?;
    let Some(open) = text.find('{') else {
        return Ok(Decl::Forward { kind, path });
    };
    let close = matching_delimiter(text, open, '{', '}')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let mut fields = Vec::new();
    let mut members = Vec::new();
    let mut access = match kind {
        RecordKind::Class => crate::Access::Private,
        _ => crate::Access::Public,
    };
    for raw_statement in split_top_level(&text[open + 1..close], ';') {
        let (next_access, statement) = strip_access_specifier(raw_statement.trim(), access);
        access = next_access;
        if statement.is_empty() {
            continue;
        }
        for declaration in lower_declaration(statement, language)? {
            match declaration {
                Decl::Variable { name, ty, .. } => fields.push(crate::Field {
                    name,
                    ty,
                    offset: None,
                    bit_width: None,
                    access,
                }),
                other => members.push(other),
            }
        }
    }
    Ok(Decl::Record {
        kind,
        path,
        bases: Vec::new(),
        fields,
        members,
    })
}

fn strip_access_specifier(text: &str, current: crate::Access) -> (crate::Access, &str) {
    for (prefix, access) in [
        ("public:", crate::Access::Public),
        ("protected:", crate::Access::Protected),
        ("private:", crate::Access::Private),
    ] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return (access, rest.trim());
        }
    }
    (current, text)
}
