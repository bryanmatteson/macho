use crate::{
    BuiltinType, Identifier, Language, NamedTypeTag, TemplateArgument, Type, TypeQualifiers,
};

use super::{
    ParseError, matching_delimiter, parse_identifier, parse_path, split_top_level, strip_attributes,
};

pub(crate) fn parse_type(text: &str, language: Language) -> Result<Type, ParseError> {
    let mut text = strip_attributes(text.trim());
    let qualifiers = TypeQualifiers {
        is_const: text.split_whitespace().any(|word| word == "const"),
        is_volatile: text.split_whitespace().any(|word| word == "volatile"),
        is_restrict: text
            .split_whitespace()
            .any(|word| matches!(word, "restrict" | "__restrict" | "__restrict__")),
    };
    text = text
        .trim_start_matches("const ")
        .trim_start_matches("volatile ")
        .trim();
    if let Some(base) = text.strip_suffix("&&") {
        return Ok(Type::Reference {
            target: Box::new(parse_type(base, language)?),
            kind: crate::ReferenceKind::Rvalue,
        });
    }
    if let Some(base) = text.strip_suffix('&') {
        return Ok(Type::Reference {
            target: Box::new(parse_type(base, language)?),
            kind: crate::ReferenceKind::Lvalue,
        });
    }
    // Objective-C object types are matched before the pointer suffix is
    // stripped: `NSObject<Proto> *` is one protocol-qualified object type, and
    // splitting the `*` off first would leave `NSObject<Proto>` to be parsed as
    // a template instantiation instead.
    if language == Language::ObjectiveC {
        if let Some(ty) = parse_objc_object_type(text, qualifiers)? {
            return Ok(ty);
        }
    }
    if let Some(base) = text.strip_suffix('*') {
        return Ok(Type::Pointer {
            pointee: Box::new(parse_type(base, language)?),
            qualifiers,
        });
    }
    if let Some(builtin) = builtin_type(text) {
        return Ok(Type::Builtin(builtin));
    }
    let (tag, named) = if let Some(value) = text.strip_prefix("struct ") {
        (NamedTypeTag::Struct, value)
    } else if let Some(value) = text.strip_prefix("union ") {
        (NamedTypeTag::Union, value)
    } else if let Some(value) = text.strip_prefix("enum ") {
        (NamedTypeTag::Enum, value)
    } else if let Some(value) = text.strip_prefix("class ") {
        (NamedTypeTag::Class, value)
    } else {
        (NamedTypeTag::Typedef, text)
    };
    let (path_text, template_arguments) = parse_template_arguments(named, language)?;
    Ok(Type::Named {
        tag,
        path: parse_path(path_text)?,
        template_arguments,
    })
}

fn parse_objc_object_type(
    text: &str,
    qualifiers: TypeQualifiers,
) -> Result<Option<Type>, ParseError> {
    if text == "id" {
        return Ok(Some(Type::ObjectiveCObject {
            name: None,
            protocols: Vec::new(),
            qualifiers,
        }));
    }

    let Some(base) = text.strip_suffix('*').map(str::trim) else {
        let Some(open) = text.find('<') else {
            return Ok(None);
        };
        let close = matching_delimiter(text, open, '<', '>')
            .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
        if text[..open].trim() != "id" || !text[close + 1..].trim().is_empty() {
            return Ok(None);
        }
        return Ok(Some(Type::ObjectiveCObject {
            name: None,
            protocols: parse_objc_protocol_list(&text[open + 1..close])?,
            qualifiers,
        }));
    };
    let Some(open) = base.find('<') else {
        return Ok(None);
    };
    let close = matching_delimiter(base, open, '<', '>')
        .ok_or_else(|| ParseError::InvalidDeclaration(base.to_owned()))?;
    if !base[close + 1..].trim().is_empty() {
        return Ok(None);
    }
    let name = base[..open].trim();
    if name == "id" {
        return Ok(None);
    }
    Ok(Some(Type::ObjectiveCObject {
        name: Some(parse_identifier(name)?),
        protocols: parse_objc_protocol_list(&base[open + 1..close])?,
        qualifiers,
    }))
}

fn parse_objc_protocol_list(text: &str) -> Result<Vec<Identifier>, ParseError> {
    text.split(',')
        .map(str::trim)
        .map(parse_identifier)
        .collect()
}

fn parse_template_arguments(
    text: &str,
    language: Language,
) -> Result<(&str, Vec<TemplateArgument>), ParseError> {
    let Some(open) = text.find('<') else {
        return Ok((text.trim(), Vec::new()));
    };
    let close = matching_delimiter(text, open, '<', '>')
        .ok_or_else(|| ParseError::InvalidDeclaration(text.to_owned()))?;
    let mut arguments = Vec::new();
    for value in split_top_level(&text[open + 1..close], ',') {
        let value = value.trim();
        if let Ok(integer) = value.parse::<i64>() {
            arguments.push(TemplateArgument::Integer(integer));
        } else if let Ok(ty) = parse_type(value, language) {
            arguments.push(TemplateArgument::Type(ty));
        } else {
            arguments.push(TemplateArgument::Identifier(parse_path(value)?));
        }
    }
    Ok((text[..open].trim(), arguments))
}

fn builtin_type(text: &str) -> Option<BuiltinType> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(match normalized.as_str() {
        "void" => BuiltinType::Void,
        "bool" | "_Bool" => BuiltinType::Bool,
        "char" => BuiltinType::Char,
        "signed char" => BuiltinType::SignedChar,
        "unsigned char" => BuiltinType::UnsignedChar,
        "short" | "short int" | "signed short" | "signed short int" => BuiltinType::Short,
        "unsigned short" | "unsigned short int" => BuiltinType::UnsignedShort,
        "int" | "signed" | "signed int" => BuiltinType::Int,
        "unsigned" | "unsigned int" => BuiltinType::UnsignedInt,
        "long" | "long int" | "signed long" | "signed long int" => BuiltinType::Long,
        "unsigned long" | "unsigned long int" => BuiltinType::UnsignedLong,
        "long long" | "long long int" | "signed long long" | "signed long long int" => {
            BuiltinType::LongLong
        }
        "unsigned long long" | "unsigned long long int" => BuiltinType::UnsignedLongLong,
        "__int128" | "signed __int128" => BuiltinType::Int128,
        "unsigned __int128" => BuiltinType::UnsignedInt128,
        "float" => BuiltinType::Float,
        "double" => BuiltinType::Double,
        "long double" => BuiltinType::LongDouble,
        _ => return None,
    })
}
