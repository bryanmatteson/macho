use crate::metadata::objc::error::{Error, Result};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
/// The ObjCQualifiedType type.
pub struct ObjCQualifiedType {
    /// The qualifiers field.
    pub qualifiers: Vec<TypeQualifier>,
    /// The ty field.
    pub ty: ObjCType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The ObjCType type.
#[non_exhaustive]
pub enum ObjCType {
    /// The Void variant.
    Void,
    /// The Bool variant.
    Bool,
    /// The Char variant.
    Char,
    /// The UnsignedChar variant.
    UnsignedChar,
    /// The Short variant.
    Short,
    /// The UnsignedShort variant.
    UnsignedShort,
    /// The Int variant.
    Int,
    /// The UnsignedInt variant.
    UnsignedInt,
    /// The Long variant.
    Long,
    /// The UnsignedLong variant.
    UnsignedLong,
    /// The LongLong variant.
    LongLong,
    /// The UnsignedLongLong variant.
    UnsignedLongLong,
    /// The Float variant.
    Float,
    /// The Double variant.
    Double,
    /// The CharPtr variant.
    CharPtr,
    /// The Selector variant.
    Selector,
    /// The Class variant.
    Class,
    /// The Object variant.
    Object {
        /// The item field.
        class_name: Option<String>,
        /// The item field.
        protocols: Vec<String>,
        /// The bool field.
        is_block: bool,
    },
    /// The CString variant.
    CString,
    /// The Pointer variant.
    Pointer(Box<ObjCQualifiedType>),
    /// The Array variant.
    Array {
        /// The usize field.
        len: usize,
        /// The item field.
        element: Box<ObjCQualifiedType>,
    },
    /// The Struct variant.
    Struct {
        /// The String field.
        name: String,
        /// The item field.
        fields: Vec<ObjCQualifiedType>,
    },
    /// The Union variant.
    Union {
        /// The String field.
        name: String,
        /// The item field.
        fields: Vec<ObjCQualifiedType>,
    },
    /// The BitField variant.
    BitField(usize),
    /// The Unknown variant.
    Unknown(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The TypeQualifier type.
#[non_exhaustive]
pub enum TypeQualifier {
    /// The Const variant.
    Const,
    /// The In variant.
    In,
    /// The InOut variant.
    InOut,
    /// The Out variant.
    Out,
    /// The ByCopy variant.
    ByCopy,
    /// The ByRef variant.
    ByRef,
    /// The OneWay variant.
    OneWay,
    /// The Atomic variant.
    Atomic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The ObjCMethodArg type.
pub struct ObjCMethodArg {
    /// The ty field.
    pub ty: ObjCQualifiedType,
    /// The stack_offset field.
    pub stack_offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The ObjCMethodSignature type.
pub struct ObjCMethodSignature {
    /// The return_type field.
    pub return_type: ObjCQualifiedType,
    /// The return_offset field.
    pub return_offset: Option<usize>,
    /// The self_type field.
    pub self_type: Option<ObjCMethodArg>,
    /// The cmd_type field.
    pub cmd_type: Option<ObjCMethodArg>,
    /// The arguments field.
    pub arguments: Vec<ObjCMethodArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
/// The ObjCPropertyAttributes type.
pub struct ObjCPropertyAttributes {
    /// The ty field.
    pub ty: Option<ObjCQualifiedType>,
    /// The readonly field.
    pub readonly: bool,
    /// The nonatomic field.
    pub nonatomic: bool,
    /// The dynamic field.
    pub dynamic: bool,
    /// The weak field.
    pub weak: bool,
    /// The copy field.
    pub copy: bool,
    /// The strong field.
    pub strong: bool,
    /// The getter field.
    pub getter: Option<String>,
    /// The setter field.
    pub setter: Option<String>,
    /// The ivar field.
    pub ivar: Option<String>,
    /// The old_type_encoding field.
    pub old_type_encoding: Option<String>,
    /// The unknown_flags field.
    pub unknown_flags: Vec<String>,
}

impl ObjCQualifiedType {
    /// Performs parse.
    pub fn parse(encoding: &str) -> Result<Self> {
        let mut parser = Parser::new(encoding);
        let ty = parser.parse_qualified_type()?;
        parser.skip_digits();
        parser.expect_eof()?;
        Ok(ty)
    }

    /// Performs render.
    pub fn render(&self) -> String {
        match &self.ty {
            ObjCType::Pointer(inner) => {
                let inner = inner.render();
                let pointer = if inner.ends_with('*') {
                    format!("{inner}*")
                } else {
                    format!("{inner} *")
                };
                self.qualify(pointer)
            }
            ObjCType::Array { len, element } => {
                self.qualify(format!("{}[{len}]", element.render()))
            }
            _ => self.qualify(self.ty.render_base()),
        }
    }

    /// Performs render_named.
    pub fn render_named(&self, name: &str) -> String {
        match &self.ty {
            ObjCType::BitField(bits) => self.qualify(attach_declarator(
                "unsigned int".to_string(),
                format!("{name} : {bits}"),
            )),
            ObjCType::Pointer(inner) => {
                if let ObjCType::Array { len, element } = &inner.ty {
                    return self.qualify(attach_declarator(
                        element.render(),
                        format!("(*{name})[{len}]"),
                    ));
                }

                let inner_rendered = inner.render();
                let declarator = if inner_rendered.ends_with('*') {
                    format!("*{name}")
                } else {
                    format!(" *{name}")
                };
                self.qualify(format!("{inner_rendered}{declarator}"))
            }
            ObjCType::Array { len, element } => self.qualify(attach_declarator(
                element.render(),
                format!("{name}[{len}]"),
            )),
            _ => self.qualify(attach_declarator(self.ty.render_base(), name.to_string())),
        }
    }

    fn qualify(&self, rendered: String) -> String {
        if self.qualifiers.is_empty() {
            rendered
        } else {
            format!(
                "{} {rendered}",
                self.qualifiers
                    .iter()
                    .map(|qualifier| qualifier.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

impl ObjCMethodSignature {
    /// Performs parse.
    pub fn parse(encoding: &str) -> Result<Self> {
        let mut parser = Parser::new(encoding);

        let return_type = parser.parse_qualified_type()?;
        let return_offset = parser.parse_number();
        let self_type = parser.parse_method_arg()?;
        let cmd_type = parser.parse_method_arg()?;

        let mut arguments = Vec::new();
        while !parser.is_eof() {
            let Some(arg) = parser.parse_method_arg()? else {
                break;
            };
            arguments.push(arg);
        }

        Ok(Self {
            return_type,
            return_offset,
            self_type,
            cmd_type,
            arguments,
        })
    }
}

impl ObjCPropertyAttributes {
    /// Performs parse.
    pub fn parse(attrs: &str) -> Self {
        let mut parsed = Self::default();

        for component in split_property_attribute_components(attrs) {
            if component.is_empty() {
                continue;
            }

            let mut chars = component.chars();
            let Some(flag) = chars.next() else {
                continue;
            };
            let value = chars.as_str();

            match flag {
                'T' => parsed.ty = ObjCQualifiedType::parse(value).ok(),
                'R' => parsed.readonly = true,
                'N' => parsed.nonatomic = true,
                'D' => parsed.dynamic = true,
                'W' => parsed.weak = true,
                'C' => parsed.copy = true,
                '&' => parsed.strong = true,
                'G' if !value.is_empty() => parsed.getter = Some(value.to_string()),
                'S' if !value.is_empty() => parsed.setter = Some(value.to_string()),
                'V' if !value.is_empty() => parsed.ivar = Some(value.to_string()),
                't' if !value.is_empty() => parsed.old_type_encoding = Some(value.to_string()),
                _ => parsed.unknown_flags.push(component.to_string()),
            }
        }

        parsed
    }

    /// Performs effective_type.
    pub fn effective_type(&self) -> Option<ObjCQualifiedType> {
        let legacy = self
            .old_type_encoding
            .as_deref()
            .and_then(|encoding| ObjCQualifiedType::parse(encoding).ok());

        match (&self.ty, legacy) {
            (Some(current), Some(legacy)) if current.is_less_specific_than(&legacy) => Some(legacy),
            (Some(current), _) => Some(current.clone()),
            (None, Some(legacy)) => Some(legacy),
            (None, None) => None,
        }
    }
}

impl fmt::Display for ObjCQualifiedType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render())
    }
}

impl fmt::Display for ObjCType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.render_base())
    }
}

impl TypeQualifier {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Const => "const",
            Self::In => "in",
            Self::InOut => "inout",
            Self::Out => "out",
            Self::ByCopy => "bycopy",
            Self::ByRef => "byref",
            Self::OneWay => "oneway",
            Self::Atomic => "_Atomic",
        }
    }
}

impl fmt::Display for TypeQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ObjCType {
    fn render_base(&self) -> String {
        match self {
            Self::Void => "void".to_string(),
            Self::Bool => "BOOL".to_string(),
            Self::Char => "char".to_string(),
            Self::UnsignedChar => "unsigned char".to_string(),
            Self::Short => "short".to_string(),
            Self::UnsignedShort => "unsigned short".to_string(),
            Self::Int => "int".to_string(),
            Self::UnsignedInt => "unsigned int".to_string(),
            Self::Long => "long".to_string(),
            Self::UnsignedLong => "unsigned long".to_string(),
            Self::LongLong => "long long".to_string(),
            Self::UnsignedLongLong => "unsigned long long".to_string(),
            Self::Float => "float".to_string(),
            Self::Double => "double".to_string(),
            Self::CharPtr | Self::CString => "char *".to_string(),
            Self::Selector => "SEL".to_string(),
            Self::Class => "Class".to_string(),
            Self::Object {
                class_name,
                protocols,
                is_block,
            } => {
                if *is_block {
                    "id /* block */".to_string()
                } else if let Some(name) = class_name {
                    if protocols.is_empty() {
                        format!("{name} *")
                    } else {
                        format!("{name}<{}> *", protocols.join(", "))
                    }
                } else if protocols.is_empty() {
                    "id".to_string()
                } else {
                    format!("id<{}>", protocols.join(", "))
                }
            }
            Self::Pointer(inner) => {
                let inner = inner.render();
                if inner.ends_with('*') {
                    format!("{inner}*")
                } else {
                    format!("{inner} *")
                }
            }
            Self::Array { len, element } => format!("{}[{len}]", element.render()),
            Self::Struct { name, .. } => {
                if name == "?" || name.is_empty() {
                    "struct ?".to_string()
                } else {
                    format!("struct {name}")
                }
            }
            Self::Union { name, .. } => {
                if name == "?" || name.is_empty() {
                    "union ?".to_string()
                } else {
                    format!("union {name}")
                }
            }
            Self::BitField(bits) => format!("unsigned int : {bits}"),
            Self::Unknown(code) => format!("unknown /* {code} */"),
        }
    }

    fn is_less_specific_than(&self, other: &Self) -> bool {
        match self {
            Self::Unknown(_) => !matches!(other, Self::Unknown(_)),
            Self::Object {
                class_name: None,
                protocols,
                is_block: false,
            } => match other {
                Self::Object {
                    class_name,
                    protocols: other_protocols,
                    ..
                } => class_name.is_some() || other_protocols.len() > protocols.len(),
                _ => false,
            },
            _ => false,
        }
    }
}

impl ObjCQualifiedType {
    fn is_less_specific_than(&self, other: &Self) -> bool {
        self.qualifiers == other.qualifiers && self.ty.is_less_specific_than(&other.ty)
    }
}

fn attach_declarator(base: String, declarator: String) -> String {
    if declarator.is_empty() {
        base
    } else if base.ends_with('*') {
        format!("{base}{declarator}")
    } else {
        format!("{base} {declarator}")
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn expect_eof(&self) -> Result<()> {
        if self.is_eof() {
            Ok(())
        } else {
            Err(Error::format(format!(
                "unexpected trailing ObjC encoding at byte {}: {}",
                self.pos,
                &self.input[self.pos..]
            )))
        }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn consume(&mut self, expected: char) -> Result<()> {
        match self.bump() {
            Some(ch) if ch == expected => Ok(()),
            Some(ch) => Err(Error::format(format!(
                "expected '{}' in ObjC encoding, found '{}'",
                expected, ch
            ))),
            None => Err(Error::format(format!(
                "expected '{}' in ObjC encoding, found EOF",
                expected
            ))),
        }
    }

    fn parse_method_arg(&mut self) -> Result<Option<ObjCMethodArg>> {
        if self.is_eof() {
            return Ok(None);
        }
        let ty = self.parse_qualified_type()?;
        let stack_offset = self.parse_number();
        Ok(Some(ObjCMethodArg { ty, stack_offset }))
    }

    fn parse_qualified_type(&mut self) -> Result<ObjCQualifiedType> {
        let mut qualifiers = Vec::new();
        while let Some(qualifier) = self.parse_qualifier() {
            qualifiers.push(qualifier);
        }
        let ty = self.parse_type()?;
        Ok(ObjCQualifiedType { qualifiers, ty })
    }

    fn parse_qualifier(&mut self) -> Option<TypeQualifier> {
        let qualifier = match self.peek()? {
            'r' => TypeQualifier::Const,
            'n' => TypeQualifier::In,
            'N' => TypeQualifier::InOut,
            'o' => TypeQualifier::Out,
            'O' => TypeQualifier::ByCopy,
            'R' => TypeQualifier::ByRef,
            'V' => TypeQualifier::OneWay,
            'A' => TypeQualifier::Atomic,
            _ => return None,
        };
        self.bump();
        Some(qualifier)
    }

    fn parse_type(&mut self) -> Result<ObjCType> {
        let Some(ch) = self.bump() else {
            return Err(Error::format("unexpected EOF in ObjC type encoding"));
        };

        match ch {
            'v' => Ok(ObjCType::Void),
            'B' => Ok(ObjCType::Bool),
            'c' => Ok(ObjCType::Char),
            'C' => Ok(ObjCType::UnsignedChar),
            's' => Ok(ObjCType::Short),
            'S' => Ok(ObjCType::UnsignedShort),
            'i' => Ok(ObjCType::Int),
            'I' => Ok(ObjCType::UnsignedInt),
            'l' => Ok(ObjCType::Long),
            'L' => Ok(ObjCType::UnsignedLong),
            'q' => Ok(ObjCType::LongLong),
            'Q' => Ok(ObjCType::UnsignedLongLong),
            'f' => Ok(ObjCType::Float),
            'd' => Ok(ObjCType::Double),
            '*' => Ok(ObjCType::CharPtr),
            ':' => Ok(ObjCType::Selector),
            '#' => Ok(ObjCType::Class),
            '%' => Ok(ObjCType::CString),
            '@' => self.parse_object_type(),
            '^' => Ok(ObjCType::Pointer(Box::new(self.parse_qualified_type()?))),
            '[' => self.parse_array_type(),
            '{' => self.parse_record_type('}', true),
            '(' => self.parse_record_type(')', false),
            'b' => Ok(ObjCType::BitField(self.parse_number().unwrap_or(0))),
            '?' => Ok(ObjCType::Unknown('?')),
            _ => Ok(ObjCType::Unknown(ch)),
        }
    }

    fn parse_object_type(&mut self) -> Result<ObjCType> {
        match self.peek() {
            Some('?') => {
                self.bump();
                Ok(ObjCType::Object {
                    class_name: None,
                    protocols: Vec::new(),
                    is_block: true,
                })
            }
            Some('"') => {
                self.bump();
                let quoted = self.take_until('"')?;
                self.consume('"')?;
                let (class_name, protocols) = parse_quoted_object_metadata(&quoted);
                Ok(ObjCType::Object {
                    class_name,
                    protocols,
                    is_block: false,
                })
            }
            _ => Ok(ObjCType::Object {
                class_name: None,
                protocols: Vec::new(),
                is_block: false,
            }),
        }
    }

    fn parse_array_type(&mut self) -> Result<ObjCType> {
        let len = self.parse_number().unwrap_or(0);
        let element = self.parse_qualified_type()?;
        self.consume(']')?;
        Ok(ObjCType::Array {
            len,
            element: Box::new(element),
        })
    }

    fn parse_record_type(&mut self, terminator: char, is_struct: bool) -> Result<ObjCType> {
        let name = self.take_record_name(terminator);
        let mut fields = Vec::new();

        if self.peek() == Some('=') {
            self.bump();
            while self.peek() != Some(terminator) {
                self.skip_quoted_field_name();
                fields.push(self.parse_qualified_type()?);
            }
        }

        self.consume(terminator)?;
        if is_struct {
            Ok(ObjCType::Struct { name, fields })
        } else {
            Ok(ObjCType::Union { name, fields })
        }
    }

    fn take_record_name(&mut self, terminator: char) -> String {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == '=' || ch == terminator {
                break;
            }
            self.bump();
        }
        self.input[start..self.pos].to_string()
    }

    fn skip_quoted_field_name(&mut self) {
        if self.peek() != Some('"') {
            return;
        }
        let _ = self.bump();
        while let Some(ch) = self.bump() {
            if ch == '"' {
                break;
            }
        }
    }

    fn take_until(&mut self, terminator: char) -> Result<String> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == terminator {
                return Ok(self.input[start..self.pos].to_string());
            }
            self.bump();
        }
        Err(Error::format(format!(
            "unterminated quoted ObjC encoding fragment starting at byte {}",
            start.saturating_sub(1)
        )))
    }

    fn parse_number(&mut self) -> Option<usize> {
        let start = self.pos;
        while matches!(self.peek(), Some('0'..='9')) {
            self.bump();
        }
        if self.pos == start {
            None
        } else {
            self.input[start..self.pos].parse().ok()
        }
    }

    fn skip_digits(&mut self) {
        while matches!(self.peek(), Some('0'..='9')) {
            self.bump();
        }
    }
}

fn parse_quoted_object_metadata(quoted: &str) -> (Option<String>, Vec<String>) {
    if quoted.is_empty() {
        return (None, Vec::new());
    }

    let mut class_name = String::new();
    let mut protocols = Vec::new();
    let mut rest = quoted;

    while let Some(start) = rest.find('<') {
        if class_name.is_empty() {
            class_name.push_str(rest[..start].trim());
        }
        let Some(end) = rest[start + 1..].find('>') else {
            break;
        };
        let proto = &rest[start + 1..start + 1 + end];
        for proto in proto
            .split(',')
            .map(str::trim)
            .filter(|proto| !proto.is_empty())
        {
            protocols.push(proto.to_string());
        }
        rest = &rest[start + 2 + end..];
    }

    if class_name.is_empty() {
        let trimmed = rest.trim();
        if !trimmed.is_empty() {
            class_name.push_str(trimmed);
        }
    }

    let class_name = if class_name.is_empty() || class_name == "<>" {
        None
    } else {
        Some(class_name)
    };

    (class_name, protocols)
}

fn split_property_attribute_components(attrs: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut angle_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;

    for (idx, ch) in attrs.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '<' if !in_quotes => angle_depth += 1,
            '>' if !in_quotes && angle_depth > 0 => angle_depth -= 1,
            '{' if !in_quotes => brace_depth += 1,
            '}' if !in_quotes && brace_depth > 0 => brace_depth -= 1,
            '(' if !in_quotes => paren_depth += 1,
            ')' if !in_quotes && paren_depth > 0 => paren_depth -= 1,
            '[' if !in_quotes => bracket_depth += 1,
            ']' if !in_quotes && bracket_depth > 0 => bracket_depth -= 1,
            ',' if !in_quotes
                && angle_depth == 0
                && brace_depth == 0
                && paren_depth == 0
                && bracket_depth == 0 =>
            {
                parts.push(&attrs[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }

    parts.push(&attrs[start..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::{
        ObjCMethodSignature, ObjCPropertyAttributes, ObjCQualifiedType, ObjCType, TypeQualifier,
    };

    #[test]
    fn parses_named_object_type() {
        let ty = ObjCQualifiedType::parse("@\"NSString\"").expect("parse object type");
        assert_eq!(
            ty.ty,
            ObjCType::Object {
                class_name: Some("NSString".into()),
                protocols: Vec::new(),
                is_block: false,
            }
        );
        assert_eq!(ty.to_string(), "NSString *");
    }

    #[test]
    fn parses_protocol_qualified_object_type() {
        let ty = ObjCQualifiedType::parse("@\"NSObject<NSCopying><NSSecureCoding>\"")
            .expect("parse qualified object");
        assert_eq!(ty.to_string(), "NSObject<NSCopying, NSSecureCoding> *");
    }

    #[test]
    fn parses_nested_pointer_and_struct_type() {
        let ty = ObjCQualifiedType::parse("^{CGRect={CGPoint=dd}{CGSize=dd}}")
            .expect("parse struct pointer");
        assert_eq!(ty.to_string(), "struct CGRect *");
    }

    #[test]
    fn parses_qualified_scalar_type() {
        let ty = ObjCQualifiedType::parse("ri").expect("parse qualified scalar");
        assert_eq!(ty.qualifiers, vec![TypeQualifier::Const]);
        assert_eq!(ty.to_string(), "const int");
    }

    #[test]
    fn parses_method_signature_with_offsets() {
        let sig =
            ObjCMethodSignature::parse("v24@0:8@\"NSString\"16").expect("parse method signature");
        assert_eq!(sig.return_type.to_string(), "void");
        assert_eq!(sig.return_offset, Some(24));
        assert_eq!(sig.arguments.len(), 1);
        assert_eq!(sig.arguments[0].ty.to_string(), "NSString *");
        assert_eq!(sig.arguments[0].stack_offset, Some(16));
    }

    #[test]
    fn parses_method_signature_with_block_argument() {
        let sig = ObjCMethodSignature::parse("v32@0:8@?16q24").expect("parse block signature");
        assert_eq!(sig.arguments.len(), 2);
        assert_eq!(sig.arguments[0].ty.to_string(), "id /* block */");
        assert_eq!(sig.arguments[1].ty.to_string(), "long long");
    }

    #[test]
    fn parses_property_attributes() {
        let attrs = ObjCPropertyAttributes::parse(
            "T@\"NSString\",&,N,GcustomTitle,SsetCustomTitle:,V_title",
        );
        assert_eq!(attrs.ty.expect("typed property").to_string(), "NSString *");
        assert!(attrs.strong);
        assert!(attrs.nonatomic);
        assert_eq!(attrs.getter.as_deref(), Some("customTitle"));
        assert_eq!(attrs.setter.as_deref(), Some("setCustomTitle:"));
        assert_eq!(attrs.ivar.as_deref(), Some("_title"));
    }

    #[test]
    fn parses_property_attributes_with_commas_inside_quoted_type_metadata() {
        let attrs =
            ObjCPropertyAttributes::parse("T@\"NSObject<NSCopying, NSSecureCoding>\",&,N,V_value");
        assert_eq!(
            attrs.effective_type().expect("typed property").to_string(),
            "NSObject<NSCopying, NSSecureCoding> *"
        );
        assert!(attrs.strong);
        assert!(attrs.nonatomic);
        assert_eq!(attrs.ivar.as_deref(), Some("_value"));
    }

    #[test]
    fn prefers_more_specific_legacy_property_type() {
        let attrs = ObjCPropertyAttributes {
            ty: Some(ObjCQualifiedType::parse("@").expect("parse id type")),
            old_type_encoding: Some("@\"NSString\"".into()),
            ..Default::default()
        };
        assert_eq!(
            attrs.effective_type().expect("effective type").to_string(),
            "NSString *"
        );
    }

    #[test]
    fn renders_named_nested_pointer_types_without_extra_spaces() {
        let ty = ObjCQualifiedType::parse("^^@\"NSError\"").expect("parse nested pointer");
        assert_eq!(ty.to_string(), "NSError ***");
        assert_eq!(ty.render_named("error"), "NSError ***error");
    }

    #[test]
    fn renders_pointer_to_array_declarators() {
        let ty = ObjCQualifiedType::parse("^[4i]").expect("parse pointer to array");
        assert_eq!(ty.render_named("matrix"), "int (*matrix)[4]");
    }

    #[test]
    fn renders_bitfield_declarators() {
        let ty = ObjCQualifiedType::parse("b3").expect("parse bitfield");
        assert_eq!(ty.render_named("flags"), "unsigned int flags : 3");
    }
}
