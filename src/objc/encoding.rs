use crate::error::{Error, Result};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjCQualifiedType {
    pub qualifiers: Vec<TypeQualifier>,
    pub ty: ObjCType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjCType {
    Void,
    Bool,
    Char,
    UnsignedChar,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    LongLong,
    UnsignedLongLong,
    Float,
    Double,
    CharPtr,
    Selector,
    Class,
    Object {
        class_name: Option<String>,
        protocols: Vec<String>,
        is_block: bool,
    },
    CString,
    Pointer(Box<ObjCQualifiedType>),
    Array {
        len: usize,
        element: Box<ObjCQualifiedType>,
    },
    Struct {
        name: String,
        fields: Vec<ObjCQualifiedType>,
    },
    Union {
        name: String,
        fields: Vec<ObjCQualifiedType>,
    },
    BitField(usize),
    Unknown(char),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeQualifier {
    Const,
    In,
    InOut,
    Out,
    ByCopy,
    ByRef,
    OneWay,
    Atomic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjCMethodArg {
    pub ty: ObjCQualifiedType,
    pub stack_offset: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjCMethodSignature {
    pub return_type: ObjCQualifiedType,
    pub return_offset: Option<usize>,
    pub self_type: Option<ObjCMethodArg>,
    pub cmd_type: Option<ObjCMethodArg>,
    pub arguments: Vec<ObjCMethodArg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjCPropertyAttributes {
    pub ty: Option<ObjCQualifiedType>,
    pub readonly: bool,
    pub nonatomic: bool,
    pub dynamic: bool,
    pub weak: bool,
    pub copy: bool,
    pub strong: bool,
    pub getter: Option<String>,
    pub setter: Option<String>,
    pub ivar: Option<String>,
    pub old_type_encoding: Option<String>,
    pub unknown_flags: Vec<String>,
}

impl ObjCQualifiedType {
    pub fn parse(encoding: &str) -> Result<Self> {
        let mut parser = Parser::new(encoding);
        let ty = parser.parse_qualified_type()?;
        parser.skip_digits();
        parser.expect_eof()?;
        Ok(ty)
    }

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
    pub fn parse(attrs: &str) -> Self {
        let mut parsed = Self::default();

        for component in attrs.split(',') {
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
            Err(Error::Format(format!(
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
            Some(ch) => Err(Error::Format(format!(
                "expected '{}' in ObjC encoding, found '{}'",
                expected, ch
            ))),
            None => Err(Error::Format(format!(
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
            return Err(Error::Format("unexpected EOF in ObjC type encoding".into()));
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
        Err(Error::Format(format!(
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
        if !proto.is_empty() {
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
