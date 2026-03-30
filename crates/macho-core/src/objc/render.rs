use crate::objc::types::{ObjCCategory, ObjCClass, ObjCProtocol};

/// Render a class-dump-style header for a class.
pub fn render_class_header(class: &ObjCClass) -> String {
    let mut out = String::new();

    out.push_str("@interface ");
    out.push_str(&class.name);
    if let Some(ref super_name) = class.superclass_name {
        out.push_str(" : ");
        out.push_str(super_name);
    }
    if !class.protocols.is_empty() {
        out.push_str(" <");
        out.push_str(&class.protocols.join(", "));
        out.push('>');
    }
    out.push('\n');

    if !class.ivars.is_empty() {
        out.push_str("{\n");
        for ivar in &class.ivars {
            let ty = decode_type(&ivar.type_encoding);
            out.push_str(&format!(
                "    {ty} {name}; // +{off}, {sz} bytes\n",
                name = ivar.name,
                off = ivar.offset,
                sz = ivar.size
            ));
        }
        out.push_str("}\n");
    }

    out.push('\n');

    for prop in &class.properties {
        let (ty, attrs) = format_property(&prop.attributes);
        out.push_str(&format!("@property {attrs}{ty}{name};\n", name = prop.name));
    }
    if !class.properties.is_empty() {
        out.push('\n');
    }

    for method in &class.instance_methods {
        let ret = decode_return_type(&method.type_encoding);
        out.push_str(&format!("- ({ret}) {};\n", method.name));
    }

    for method in &class.class_methods {
        let ret = decode_return_type(&method.type_encoding);
        out.push_str(&format!("+ ({ret}) {};\n", method.name));
    }

    out.push_str("@end\n");
    out
}

/// Render a class-dump-style header for a protocol.
pub fn render_protocol_header(proto: &ObjCProtocol) -> String {
    let mut out = String::new();

    out.push_str("@protocol ");
    out.push_str(&proto.name);
    if !proto.adopted_protocols.is_empty() {
        out.push_str(" <");
        out.push_str(&proto.adopted_protocols.join(", "));
        out.push('>');
    }
    out.push('\n');

    for prop in &proto.properties {
        let (ty, attrs) = format_property(&prop.attributes);
        out.push_str(&format!("@property {attrs}{ty}{name};\n", name = prop.name));
    }

    if !proto.instance_methods.is_empty() {
        for method in &proto.instance_methods {
            let ret = decode_return_type(&method.type_encoding);
            out.push_str(&format!("- ({ret}) {};\n", method.name));
        }
    }

    if !proto.class_methods.is_empty() {
        for method in &proto.class_methods {
            let ret = decode_return_type(&method.type_encoding);
            out.push_str(&format!("+ ({ret}) {};\n", method.name));
        }
    }

    if !proto.optional_instance_methods.is_empty() || !proto.optional_class_methods.is_empty() {
        out.push_str("@optional\n");
        for method in &proto.optional_instance_methods {
            let ret = decode_return_type(&method.type_encoding);
            out.push_str(&format!("- ({ret}) {};\n", method.name));
        }
        for method in &proto.optional_class_methods {
            let ret = decode_return_type(&method.type_encoding);
            out.push_str(&format!("+ ({ret}) {};\n", method.name));
        }
    }

    out.push_str("@end\n");
    out
}

/// Render a category header.
pub fn render_category_header(cat: &ObjCCategory) -> String {
    let mut out = String::new();

    out.push_str(&format!("@interface {} ({})\n", cat.class_name, cat.name));

    for method in &cat.instance_methods {
        let ret = decode_return_type(&method.type_encoding);
        out.push_str(&format!("- ({ret}) {};\n", method.name));
    }
    for method in &cat.class_methods {
        let ret = decode_return_type(&method.type_encoding);
        out.push_str(&format!("+ ({ret}) {};\n", method.name));
    }

    out.push_str("@end\n");
    out
}

/// Decode a full ObjC type encoding to a human-readable type string.
fn decode_type(encoding: &str) -> String {
    if encoding.is_empty() {
        return "id".to_string();
    }
    let bytes = encoding.as_bytes();
    let mut i = 0;

    // Skip qualifiers
    while i < bytes.len() && matches!(bytes[i], b'r' | b'n' | b'N' | b'o' | b'O' | b'R' | b'V') {
        i += 1;
    }
    if i >= bytes.len() {
        return "id".to_string();
    }

    match bytes[i] {
        b'v' => "void".to_string(),
        b'@' => {
            // Check for @"ClassName"
            if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                let start = i + 2;
                if let Some(end) = encoding[start..].find('"') {
                    return format!("{} *", &encoding[start..start + end]);
                }
            }
            "id".to_string()
        }
        b'#' => "Class".to_string(),
        b':' => "SEL".to_string(),
        b'c' => "char".to_string(),
        b'C' => "unsigned char".to_string(),
        b'i' => "int".to_string(),
        b'I' => "unsigned int".to_string(),
        b's' => "short".to_string(),
        b'S' => "unsigned short".to_string(),
        b'l' => "long".to_string(),
        b'L' => "unsigned long".to_string(),
        b'q' => "long long".to_string(),
        b'Q' => "unsigned long long".to_string(),
        b'f' => "float".to_string(),
        b'd' => "double".to_string(),
        b'B' => "BOOL".to_string(),
        b'*' => "char *".to_string(),
        b'^' => {
            let inner = if i + 1 < bytes.len() {
                decode_type(&encoding[i + 1..])
            } else {
                "void".to_string()
            };
            format!("{inner} *")
        }
        b'{' => {
            // Struct: {Name=fields}
            if let Some(eq) = encoding[i..].find('=') {
                let name = &encoding[i + 1..i + eq];
                format!("struct {name}")
            } else if let Some(close) = encoding[i..].find('}') {
                let name = &encoding[i + 1..i + close];
                format!("struct {name}")
            } else {
                "struct ?".to_string()
            }
        }
        _ => "id".to_string(),
    }
}

/// Extract just the return type from a method type encoding.
fn decode_return_type(type_encoding: &str) -> String {
    if type_encoding.is_empty() {
        return "void".to_string();
    }
    decode_type(type_encoding)
}

/// Parse property attributes and return (type_string, attribute_string).
fn format_property(attrs: &str) -> (String, String) {
    if attrs.is_empty() {
        return ("id ".to_string(), String::new());
    }

    let mut prop_type = "id".to_string();
    let mut parts = Vec::new();

    for component in attrs.split(',') {
        if component.is_empty() {
            continue;
        }
        match component.as_bytes()[0] {
            b'T' => {
                let type_enc = &component[1..];
                prop_type = decode_type(type_enc);
            }
            b'N' => parts.push("nonatomic"),
            b'R' => parts.push("readonly"),
            b'C' => parts.push("copy"),
            b'&' => parts.push("retain"),
            b'W' => parts.push("weak"),
            b'D' => parts.push("dynamic"),
            _ => {}
        }
    }

    let attrs_str = if parts.is_empty() {
        String::new()
    } else {
        format!("({}) ", parts.join(", "))
    };

    (format!("{prop_type} "), attrs_str)
}
