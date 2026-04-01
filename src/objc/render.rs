use crate::objc::encoding::{ObjCMethodArg, ObjCPropertyAttributes, ObjCQualifiedType};
use crate::objc::types::{ObjCCategory, ObjCClass, ObjCMethod, ObjCProperty, ObjCProtocol};

/// Render a class-dump-style header for a class.
pub fn render_class_header(class: &ObjCClass) -> String {
    let mut out = String::new();

    out.push_str("@interface ");
    out.push_str(&class.name);
    if let Some(ref super_name) = class.superclass_name {
        out.push_str(" : ");
        out.push_str(super_name);
    }
    append_protocol_list(&mut out, &class.protocols);
    out.push('\n');

    if !class.ivars.is_empty() {
        out.push_str("{\n");
        for ivar in &class.ivars {
            let ty = ivar
                .parsed_type()
                .map(|ty| ty.render_named(&ivar.name))
                .unwrap_or_else(|| format!("id {}", ivar.name));
            out.push_str(&format!(
                "    {ty}; // +{off}, {sz} bytes\n",
                off = ivar.offset,
                sz = ivar.size
            ));
        }
        out.push_str("}\n");
    }

    append_property_section(&mut out, &class.properties);
    append_method_section(&mut out, &class.instance_methods, '-');
    append_method_section(&mut out, &class.class_methods, '+');

    out.push_str("@end\n");
    out
}

/// Render a class-dump-style header for a protocol.
pub fn render_protocol_header(proto: &ObjCProtocol) -> String {
    let mut out = String::new();

    out.push_str("@protocol ");
    out.push_str(&proto.name);
    append_protocol_list(&mut out, &proto.adopted_protocols);
    out.push('\n');

    append_property_section(&mut out, &proto.properties);
    append_method_section(&mut out, &proto.instance_methods, '-');
    append_method_section(&mut out, &proto.class_methods, '+');

    if !proto.optional_instance_methods.is_empty() || !proto.optional_class_methods.is_empty() {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("@optional\n");
        append_method_section(&mut out, &proto.optional_instance_methods, '-');
        append_method_section(&mut out, &proto.optional_class_methods, '+');
    }

    out.push_str("@end\n");
    out
}

/// Render a category header.
pub fn render_category_header(cat: &ObjCCategory) -> String {
    let mut out = String::new();

    out.push_str(&format!("@interface {} ({})", cat.class_name, cat.name));
    append_protocol_list(&mut out, &cat.protocols);
    out.push('\n');

    append_property_section(&mut out, &cat.properties);
    append_method_section(&mut out, &cat.instance_methods, '-');
    append_method_section(&mut out, &cat.class_methods, '+');

    out.push_str("@end\n");
    out
}

fn append_protocol_list(out: &mut String, protocols: &[String]) {
    if protocols.is_empty() {
        return;
    }
    out.push_str(" <");
    out.push_str(&protocols.join(", "));
    out.push('>');
}

fn append_property_section(out: &mut String, properties: &[ObjCProperty]) {
    if properties.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    for prop in properties {
        out.push_str(&render_property(prop));
        out.push('\n');
    }
}

fn append_method_section(out: &mut String, methods: &[ObjCMethod], prefix: char) {
    if methods.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    for method in methods {
        out.push_str(&render_method(method, prefix));
        out.push('\n');
    }
}

fn render_property(prop: &ObjCProperty) -> String {
    let attrs = prop.parsed_attributes();
    let mut attr_parts = Vec::new();
    if attrs.readonly {
        attr_parts.push("readonly".to_string());
    }
    if attrs.copy {
        attr_parts.push("copy".to_string());
    } else if attrs.strong {
        attr_parts.push("strong".to_string());
    } else if attrs.weak {
        attr_parts.push("weak".to_string());
    }
    if attrs.nonatomic {
        attr_parts.push("nonatomic".to_string());
    }
    if let Some(getter) = &attrs.getter {
        attr_parts.push(format!("getter={getter}"));
    }
    if let Some(setter) = &attrs.setter {
        attr_parts.push(format!("setter={setter}"));
    }

    let attr_prefix = if attr_parts.is_empty() {
        String::new()
    } else {
        format!("({}) ", attr_parts.join(", "))
    };

    let ty = attrs
        .ty
        .as_ref()
        .map(|ty| ty.render_named(&prop.name))
        .unwrap_or_else(|| format!("id {}", prop.name));

    let mut line = format!("@property {attr_prefix}{ty};");
    let comment = render_property_comment(&attrs);
    if !comment.is_empty() {
        line.push(' ');
        line.push_str("// ");
        line.push_str(&comment);
    }
    line
}

fn render_property_comment(attrs: &ObjCPropertyAttributes) -> String {
    let mut parts = Vec::new();
    if attrs.dynamic {
        parts.push("@dynamic".to_string());
    }
    if let Some(ivar) = &attrs.ivar {
        parts.push(format!("ivar: {ivar}"));
    }
    if let Some(old_type) = &attrs.old_type_encoding {
        parts.push(format!("legacy type: {old_type}"));
    }
    if !attrs.unknown_flags.is_empty() {
        parts.push(format!("raw attrs: {}", attrs.unknown_flags.join(",")));
    }
    parts.join(", ")
}

fn render_method(method: &ObjCMethod, prefix: char) -> String {
    let signature = method.parsed_signature();
    let return_type = signature
        .as_ref()
        .map(|sig| sig.return_type.to_string())
        .unwrap_or_else(|| "id".to_string());

    let Some(signature) = signature else {
        return format!("{prefix} ({return_type}){};", method.name);
    };

    if signature.arguments.is_empty() {
        return format!("{prefix} ({return_type}){};", method.name);
    }

    let pieces: Vec<&str> = method.name.split(':').collect();
    if pieces.len().saturating_sub(1) != signature.arguments.len() {
        let fallback_args = signature
            .arguments
            .iter()
            .enumerate()
            .map(|(idx, arg)| render_method_arg(arg, idx))
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "{prefix} ({return_type}){}; // args: {fallback_args}",
            method.name
        );
    }

    let mut out = format!("{prefix} ({return_type})");
    for (idx, arg) in signature.arguments.iter().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(pieces[idx]);
        out.push(':');
        out.push_str(&render_parenthesized_type(&arg.ty));
        out.push_str(&format!("arg{}", idx + 1));
    }
    out.push(';');
    out
}

fn render_method_arg(arg: &ObjCMethodArg, idx: usize) -> String {
    format!("{} arg{}", arg.ty, idx + 1)
}

fn render_parenthesized_type(ty: &ObjCQualifiedType) -> String {
    format!("({})", ty.render())
}

#[cfg(test)]
mod tests {
    use crate::addr::Va;
    use crate::objc::types::{
        ObjCCategory, ObjCClass, ObjCIvar, ObjCMethod, ObjCProperty, ObjCProtocol,
    };

    use super::{render_category_header, render_class_header, render_protocol_header};

    #[test]
    fn class_header_renders_typed_selectors_and_properties() {
        let header = render_class_header(&ObjCClass {
            name: "Widget".into(),
            superclass_name: Some("NSObject".into()),
            instance_methods: vec![
                ObjCMethod {
                    name: "setTitle:forState:".into(),
                    type_encoding: "v40@0:8@\"NSString\"16q24".into(),
                    imp: Va(0),
                },
                ObjCMethod {
                    name: "reload".into(),
                    type_encoding: "v16@0:8".into(),
                    imp: Va(0),
                },
            ],
            class_methods: Vec::new(),
            ivars: vec![ObjCIvar {
                name: "_title".into(),
                type_encoding: "@\"NSString\"".into(),
                offset: 8,
                size: 8,
                alignment: 3,
            }],
            properties: vec![ObjCProperty {
                name: "title".into(),
                attributes: "T@\"NSString\",&,N,GcustomTitle,SsetCustomTitle:,V_title".into(),
            }],
            protocols: vec!["NSCopying".into()],
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        });

        assert!(header.contains("@interface Widget : NSObject <NSCopying>"));
        assert!(header.contains("NSString *_title; // +8, 8 bytes"));
        assert!(header.contains(
            "@property (strong, nonatomic, getter=customTitle, setter=setCustomTitle:) NSString *title; // ivar: _title"
        ));
        assert!(header.contains("- (void)setTitle:(NSString *)arg1 forState:(long long)arg2;"));
        assert!(header.contains("- (void)reload;"));
    }

    #[test]
    fn category_header_renders_protocols_and_properties() {
        let header = render_category_header(&ObjCCategory {
            name: "Debug".into(),
            class_name: "Widget".into(),
            instance_methods: vec![ObjCMethod {
                name: "setHandler:".into(),
                type_encoding: "v24@0:8@?16".into(),
                imp: Va(0),
            }],
            class_methods: Vec::new(),
            properties: vec![ObjCProperty {
                name: "handler".into(),
                attributes: "T@?,C,N".into(),
            }],
            protocols: vec!["Inspectable".into()],
        });

        assert!(header.contains("@interface Widget (Debug) <Inspectable>"));
        assert!(header.contains("@property (copy, nonatomic) id /* block */ handler;"));
        assert!(header.contains("- (void)setHandler:(id /* block */)arg1;"));
    }

    #[test]
    fn protocol_header_renders_optional_section() {
        let header = render_protocol_header(&ObjCProtocol {
            name: "WidgetProtocol".into(),
            instance_methods: vec![ObjCMethod {
                name: "renderWithContext:".into(),
                type_encoding: "v24@0:8@\"NSString\"16".into(),
                imp: Va(0),
            }],
            class_methods: Vec::new(),
            optional_instance_methods: vec![ObjCMethod {
                name: "debugName".into(),
                type_encoding: "@16@0:8".into(),
                imp: Va(0),
            }],
            optional_class_methods: Vec::new(),
            properties: vec![ObjCProperty {
                name: "title".into(),
                attributes: "T@\"NSString\",R".into(),
            }],
            adopted_protocols: vec!["NSObject".into()],
        });

        assert!(header.contains("@protocol WidgetProtocol <NSObject>"));
        assert!(header.contains("@property (readonly) NSString *title;"));
        assert!(header.contains("- (void)renderWithContext:(NSString *)arg1;"));
        assert!(header.contains("@optional"));
        assert!(header.contains("- (id)debugName;"));
    }

    #[test]
    fn method_rendering_handles_nested_pointer_arguments() {
        let header = render_class_header(&ObjCClass {
            name: "Widget".into(),
            superclass_name: Some("NSObject".into()),
            instance_methods: vec![ObjCMethod {
                name: "renderIntoError:".into(),
                type_encoding: "v24@0:8^@\"NSError\"16".into(),
                imp: Va(0),
            }],
            class_methods: Vec::new(),
            ivars: Vec::new(),
            properties: Vec::new(),
            protocols: Vec::new(),
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        });

        assert!(header.contains("- (void)renderIntoError:(NSError **)arg1;"));
    }
}
