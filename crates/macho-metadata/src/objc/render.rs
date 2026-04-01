use crate::metadata::objc::encoding::{ObjCMethodArg, ObjCQualifiedType};
use crate::metadata::objc::types::{
    ObjCCategory, ObjCClass, ObjCMethod, ObjCProperty, ObjCProtocol,
};
use std::collections::BTreeMap;

/// Render a class-dump-style header for a class.
pub fn render_class_header(class: &ObjCClass) -> String {
    let mut out = String::new();
    let instance_accessors = property_accessor_map(&class.properties, false);
    let class_accessors = property_accessor_map(&class.properties, true);

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
    append_method_section(
        &mut out,
        &class.instance_methods,
        '-',
        Some(&instance_accessors),
    );
    append_method_section(&mut out, &class.class_methods, '+', Some(&class_accessors));

    out.push_str("@end\n");
    out
}

/// Render a class-dump-style header for a protocol.
pub fn render_protocol_header(proto: &ObjCProtocol) -> String {
    let mut out = String::new();
    let instance_accessors = property_accessor_map(&proto.properties, false);
    let class_accessors = property_accessor_map(&proto.properties, true);

    out.push_str("@protocol ");
    out.push_str(&proto.name);
    append_protocol_list(&mut out, &proto.adopted_protocols);
    out.push('\n');

    if has_required_protocol_members(proto) {
        out.push('\n');
        out.push_str("@required\n");
        append_property_section(&mut out, &proto.properties);
        append_method_section(
            &mut out,
            &proto.instance_methods,
            '-',
            Some(&instance_accessors),
        );
        append_method_section(&mut out, &proto.class_methods, '+', Some(&class_accessors));
    }

    if !proto.optional_instance_methods.is_empty() || !proto.optional_class_methods.is_empty() {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str("@optional\n");
        append_method_section(
            &mut out,
            &proto.optional_instance_methods,
            '-',
            Some(&instance_accessors),
        );
        append_method_section(
            &mut out,
            &proto.optional_class_methods,
            '+',
            Some(&class_accessors),
        );
    }

    out.push_str("@end\n");
    out
}

/// Render a category header.
pub fn render_category_header(cat: &ObjCCategory) -> String {
    let mut out = String::new();
    let instance_accessors = property_accessor_map(&cat.properties, false);
    let class_accessors = property_accessor_map(&cat.properties, true);

    out.push_str(&format!("@interface {} ({})", cat.class_name, cat.name));
    append_protocol_list(&mut out, &cat.protocols);
    out.push('\n');

    append_property_section(&mut out, &cat.properties);
    append_method_section(
        &mut out,
        &cat.instance_methods,
        '-',
        Some(&instance_accessors),
    );
    append_method_section(&mut out, &cat.class_methods, '+', Some(&class_accessors));

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

fn append_method_section(
    out: &mut String,
    methods: &[ObjCMethod],
    prefix: char,
    accessors: Option<&BTreeMap<String, PropertyAccessorKind>>,
) {
    if methods.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    for method in methods {
        out.push_str(&render_method(method, prefix, accessors));
        out.push('\n');
    }
}

fn render_property(prop: &ObjCProperty) -> String {
    let attrs = prop.parsed_attributes();
    let mut attr_parts = Vec::new();
    if prop.is_class {
        attr_parts.push("class".to_string());
    }
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
        .effective_type()
        .as_ref()
        .map(|ty| ty.render_named(&prop.name))
        .unwrap_or_else(|| format!("id {}", prop.name));

    format!("@property {attr_prefix}{ty};")
}

fn render_method(
    method: &ObjCMethod,
    prefix: char,
    accessors: Option<&BTreeMap<String, PropertyAccessorKind>>,
) -> String {
    let signature = method.parsed_signature();
    let accessor = accessors.and_then(|map| map.get(&method.name));
    let mut return_type = signature
        .as_ref()
        .map(|sig| sig.return_type.to_string())
        .unwrap_or_else(|| "id".to_string());

    let Some(signature) = signature else {
        return format!("{prefix} ({return_type}){};", method.name);
    };

    if let Some(PropertyAccessorKind::Getter(ty)) = accessor {
        return_type = ty.to_string();
    } else if matches!(accessor, Some(PropertyAccessorKind::Setter(_))) {
        return_type = "void".to_string();
    }

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
        out.push('(');
        match accessor {
            Some(PropertyAccessorKind::Setter(ty)) if idx == 0 => out.push_str(&ty.to_string()),
            _ => out.push_str(&arg.ty.to_string()),
        }
        out.push(')');
        out.push_str(&format!("arg{}", idx + 1));
    }
    out.push(';');
    out
}

fn render_method_arg(arg: &ObjCMethodArg, idx: usize) -> String {
    format!("{} arg{}", arg.ty, idx + 1)
}

fn property_accessor_map(
    properties: &[ObjCProperty],
    is_class: bool,
) -> BTreeMap<String, PropertyAccessorKind> {
    let mut map = BTreeMap::new();

    for property in properties
        .iter()
        .filter(|property| property.is_class == is_class)
    {
        let attrs = property.parsed_attributes();
        let Some(ty) = attrs.effective_type() else {
            continue;
        };

        let getter = attrs.getter.unwrap_or_else(|| property.name.clone());
        map.insert(getter, PropertyAccessorKind::Getter(ty.clone()));

        if !attrs.readonly {
            let setter = attrs
                .setter
                .unwrap_or_else(|| default_setter_name(&property.name));
            map.insert(setter, PropertyAccessorKind::Setter(ty));
        }
    }

    map
}

fn default_setter_name(property_name: &str) -> String {
    let mut chars = property_name.chars();
    let Some(first) = chars.next() else {
        return "set:".to_string();
    };
    format!("set{}{}:", first.to_ascii_uppercase(), chars.as_str())
}

fn has_required_protocol_members(proto: &ObjCProtocol) -> bool {
    !proto.properties.is_empty()
        || !proto.instance_methods.is_empty()
        || !proto.class_methods.is_empty()
}

enum PropertyAccessorKind {
    Getter(ObjCQualifiedType),
    Setter(ObjCQualifiedType),
}

#[cfg(test)]
mod tests {
    use crate::metadata::objc::types::{
        ObjCCategory, ObjCClass, ObjCIvar, ObjCMethod, ObjCProperty, ObjCProtocol,
    };
    use crate::model::addr::Va;

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
                is_class: false,
            }],
            protocols: vec!["NSCopying".into()],
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        });

        assert!(header.contains("@interface Widget : NSObject <NSCopying>"));
        assert!(header.contains("NSString *_title; // +8, 8 bytes"));
        assert!(header.contains(
            "@property (strong, nonatomic, getter=customTitle, setter=setCustomTitle:) NSString *title;"
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
                is_class: false,
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
                is_class: false,
            }],
            adopted_protocols: vec!["NSObject".into()],
        });

        assert!(header.contains("@protocol WidgetProtocol <NSObject>"));
        assert!(header.contains("@required"));
        assert!(header.contains("@property (readonly) NSString *title;"));
        assert!(header.contains("- (void)renderWithContext:(NSString *)arg1;"));
        assert!(header.contains("@optional"));
        assert!(header.contains("- (id)debugName;"));
    }

    #[test]
    fn property_accessors_render_with_property_types() {
        let header = render_class_header(&ObjCClass {
            name: "Widget".into(),
            superclass_name: Some("NSObject".into()),
            instance_methods: vec![
                ObjCMethod {
                    name: "title".into(),
                    type_encoding: "@16@0:8".into(),
                    imp: Va(0),
                },
                ObjCMethod {
                    name: "setTitle:".into(),
                    type_encoding: "v24@0:8@16".into(),
                    imp: Va(0),
                },
            ],
            class_methods: Vec::new(),
            ivars: Vec::new(),
            properties: vec![ObjCProperty {
                name: "title".into(),
                attributes: "T@\"NSString\",&,N".into(),
                is_class: false,
            }],
            protocols: Vec::new(),
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        });

        assert!(header.contains("- (NSString *)title;"));
        assert!(header.contains("- (void)setTitle:(NSString *)arg1;"));
    }

    #[test]
    fn class_property_accessors_render_with_class_property_types() {
        let header = render_class_header(&ObjCClass {
            name: "Widget".into(),
            superclass_name: Some("NSObject".into()),
            instance_methods: Vec::new(),
            class_methods: vec![
                ObjCMethod {
                    name: "sharedWidget".into(),
                    type_encoding: "@16@0:8".into(),
                    imp: Va(0),
                },
                ObjCMethod {
                    name: "setSharedWidget:".into(),
                    type_encoding: "v24@0:8@16".into(),
                    imp: Va(0),
                },
            ],
            ivars: Vec::new(),
            properties: vec![ObjCProperty {
                name: "sharedWidget".into(),
                attributes: "T@\"Widget\",&,N".into(),
                is_class: true,
            }],
            protocols: Vec::new(),
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        });

        assert!(header.contains("@property (class, strong, nonatomic) Widget *sharedWidget;"));
        assert!(header.contains("+ (Widget *)sharedWidget;"));
        assert!(header.contains("+ (void)setSharedWidget:(Widget *)arg1;"));
    }

    #[test]
    fn property_rendering_prefers_more_specific_legacy_type() {
        let header = render_class_header(&ObjCClass {
            name: "Widget".into(),
            superclass_name: Some("NSObject".into()),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            ivars: Vec::new(),
            properties: vec![ObjCProperty {
                name: "title".into(),
                attributes: "T@,t@\"NSString\",&,N".into(),
                is_class: false,
            }],
            protocols: Vec::new(),
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        });

        assert!(header.contains("@property (strong, nonatomic) NSString *title;"));
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
