use std::borrow::Cow;
use std::collections::HashMap;
use std::process::Command;

/// Cached demangler for symbol-heavy CLI output.
#[derive(Debug, Default)]
pub struct SymbolDemangler {
    enabled: bool,
    cache: HashMap<String, Option<String>>,
    swift_tool: SwiftToolState,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum SwiftToolState {
    #[default]
    Unknown,
    Available,
    Unavailable,
}

impl SymbolDemangler {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            cache: HashMap::new(),
            swift_tool: SwiftToolState::Unknown,
        }
    }

    pub fn precompute<'a>(&mut self, names: impl IntoIterator<Item = &'a str>) {
        if !self.enabled {
            return;
        }

        let mut swift_candidates = Vec::new();

        for name in names {
            if self.cache.contains_key(name) {
                continue;
            }

            if let Some(demangled) = demangle_rust_or_cpp(name) {
                self.cache.insert(name.to_owned(), Some(demangled));
                continue;
            }

            if let Some(candidate) = swift_candidate(name) {
                swift_candidates.push((name.to_owned(), candidate.to_owned()));
                continue;
            }

            self.cache.insert(name.to_owned(), None);
        }

        self.precompute_swift(&swift_candidates);
    }

    pub fn format<'a>(&mut self, name: &'a str) -> Cow<'a, str> {
        if !self.enabled {
            return Cow::Borrowed(name);
        }

        if !self.cache.contains_key(name) {
            self.precompute([name]);
        }

        match self.cache.get(name).and_then(|entry| entry.as_ref()) {
            Some(demangled) => Cow::Owned(demangled.clone()),
            None => Cow::Borrowed(name),
        }
    }

    fn precompute_swift(&mut self, names: &[(String, String)]) {
        if names.is_empty() {
            return;
        }

        if !self.swift_tool_available() {
            for (name, _) in names {
                self.cache.insert(name.clone(), None);
            }
            return;
        }

        const CHUNK_SIZE: usize = 256;

        for chunk in names.chunks(CHUNK_SIZE) {
            let mut command = Command::new("xcrun");
            command.arg("swift-demangle");
            for (_, candidate) in chunk {
                command.arg(candidate);
            }

            let output = match command.output() {
                Ok(output) if output.status.success() => output,
                _ => {
                    self.swift_tool = SwiftToolState::Unavailable;
                    for (name, _) in chunk {
                        self.cache.insert(name.clone(), None);
                    }
                    continue;
                }
            };

            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut lines = stdout.lines();

            for (name, candidate) in chunk {
                let demangled = lines
                    .next()
                    .and_then(|line| parse_swift_demangle_line(line, candidate));
                self.cache.insert(name.clone(), demangled);
            }
        }
    }

    fn swift_tool_available(&mut self) -> bool {
        match self.swift_tool {
            SwiftToolState::Available => true,
            SwiftToolState::Unavailable => false,
            SwiftToolState::Unknown => {
                let available = Command::new("xcrun")
                    .arg("swift-demangle")
                    .arg("--help")
                    .output()
                    .map(|output| output.status.success())
                    .unwrap_or(false);

                self.swift_tool = if available {
                    SwiftToolState::Available
                } else {
                    SwiftToolState::Unavailable
                };
                available
            }
        }
    }
}

/// Demangle a Rust, C++, or Swift symbol name when possible.
pub fn demangle_symbol(name: &str) -> Option<String> {
    let mut demangler = SymbolDemangler::new(true);
    demangler.precompute([name]);
    demangler.cache.remove(name).flatten()
}

/// Return either the original name or a demangled replacement.
pub fn format_symbol<'a>(name: &'a str, demangle: bool) -> Cow<'a, str> {
    if !demangle {
        return Cow::Borrowed(name);
    }

    match demangle_symbol(name) {
        Some(demangled) => Cow::Owned(demangled),
        None => Cow::Borrowed(name),
    }
}

fn demangle_rust_or_cpp(name: &str) -> Option<String> {
    for candidate in symbol_candidates(name) {
        if is_rust_v0_symbol(candidate)
            && let Ok(demangled) = rustc_demangle::try_demangle(candidate)
        {
            return Some(demangled.to_string());
        }

        if is_likely_legacy_rust_symbol(candidate)
            && let Ok(demangled) = rustc_demangle::try_demangle(candidate)
        {
            return Some(demangled.to_string());
        }

        if looks_like_cpp_symbol(candidate)
            && let Ok(symbol) = cpp_demangle::Symbol::new(candidate)
            && let Ok(demangled) = symbol.demangle()
        {
            return Some(simplify_cpp_demangled(&demangled));
        }

        if candidate.starts_with("_ZN")
            && let Ok(demangled) = rustc_demangle::try_demangle(candidate)
        {
            return Some(demangled.to_string());
        }
    }

    None
}

fn symbol_candidates(name: &str) -> impl Iterator<Item = &str> {
    [Some(name), macho_stripped_candidate(name)]
        .into_iter()
        .flatten()
}

fn macho_stripped_candidate(name: &str) -> Option<&str> {
    let stripped = name.strip_prefix('_')?;
    if is_rust_v0_symbol(stripped)
        || stripped.starts_with("_ZN")
        || looks_like_cpp_symbol(stripped)
        || looks_like_swift_symbol(stripped)
    {
        Some(stripped)
    } else {
        None
    }
}

fn is_rust_v0_symbol(name: &str) -> bool {
    name.starts_with("_R")
}

fn is_likely_legacy_rust_symbol(name: &str) -> bool {
    name.starts_with("_ZN") && has_legacy_rust_hash(name)
}

fn has_legacy_rust_hash(name: &str) -> bool {
    let bytes = name.as_bytes();
    for index in 0..bytes.len() {
        if bytes[index] != b'h' {
            continue;
        }

        let mut end = index + 1;
        while end < bytes.len() && bytes[end].is_ascii_hexdigit() {
            end += 1;
        }

        if end > index + 8 && end <= index + 17 {
            return true;
        }
    }

    false
}

fn looks_like_cpp_symbol(name: &str) -> bool {
    name.starts_with("_Z")
}

fn swift_candidate(name: &str) -> Option<&str> {
    symbol_candidates(name).find(|candidate| looks_like_swift_symbol(candidate))
}

fn looks_like_swift_symbol(name: &str) -> bool {
    name.starts_with("$s") || name.starts_with("$S") || name.starts_with("$e")
}

fn parse_swift_demangle_line(line: &str, candidate: &str) -> Option<String> {
    if let Some((_, demangled)) = line.split_once(" ---> ") {
        return Some(demangled.to_owned());
    }

    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed == candidate {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn simplify_cpp_demangled(text: &str) -> String {
    let normalized = text.replace("std::__1::", "std::");
    let simplified = simplify_cpp_fragment(&normalized);
    simplify_cpp_abi_wrapper(&simplified)
}

fn simplify_cpp_fragment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        let Some(ch) = input[index..].chars().next() else {
            break;
        };

        if is_template_name_start(ch) {
            let mut name_end = index + ch.len_utf8();
            while let Some(next) = input[name_end..].chars().next() {
                if is_template_name_char(next) {
                    name_end += next.len_utf8();
                } else {
                    break;
                }
            }

            if input[name_end..].starts_with('<')
                && let Some(template_end) = find_matching_angle(input, name_end)
            {
                let name = &input[index..name_end];
                let inner = &input[name_end + 1..template_end];
                let args: Vec<String> = split_top_level_args(inner)
                    .into_iter()
                    .map(|arg| simplify_cpp_fragment(arg.trim()))
                    .collect();
                out.push_str(&simplify_template(name, &args));
                index = template_end + 1;
                continue;
            }
        }

        out.push(ch);
        index += ch.len_utf8();
    }

    out
}

fn is_template_name_start(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == '_'
}

fn is_template_name_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':')
}

fn find_matching_angle(input: &str, open_index: usize) -> Option<usize> {
    let mut depth = 0usize;

    for (offset, ch) in input[open_index..].char_indices() {
        match ch {
            '<' => depth += 1,
            '>' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open_index + offset);
                }
            }
            _ => {}
        }
    }

    None
}

fn split_top_level_args(input: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let mut start = 0usize;
    let mut angle_depth = 0usize;
    let mut paren_depth = 0usize;

    for (index, ch) in input.char_indices() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ',' if angle_depth == 0 && paren_depth == 0 => {
                args.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }

    args.push(&input[start..]);
    args
}

fn simplify_template(name: &str, args: &[String]) -> String {
    if let Some(alias) = simplify_string_like(name, args) {
        return alias;
    }

    if let Some(alias) = simplify_stream_like(name, args) {
        return alias;
    }

    if let Some(simplified) = simplify_allocator_container(name, args) {
        return simplified;
    }

    if let Some(simplified) = simplify_set_like(name, args) {
        return simplified;
    }

    if let Some(simplified) = simplify_map_like(name, args) {
        return simplified;
    }

    format!("{name}<{}>", args.join(", "))
}

fn simplify_string_like(name: &str, args: &[String]) -> Option<String> {
    let alias_base = match name {
        "std::basic_string" => "string",
        "std::basic_string_view" => "string_view",
        _ => return None,
    };

    if args.len() != 3 && args.len() != 2 {
        return None;
    }

    let kind = char_type_prefix(args[0].as_str())?;

    let traits = format!("std::char_traits<{}>", args[0]);
    if args[1] != traits {
        return None;
    }

    if name == "std::basic_string" && args[2] != format!("std::allocator<{}>", args[0]) {
        return None;
    }

    Some(format!("std::{kind}{alias_base}"))
}

fn simplify_stream_like(name: &str, args: &[String]) -> Option<String> {
    let alias_base = match name {
        "std::basic_stringbuf" => "stringbuf",
        "std::basic_stringstream" => "stringstream",
        "std::basic_istringstream" => "istringstream",
        "std::basic_ostringstream" => "ostringstream",
        "std::basic_filebuf" => "filebuf",
        "std::basic_ifstream" => "ifstream",
        "std::basic_ofstream" => "ofstream",
        "std::basic_fstream" => "fstream",
        _ => return None,
    };

    let kind = match args.first().map(String::as_str) {
        Some("char") => "",
        Some("wchar_t") => "w",
        _ => return None,
    };

    let traits = format!("std::char_traits<{}>", args[0]);
    match name {
        "std::basic_stringbuf"
        | "std::basic_stringstream"
        | "std::basic_istringstream"
        | "std::basic_ostringstream" => {
            if args.len() != 3 || args[1] != traits {
                return None;
            }
            if args[2] != format!("std::allocator<{}>", args[0]) {
                return None;
            }
        }
        "std::basic_filebuf"
        | "std::basic_ifstream"
        | "std::basic_ofstream"
        | "std::basic_fstream" => {
            if args.len() != 2 || args[1] != traits {
                return None;
            }
        }
        _ => return None,
    }

    Some(format!("std::{kind}{alias_base}"))
}

fn char_type_prefix(arg: &str) -> Option<&'static str> {
    match arg {
        "char" => Some(""),
        "wchar_t" => Some("w"),
        "char8_t" => Some("u8"),
        "char16_t" => Some("u16"),
        "char32_t" => Some("u32"),
        _ => None,
    }
}

fn simplify_allocator_container(name: &str, args: &[String]) -> Option<String> {
    let container = match name {
        "std::vector" | "std::list" | "std::deque" | "std::forward_list" => name,
        _ => return None,
    };

    if args.len() != 2 {
        return None;
    }

    if args[1] != format!("std::allocator<{}>", args[0]) {
        return None;
    }

    Some(format!("{container}<{}>", args[0]))
}

fn simplify_set_like(name: &str, args: &[String]) -> Option<String> {
    match name {
        "std::set" | "std::multiset" => {
            if args.len() != 3 {
                return None;
            }
            if args[1] == format!("std::less<{}>", args[0])
                && args[2] == format!("std::allocator<{}>", args[0])
            {
                return Some(format!("{name}<{}>", args[0]));
            }
        }
        "std::unordered_set" | "std::unordered_multiset" => {
            if args.len() != 4 {
                return None;
            }
            if args[1] == format!("std::hash<{}>", args[0])
                && args[2] == format!("std::equal_to<{}>", args[0])
                && args[3] == format!("std::allocator<{}>", args[0])
            {
                return Some(format!("{name}<{}>", args[0]));
            }
        }
        _ => {}
    }

    None
}

fn simplify_map_like(name: &str, args: &[String]) -> Option<String> {
    match name {
        "std::map" | "std::multimap" => {
            if args.len() != 4 {
                return None;
            }
            if args[2] == format!("std::less<{}>", args[0])
                && args[3] == format!("std::allocator<std::pair<{} const, {}>>", args[0], args[1])
            {
                return Some(format!("{name}<{}, {}>", args[0], args[1]));
            }
        }
        "std::unordered_map" | "std::unordered_multimap" => {
            if args.len() != 5 {
                return None;
            }
            if args[2] == format!("std::hash<{}>", args[0])
                && args[3] == format!("std::equal_to<{}>", args[0])
                && args[4] == format!("std::allocator<std::pair<{} const, {}>>", args[0], args[1])
            {
                return Some(format!("{name}<{}, {}>", args[0], args[1]));
            }
        }
        _ => {}
    }

    None
}

fn simplify_cpp_abi_wrapper(text: &str) -> String {
    if let Some(name) = text
        .strip_prefix("{vtable(")
        .and_then(|inner| inner.strip_suffix(")}"))
    {
        return format!("vtable for {}", name.trim());
    }

    if let Some(name) = text
        .strip_prefix("{typeinfo(")
        .and_then(|inner| inner.strip_suffix(")}"))
    {
        return format!("typeinfo for {}", name.trim());
    }

    if let Some(name) = text
        .strip_prefix("{vtt(")
        .and_then(|inner| inner.strip_suffix(")}"))
    {
        return format!("vtt for {}", name.trim());
    }

    if let Some(inner) = text
        .strip_prefix("{virtual override thunk(")
        .and_then(|value| value.strip_suffix(")}"))
    {
        return simplify_virtual_override_thunk(inner);
    }

    text.trim().to_owned()
}

fn simplify_virtual_override_thunk(inner: &str) -> String {
    if let Some(rest) = inner.strip_prefix("{offset(")
        && let Some((offset, target)) = rest.split_once(")},")
    {
        return format!(
            "virtual override thunk [offset {}] {}",
            offset.trim(),
            target.trim()
        );
    }

    format!("virtual override thunk {}", inner.trim())
}

#[cfg(test)]
mod tests {
    use super::{SymbolDemangler, demangle_symbol, format_symbol, simplify_cpp_demangled};
    use std::process::Command;

    #[test]
    fn demangles_macho_cpp_symbol() {
        let demangled = demangle_symbol("__Z3foov").expect("expected C++ demangling");
        assert_eq!(demangled, "foo()");
    }

    #[test]
    fn demangles_legacy_rust_symbol() {
        let demangled =
            demangle_symbol("__ZN3foo17h05af221e174051e9E").expect("expected Rust demangling");
        assert_eq!(demangled, "foo::h05af221e174051e9");
    }

    #[test]
    fn leaves_plain_c_symbol_untouched() {
        assert!(demangle_symbol("_printf").is_none());
        assert_eq!(format_symbol("_printf", false), "_printf");
        assert_eq!(format_symbol("_printf", true), "_printf");
    }

    #[test]
    fn caches_batch_demangles_for_cpp_and_rust() {
        let mut demangler = SymbolDemangler::new(true);
        demangler.precompute(["__Z3foov", "__ZN3foo17h05af221e174051e9E"]);

        assert_eq!(demangler.format("__Z3foov"), "foo()");
        assert_eq!(
            demangler.format("__ZN3foo17h05af221e174051e9E"),
            "foo::h05af221e174051e9"
        );
    }

    #[test]
    fn demangles_swift_symbol_when_tool_is_available() {
        let available = Command::new("xcrun")
            .arg("swift-demangle")
            .arg("--help")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !available {
            return;
        }

        let mut demangler = SymbolDemangler::new(true);
        demangler.precompute(["_$sSSN"]);
        assert_eq!(demangler.format("_$sSSN"), "type metadata for Swift.String");
    }

    #[test]
    fn simplifies_libcxx_string_and_list_spellings() {
        let simplified = simplify_cpp_demangled(
            "FileMgr::GetDirInfo(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, std::__1::list<file_info, std::__1::allocator<file_info> >&, bool*)",
        );

        assert_eq!(
            simplified,
            "FileMgr::GetDirInfo(std::string&, std::list<file_info>&, bool*)"
        );
    }

    #[test]
    fn simplifies_typeinfo_stream_aliases() {
        let simplified = simplify_cpp_demangled(
            "typeinfo name for std::__1::basic_stringstream<char, std::__1::char_traits<char>, std::__1::allocator<char> >",
        );

        assert_eq!(simplified, "typeinfo name for std::stringstream");
    }

    #[test]
    fn simplifies_vtable_and_thunk_wrappers() {
        assert_eq!(
            simplify_cpp_demangled("{vtable(CWeChatMgr)}"),
            "vtable for CWeChatMgr"
        );
        assert_eq!(
            simplify_cpp_demangled(
                "{virtual override thunk({offset(-16)}, MainWindow::~MainWindow())}"
            ),
            "virtual override thunk [offset -16] MainWindow::~MainWindow()"
        );
    }
}
