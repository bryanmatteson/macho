//! Objective-C header presentation profile.
//!
//! Termosaic owns semantic tokens and theme resolution, not a language
//! parser. This profile maps the generated, already-validated Objective-C
//! header source to those tokens at the CLI presentation boundary. It is not
//! involved in header recovery or validation: ANSI escapes never enter the
//! source artifact.

use termosaic::{Span, TokenId, tokens};

use super::Style;

const KEYWORDS: &[&str] = &[
    "@autoreleasepool",
    "@class",
    "@dynamic",
    "@end",
    "@implementation",
    "@interface",
    "@optional",
    "@private",
    "@property",
    "@protected",
    "@protocol",
    "@public",
    "@required",
    "@selector",
    "@synthesize",
    "atomic",
    "assign",
    "class",
    "const",
    "copy",
    "nonatomic",
    "nullable",
    "null_resettable",
    "null_unspecified",
    "readonly",
    "readwrite",
    "retain",
    "strong",
    "weak",
];

const BUILTIN_TYPES: &[&str] = &[
    "BOOL",
    "Class",
    "CGFloat",
    "NSInteger",
    "NSUInteger",
    "SEL",
    "char",
    "double",
    "float",
    "id",
    "int",
    "long",
    "short",
    "signed",
    "unsigned",
    "void",
    "bool",
    "Boolean",
    "NSObject",
    "NSString",
    "NSNumber",
    "NSArray",
    "NSDictionary",
    "NSData",
    "NSDate",
];

/// Render validated Objective-C header source through the Termosaic profile.
///
/// The profile preserves every source byte.  In particular, line endings are
/// emitted outside spans because Termosaic correctly sanitizes control
/// characters in human text.  With color disabled this returns `source`
/// directly, keeping redirects and `--color never` suitable for class-dump
/// consumers.
pub fn render_header(style: Style, source: &str) -> String {
    if !style.enabled() {
        return source.to_owned();
    }

    let mut output = String::with_capacity(source.len());
    let mut in_block_comment = false;
    for line in source.split_inclusive('\n') {
        let (line, newline) = line
            .strip_suffix('\n')
            .map_or((line, ""), |line| (line, "\n"));
        let (line, carriage_return) = line
            .strip_suffix('\r')
            .map_or((line, ""), |line| (line, "\r"));
        output.push_str(&style.render_spans(&line_spans(line, &mut in_block_comment)));
        output.push_str(carriage_return);
        output.push_str(newline);
    }
    output
}

/// Tokenize one physical header line without consuming its line ending.
fn line_spans(line: &str, in_block_comment: &mut bool) -> Vec<Span> {
    let mut spans = Vec::new();
    let mut index = 0;
    while index < line.len() {
        let rest = &line[index..];
        let (token, run, block_state) = if *in_block_comment {
            match rest.find("*/") {
                Some(end) => (tokens::SYNTAX_COMMENT, &rest[..end + 2], Some(false)),
                None => (tokens::SYNTAX_COMMENT, rest, Some(true)),
            }
        } else if rest.starts_with("//") {
            (tokens::SYNTAX_COMMENT, rest, None)
        } else if rest.starts_with("/*") {
            match rest.find("*/") {
                Some(end) => (tokens::SYNTAX_COMMENT, &rest[..end + 2], Some(false)),
                None => (tokens::SYNTAX_COMMENT, rest, Some(true)),
            }
        } else {
            let byte = rest.as_bytes()[0];
            if byte.is_ascii_whitespace() {
                (
                    tokens::TEXT,
                    take_while(rest, |character| character.is_ascii_whitespace()),
                    None,
                )
            } else if matches!(byte, b'\'' | b'\"') {
                (tokens::SYNTAX_STRING, string_literal(rest), None)
            } else if byte.is_ascii_digit() {
                (
                    tokens::SYNTAX_NUMBER,
                    take_while(rest, is_number_continue),
                    None,
                )
            } else if is_word_start(byte) {
                let word = take_while(rest, |character| is_word_continue(character as u8));
                (classify_word(word), word, None)
            } else {
                (
                    tokens::SYNTAX_PUNCTUATION,
                    take_while(rest, |character| {
                        !character.is_ascii_whitespace()
                            && !character.is_ascii_digit()
                            && !is_word_start(character as u8)
                            && !matches!(character, '\'' | '\"')
                    }),
                    None,
                )
            }
        };
        spans.push(Span::new(token, run));
        index += run.len();
        if let Some(block_state) = block_state {
            *in_block_comment = block_state;
        }
    }
    spans
}

fn classify_word(word: &str) -> TokenId {
    if KEYWORDS.contains(&word) {
        tokens::SYNTAX_KEYWORD
    } else if BUILTIN_TYPES.contains(&word) {
        tokens::SYNTAX_TYPE_BUILTIN
    } else {
        tokens::TEXT
    }
}

fn string_literal(text: &str) -> &str {
    let quote = text.as_bytes()[0];
    let mut escaped = false;
    for (offset, byte) in text.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == quote {
            return &text[..offset + 1];
        }
    }
    text
}

fn take_while(text: &str, predicate: impl Fn(char) -> bool) -> &str {
    let end = text
        .char_indices()
        .find(|(_, character)| !predicate(*character))
        .map_or(text.len(), |(offset, _)| offset);
    &text[..end]
}

const fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'@')
}

const fn is_word_continue(byte: u8) -> bool {
    is_word_start(byte) || byte.is_ascii_digit()
}

fn is_number_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span_text(spans: &[Span]) -> String {
        spans
            .iter()
            .map(|span| span.text.as_str())
            .collect::<String>()
    }

    fn token_for(spans: &[Span], text: &str) -> TokenId {
        spans
            .iter()
            .find(|span| span.text.as_str() == text)
            .unwrap_or_else(|| panic!("missing {text:?}"))
            .token
            .clone()
    }

    #[test]
    fn profile_classifies_objc_declarations_without_changing_source() {
        let line = "@property (readonly, strong) NSString * name; // recovered";
        let mut in_block_comment = false;
        let spans = line_spans(line, &mut in_block_comment);
        assert_eq!(span_text(&spans), line);
        assert_eq!(token_for(&spans, "@property"), tokens::SYNTAX_KEYWORD);
        assert_eq!(token_for(&spans, "readonly"), tokens::SYNTAX_KEYWORD);
        assert_eq!(token_for(&spans, "NSString"), tokens::SYNTAX_TYPE_BUILTIN);
        assert_eq!(token_for(&spans, "// recovered"), tokens::SYNTAX_COMMENT);
    }

    #[test]
    fn profile_carries_block_comments_across_lines() {
        let mut in_block_comment = false;
        let first = line_spans("/* unresolved", &mut in_block_comment);
        assert!(in_block_comment);
        assert_eq!(token_for(&first, "/* unresolved"), tokens::SYNTAX_COMMENT);
        let second = line_spans(" evidence */ @end", &mut in_block_comment);
        assert!(!in_block_comment);
        assert_eq!(token_for(&second, " evidence */"), tokens::SYNTAX_COMMENT);
        assert_eq!(token_for(&second, "@end"), tokens::SYNTAX_KEYWORD);
    }

    #[test]
    fn rendering_preserves_source_when_color_is_disabled_or_stripped() {
        let source = "@interface Widget : NSObject\n@property (strong) NSString * name;\n@end\n";
        assert_eq!(render_header(Style::new(false), source), source);
        let rendered = render_header(Style::new(true), source);
        assert!(rendered.contains("\u{1b}[1;34m@interface\u{1b}[0m"));
        assert!(rendered.contains("\u{1b}[35mNSObject\u{1b}[0m"));
        assert_eq!(strip_ansi(&rendered), source);
    }

    fn strip_ansi(text: &str) -> String {
        let mut output = String::new();
        let mut characters = text.chars();
        while let Some(character) = characters.next() {
            if character == '\u{1b}' && characters.next() == Some('[') {
                for character in characters.by_ref() {
                    if character.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                output.push(character);
            }
        }
        output
    }
}
