//! Semantic tokenization of decoded instruction text.
//!
//! The decoder hands the delivery layer one already-rendered instruction string
//! per record (Intel syntax for x86-64, ARM syntax for AArch64). This module
//! performs the first two stages of the presentation pipeline — lex the string
//! into lexical runs, then assign each run a Termosaic [`termosaic::TokenId`] —
//! and emits the result as a [`termosaic::Span`] stream. Resolving those tokens
//! against the theme is [`Style`](crate::commands::output::Style)'s job, so
//! classification stays independent of colour.
//!
//! Tokenization never alters a character: concatenating the span texts always
//! reproduces the input exactly, which is what keeps plain output and
//! ANSI-stripped colored output identical.

use termosaic::{Span, TokenId, tokens};

/// Operand words that qualify another operand rather than naming a value:
/// x86 size/branch hints and ARM shift, extend, and condition words.
const QUALIFIERS: &[&str] = &[
    // x86 size and branch qualifiers.
    "byte", "word", "dword", "qword", "tbyte", "fword", "oword", "xmmword", "ymmword", "zmmword",
    "ptr", "short", "near", "far", "offset", // ARM shifts, extends, and barriers.
    "lsl", "lsr", "asr", "ror", "rrx", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw",
    "sxtx", "msl", "sy", "ish", "ishst", "ishld", "nsh", "osh", "st", "ld",
    // ARM condition codes.
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
    "hs", "lo",
];

/// x86-64 registers whose spelling is not a prefix/index pair.
const X86_NAMED_REGISTERS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eax", "ebx", "ecx", "edx",
    "esi", "edi", "ebp", "esp", "eip", "ax", "bx", "cx", "dx", "si", "di", "bp", "al", "bl", "cl",
    "dl", "ah", "bh", "ch", "dh", "sil", "dil", "bpl", "spl", "cs", "ds", "es", "fs", "gs", "ss",
];

/// AArch64 registers whose spelling is not a prefix/index pair.
const ARM_NAMED_REGISTERS: &[&str] = &["sp", "lr", "fp", "pc", "xzr", "wzr", "wsp"];

/// Tokenize one decoded instruction, appending its spans to `spans`.
///
/// The caller owns the buffer so a streaming sink can reuse one allocation for
/// every record instead of allocating per instruction. Existing contents are
/// left in place; clear the buffer first when starting a fresh line.
pub fn instruction_spans_into(text: &str, spans: &mut Vec<Span>) {
    let mnemonic_end = text.find(char::is_whitespace).unwrap_or(text.len());
    let (mnemonic, operands) = text.split_at(mnemonic_end);
    if !mnemonic.is_empty() {
        spans.push(Span::new(tokens::SYNTAX_KEYWORD, mnemonic));
    }
    push_operand_spans(operands, spans);
}

/// Tokenize one decoded instruction into a fresh span stream.
pub fn instruction_spans(text: &str) -> Vec<Span> {
    let mut spans = Vec::new();
    instruction_spans_into(text, &mut spans);
    spans
}

/// Unstyled literal text, used for separators and column padding.
pub fn literal(text: impl AsRef<str>) -> Span {
    Span::new(tokens::TEXT, text)
}

/// Scan operand text, emitting one span per lexical run.
fn push_operand_spans(operands: &str, spans: &mut Vec<Span>) {
    let bytes = operands.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let rest = &operands[index..];
        let byte = bytes[index];
        let (token, run) = if byte.is_ascii_whitespace() {
            (tokens::TEXT, take_while(rest, |c| c.is_ascii_whitespace()))
        } else if byte.is_ascii_digit() {
            // Numeric literals cover `0x1f`, `1234`, and the Intel `0ff00h`
            // trailing-radix spelling, so consume the whole alphanumeric run.
            (
                tokens::SYNTAX_NUMBER,
                take_while(rest, |c| c.is_ascii_alphanumeric()),
            )
        } else if is_word_start(byte) {
            let run = take_while(rest, |c| is_word_continue(c as u8));
            (classify_word(run), run)
        } else {
            (
                tokens::SYNTAX_PUNCTUATION,
                take_while(rest, |c| {
                    !c.is_ascii_whitespace()
                        && !c.is_ascii_alphanumeric()
                        && !is_word_start(c as u8)
                }),
            )
        };
        spans.push(Span::new(token, run));
        index += run.len();
    }
}

/// Borrow the leading run of `text` whose characters all satisfy `predicate`.
fn take_while(text: &str, predicate: impl Fn(char) -> bool) -> &str {
    let end = text
        .char_indices()
        .find(|(_, character)| !predicate(*character))
        .map_or(text.len(), |(offset, _)| offset);
    &text[..end]
}

const fn is_word_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'.' | b'$' | b'@')
}

const fn is_word_continue(byte: u8) -> bool {
    is_word_start(byte) || byte.is_ascii_digit()
}

/// Classify one operand word as a register, qualifier, or plain identifier.
fn classify_word(word: &str) -> TokenId {
    let lowered = word.to_ascii_lowercase();
    if is_register(&lowered) {
        tokens::SYNTAX_VARIABLE_BUILTIN
    } else if QUALIFIERS.contains(&lowered.as_str()) {
        tokens::SYNTAX_TYPE_BUILTIN
    } else {
        // Symbol and label operands keep the surrounding text colour.
        tokens::TEXT
    }
}

fn is_register(word: &str) -> bool {
    X86_NAMED_REGISTERS.contains(&word)
        || ARM_NAMED_REGISTERS.contains(&word)
        || indexed_register(word, "xmm", 31)
        || indexed_register(word, "ymm", 31)
        || indexed_register(word, "zmm", 31)
        || indexed_register(word, "st", 7)
        || indexed_register(word, "r", 15)
        || indexed_register(word, "x", 30)
        || indexed_register(word, "w", 30)
        || indexed_register(word, "v", 31)
        || indexed_register(word, "q", 31)
        || indexed_register(word, "d", 31)
        || indexed_register(word, "s", 31)
        || indexed_register(word, "h", 31)
        || indexed_register(word, "b", 31)
}

/// Whether `word` is `prefix` followed by a decimal index of at most `max`,
/// allowing one trailing width letter such as the `d` in `r8d`.
fn indexed_register(word: &str, prefix: &str, max: u32) -> bool {
    let Some(rest) = word.strip_prefix(prefix) else {
        return false;
    };
    let digits = take_while(rest, |character| character.is_ascii_digit());
    if digits.is_empty() || digits.len() > 2 {
        return false;
    }
    let tail = &rest[digits.len()..];
    if tail.len() > 1
        || tail
            .chars()
            .any(|character| !character.is_ascii_alphabetic())
    {
        return false;
    }
    digits.parse::<u32>().is_ok_and(|index| index <= max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(text: &str) -> String {
        instruction_spans(text)
            .iter()
            .map(|span| span.text.as_str().to_owned())
            .collect()
    }

    /// Classification is asserted against token identities rather than escape
    /// sequences, so recolouring the theme cannot break these tests.
    fn token_of(text: &str, fragment: &str) -> TokenId {
        instruction_spans(text)
            .into_iter()
            .find(|span| span.text.as_str() == fragment)
            .unwrap_or_else(|| panic!("no span for {fragment:?} in {text:?}"))
            .token
    }

    #[test]
    fn tokenization_preserves_every_character() {
        for text in [
            "nop",
            "ret",
            "jmp short 0000000100000104h",
            "mov rax, qword ptr [rip+0FF00h]",
            "movzx r8d, byte ptr [rsp+8]",
            "ldr x0, [sp, #0x10]",
            "add w1, w2, w3, lsl #2",
            "b.eq 0x100003f50",
            "bl _objc_msgSend",
            "",
        ] {
            assert_eq!(rendered(text), text, "span texts must rebuild {text:?}");
        }
    }

    #[test]
    fn spans_carry_semantic_tokens() {
        let text = "mov rax, qword ptr [rip+0FF00h]";
        assert_eq!(token_of(text, "mov"), tokens::SYNTAX_KEYWORD);
        assert_eq!(token_of(text, "rax"), tokens::SYNTAX_VARIABLE_BUILTIN);
        assert_eq!(token_of(text, "qword"), tokens::SYNTAX_TYPE_BUILTIN);
        assert_eq!(token_of(text, "0FF00h"), tokens::SYNTAX_NUMBER);
        assert_eq!(token_of(text, "["), tokens::SYNTAX_PUNCTUATION);

        let arm = "ldr x0, [sp, #0x10]";
        assert_eq!(token_of(arm, "ldr"), tokens::SYNTAX_KEYWORD);
        assert_eq!(token_of(arm, "x0"), tokens::SYNTAX_VARIABLE_BUILTIN);
        assert_eq!(token_of(arm, "sp"), tokens::SYNTAX_VARIABLE_BUILTIN);
        assert_eq!(token_of(arm, "0x10"), tokens::SYNTAX_NUMBER);

        // A symbol operand is left unclassified.
        assert_eq!(token_of("bl _objc_msgSend", "_objc_msgSend"), tokens::TEXT);
    }

    #[test]
    fn a_reused_buffer_matches_a_fresh_one() {
        let mut buffer = Vec::new();
        instruction_spans_into("mov rax, 1", &mut buffer);
        let first = buffer.clone();
        buffer.clear();
        instruction_spans_into("ldr x0, [sp]", &mut buffer);

        assert_eq!(first, instruction_spans("mov rax, 1"));
        assert_eq!(buffer, instruction_spans("ldr x0, [sp]"));
    }

    #[test]
    fn registers_and_qualifiers_are_classified() {
        assert!(is_register("rax"));
        assert!(is_register("r15"));
        assert!(is_register("r8d"));
        assert!(is_register("xmm0"));
        assert!(is_register("x29"));
        assert!(is_register("w0"));
        assert!(is_register("sp"));
        assert!(is_register("v31"));
        assert!(!is_register("x31"));
        assert!(!is_register("r16"));
        assert!(!is_register("_helper"));
        assert!(!is_register("objc_msgSend"));
        assert!(QUALIFIERS.contains(&"qword"));
        assert!(QUALIFIERS.contains(&"lsl"));
    }
}
