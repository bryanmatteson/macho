use std::io::Write;

use serde::Serialize;
use serde_json::{Value, json};
use termosaic::HumanText;

use super::{Error, Format, Options, Result, json as json_output};

/// Structured warning or error emitted on the diagnostic stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// Stable diagnostic code.
    pub code: String,
    /// Human-readable diagnostic message.
    pub message: String,
}

impl Diagnostic {
    /// Construct a diagnostic.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Deliver a successfully rendered command payload.
pub fn write_success(
    out: &mut dyn Write,
    options: Options,
    command: &str,
    bytes: &[u8],
) -> Result<()> {
    match options.format() {
        Format::Text | Format::Sarif => out.write_all(bytes).map_err(Into::into),
        Format::Json => {
            let data = serde_json::from_slice::<Value>(bytes).map_err(Error::InvalidJsonReport)?;
            write_envelope(out, command, true, data, &[])
        }
    }
}

/// Deliver one failure on the diagnostic stream.
pub fn write_failure(
    out: &mut dyn Write,
    options: Options,
    command: &str,
    code: &str,
    message: &str,
) -> Result<()> {
    if options.format() == Format::Json {
        write_envelope(
            out,
            command,
            false,
            Value::Null,
            &[Diagnostic::new(code, message)],
        )
    } else {
        write!(out, "{} ", options.style().error("Error:"))?;
        write_human_message(out, message)
    }
}

/// Deliver warnings on the diagnostic stream.
pub fn write_diagnostics(
    out: &mut dyn Write,
    options: Options,
    command: &str,
    diagnostics: &[Diagnostic],
) -> Result<()> {
    if diagnostics.is_empty() {
        return Ok(());
    }
    if options.format() == Format::Json {
        write_envelope(out, command, true, Value::Null, diagnostics)
    } else {
        for diagnostic in diagnostics {
            let code = HumanText::sanitize(&diagnostic.code);
            write!(
                out,
                "{} [{}]: ",
                options.style().warning("Warning"),
                code.as_str(),
            )?;
            write_human_message(out, &diagnostic.message)?;
        }
        Ok(())
    }
}

fn write_human_message(out: &mut dyn Write, message: &str) -> Result<()> {
    let mut remainder = message;
    while let Some(newline) = remainder.find('\n') {
        let line = remainder[..newline]
            .strip_suffix('\r')
            .unwrap_or(&remainder[..newline]);
        out.write_all(HumanText::sanitize(line).as_str().as_bytes())?;
        out.write_all(b"\n")?;
        remainder = &remainder[newline + 1..];
    }
    if !remainder.is_empty() {
        out.write_all(HumanText::sanitize(remainder).as_str().as_bytes())?;
    }
    if !message.ends_with('\n') {
        out.write_all(b"\n")?;
    }
    Ok(())
}

fn write_envelope(
    out: &mut dyn Write,
    command: &str,
    ok: bool,
    data: Value,
    diagnostics: &[Diagnostic],
) -> Result<()> {
    json_output::write_pretty(
        out,
        &json!({
            "schema_version": 1,
            "command": command,
            "ok": ok,
            "data": data,
            "diagnostics": diagnostics,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, write_diagnostics, write_failure, write_success};
    use crate::commands::output::{ColorChoice, Format, Options};

    #[test]
    fn json_success_is_one_parseable_envelope() {
        let mut output = Vec::new();
        write_success(
            &mut output,
            Options::plain(Format::Json),
            "info",
            br#"{"header":{"cpu":"arm64"}}"#,
        )
        .expect("delivery succeeds");
        let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(value["command"], "info");
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["header"]["cpu"], "arm64");
    }

    #[test]
    fn json_diagnostics_never_contain_ansi() {
        let options = Options::resolve(Format::Json, ColorChoice::Always, true);
        let mut output = Vec::new();
        write_diagnostics(
            &mut output,
            options,
            "info",
            &[Diagnostic::new("parse.warning", "recovered")],
        )
        .expect("delivery succeeds");
        assert!(!output.contains(&0x1b));
        serde_json::from_slice::<serde_json::Value>(&output).expect("valid JSON");
    }

    #[test]
    fn human_failure_uses_resolved_style() {
        let mut output = Vec::new();
        write_failure(
            &mut output,
            Options::resolve(Format::Text, ColorChoice::Always, false),
            "info",
            "parse.failed",
            "bad input",
        )
        .expect("delivery succeeds");
        assert!(output.starts_with(b"\x1b[1;31mError:\x1b[0m bad input"));
    }

    #[test]
    fn human_failure_preserves_structural_lines_while_sanitizing_content() {
        let mut output = Vec::new();
        write_failure(
            &mut output,
            Options::plain(Format::Text),
            "info",
            "parse.failed",
            "bad\u{1b}\r\nUsage: macho <COMMAND>\n",
        )
        .expect("delivery succeeds");
        assert_eq!(
            String::from_utf8(output).expect("human output is UTF-8"),
            "Error: bad�\nUsage: macho <COMMAND>\n"
        );
    }

    #[test]
    fn human_diagnostics_sanitize_terminal_controls() {
        let mut output = Vec::new();
        write_diagnostics(
            &mut output,
            Options::plain(Format::Text),
            "info",
            &[Diagnostic::new("parse\u{1b}[31m", "unsafe\u{202e}message")],
        )
        .expect("delivery succeeds");
        assert_eq!(
            String::from_utf8(output).expect("human output is UTF-8"),
            "Warning [parse�[31m]: unsafe�message\n"
        );
    }
}
