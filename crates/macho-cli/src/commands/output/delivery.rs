use std::io::Write;

use serde::Serialize;
use serde_json::{Value, json};

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
        writeln!(out, "{} {message}", options.style().error("Error:"))?;
        Ok(())
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
            writeln!(
                out,
                "{} [{}]: {}",
                options.style().warning("Warning"),
                diagnostic.code,
                diagnostic.message
            )?;
        }
        Ok(())
    }
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
}
