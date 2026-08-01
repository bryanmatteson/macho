use std::fmt;

use clap::ValueEnum;

use super::Style;

/// Output representation shared by every command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Format {
    /// Human-readable text.
    Text,
    /// JSON report or command-documented NDJSON stream.
    Json,
    /// SARIF 2.1 report.
    Sarif,
}

impl Format {
    /// Whether this format is the JSON machine-output format.
    pub const fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }

    /// Whether this format must never contain ANSI escape sequences.
    pub const fn is_machine(self) -> bool {
        matches!(self, Self::Json | Self::Sarif)
    }
}

impl fmt::Display for Format {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Sarif => "sarif",
        })
    }
}

/// ANSI color selection for human output.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    /// Enable color only for a terminal that permits it.
    #[default]
    Auto,
    /// Always enable color for human text output.
    Always,
    /// Never emit ANSI color.
    Never,
}

impl fmt::Display for ColorChoice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        })
    }
}

/// Invalid combinations of shared output arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// SARIF was selected for a command that does not produce SARIF reports.
    #[error("SARIF output is supported only by the audit command")]
    UnsupportedSarif,
    /// Explicit ANSI color was requested for a machine-readable format.
    #[error("--color always is incompatible with machine output")]
    ColorMachine,
}

const UNSUPPORTED_FORMAT_CODE: &str = "cli.usage.unsupported_format";
const COLOR_MACHINE_CODE: &str = "cli.usage.color_machine";

impl PolicyError {
    /// Stable diagnostic code for this usage-policy failure.
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedSarif => UNSUPPORTED_FORMAT_CODE,
            Self::ColorMachine => COLOR_MACHINE_CODE,
        }
    }
}

/// Validate shared output arguments before command dispatch.
pub const fn validate_policy(
    format: Format,
    color: ColorChoice,
    sarif_supported: bool,
) -> Result<(), PolicyError> {
    if format.is_machine() && matches!(color, ColorChoice::Always) {
        return Err(PolicyError::ColorMachine);
    }
    if matches!(format, Format::Sarif) && !sarif_supported {
        return Err(PolicyError::UnsupportedSarif);
    }
    Ok(())
}

/// Resolved rendering options for one output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    format: Format,
    style: Style,
    color: ColorChoice,
}

impl Options {
    /// Resolve output options for a stream with known terminal state.
    pub fn resolve(format: Format, color: ColorChoice, is_terminal: bool) -> Self {
        let term_is_dumb = std::env::var("TERM").is_ok_and(|term| term == "dumb");
        Self::resolve_policy(
            format,
            color,
            is_terminal,
            std::env::var_os("NO_COLOR").is_some(),
            term_is_dumb,
        )
    }

    fn resolve_policy(
        format: Format,
        color: ColorChoice,
        is_terminal: bool,
        no_color: bool,
        term_is_dumb: bool,
    ) -> Self {
        let color_enabled = format == Format::Text
            && match color {
                ColorChoice::Always => true,
                ColorChoice::Never => false,
                ColorChoice::Auto => is_terminal && !no_color && !term_is_dumb,
            };
        Self {
            format,
            style: Style::new(color_enabled),
            color,
        }
    }

    /// Construct deterministic, escape-free options for an injected writer.
    pub const fn plain(format: Format) -> Self {
        Self {
            format,
            style: Style::new(false),
            color: ColorChoice::Never,
        }
    }

    /// Selected output format.
    pub const fn format(self) -> Format {
        self.format
    }

    /// Resolved human-output style.
    pub const fn style(self) -> Style {
        self.style
    }

    /// Requested color policy before terminal resolution.
    pub const fn color(self) -> ColorChoice {
        self.color
    }
}

#[cfg(test)]
mod tests {
    use super::{ColorChoice, Format, Options, PolicyError, validate_policy};

    #[test]
    fn shared_output_policy_rejects_machine_color_and_non_audit_sarif() {
        assert_eq!(
            validate_policy(Format::Json, ColorChoice::Always, false),
            Err(PolicyError::ColorMachine)
        );
        assert_eq!(
            validate_policy(Format::Sarif, ColorChoice::Always, true),
            Err(PolicyError::ColorMachine)
        );
        assert_eq!(
            validate_policy(Format::Sarif, ColorChoice::Auto, false),
            Err(PolicyError::UnsupportedSarif)
        );
        assert_eq!(PolicyError::ColorMachine.code(), "cli.usage.color_machine");
        assert_eq!(
            PolicyError::ColorMachine.to_string(),
            "--color always is incompatible with machine output"
        );
        assert_eq!(
            PolicyError::UnsupportedSarif.code(),
            "cli.usage.unsupported_format"
        );
        assert_eq!(
            PolicyError::UnsupportedSarif.to_string(),
            "SARIF output is supported only by the audit command"
        );
    }

    #[test]
    fn shared_output_policy_preserves_text_color_and_audit_sarif() {
        for color in [ColorChoice::Auto, ColorChoice::Always, ColorChoice::Never] {
            assert_eq!(validate_policy(Format::Text, color, false), Ok(()));
        }
        assert_eq!(
            validate_policy(Format::Json, ColorChoice::Auto, false),
            Ok(())
        );
        assert_eq!(
            validate_policy(Format::Json, ColorChoice::Never, false),
            Ok(())
        );
        assert_eq!(
            validate_policy(Format::Sarif, ColorChoice::Auto, true),
            Ok(())
        );
        assert_eq!(
            validate_policy(Format::Sarif, ColorChoice::Never, true),
            Ok(())
        );
    }

    #[test]
    fn machine_formats_never_enable_color() {
        assert!(
            !Options::resolve(Format::Json, ColorChoice::Always, true)
                .style()
                .enabled()
        );
        assert!(
            !Options::resolve(Format::Sarif, ColorChoice::Always, true)
                .style()
                .enabled()
        );
    }

    #[test]
    fn explicit_human_color_choices_are_deterministic() {
        assert!(
            Options::resolve(Format::Text, ColorChoice::Always, false)
                .style()
                .enabled()
        );
        assert!(
            !Options::resolve(Format::Text, ColorChoice::Never, true)
                .style()
                .enabled()
        );
    }

    #[test]
    fn auto_defaults_to_color_on_an_interactive_terminal() {
        assert_eq!(ColorChoice::default(), ColorChoice::Auto);
        assert!(
            Options::resolve_policy(Format::Text, ColorChoice::Auto, true, false, false)
                .style()
                .enabled()
        );
        assert!(
            !Options::resolve_policy(Format::Text, ColorChoice::Auto, false, false, false)
                .style()
                .enabled()
        );
    }
}
