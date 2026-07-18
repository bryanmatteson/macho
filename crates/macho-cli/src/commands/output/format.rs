use std::fmt;

use clap::ValueEnum;

use super::Style;

/// Output representation shared by every command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[non_exhaustive]
pub enum Format {
    /// Human-readable text.
    Text,
    /// Versioned JSON envelope.
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
    use super::{ColorChoice, Format, Options};

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
