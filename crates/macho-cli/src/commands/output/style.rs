use std::sync::OnceLock;

use termosaic::{AnsiColor, Color, HumanText, Span, Theme, TokenId, TokenStyle, tokens};

const RESET: &str = "\u{1b}[0m";

const SEGMENT_NAME: TokenId = TokenId::from_static("entity.identifier.segment");
const SECTION_NAME: TokenId = TokenId::from_static("entity.identifier.section");
const SYMBOL: TokenId = TokenId::from_static("entity.identifier.symbol");

/// Macho's address token, for callers assembling their own span streams.
pub const ADDRESS: TokenId = TokenId::from_static("entity.identifier.address");
/// Macho's raw encoded-byte token, for callers assembling their own span streams.
pub const RAW_BYTES: TokenId = TokenId::from_static("data.raw-bytes");

/// Termosaic theme and ANSI policy resolved for one human-output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    enabled: bool,
}

impl Style {
    /// Construct Macho's compatibility theme with ANSI either enabled or disabled.
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether ANSI styling is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Render a top-level title.
    pub fn title(&self, text: &str) -> String {
        self.paint(&tokens::TEXT_HEADING, text)
    }

    /// Render a section heading.
    pub fn heading(&self, text: &str) -> String {
        self.paint(&tokens::TEXT_SUBHEADING, text)
    }

    /// Render a top-level segment name.
    pub fn segment_name(&self, text: &str) -> String {
        self.paint(&SEGMENT_NAME, text)
    }

    /// Render a nested section name.
    pub fn section_name(&self, text: &str) -> String {
        self.paint(&SECTION_NAME, text)
    }

    /// Render an address or other location value.
    pub fn address(&self, text: &str) -> String {
        self.paint(&ADDRESS, text)
    }

    /// Render secondary metadata.
    pub fn muted(&self, text: &str) -> String {
        self.paint(&tokens::TEXT_MUTED, text)
    }

    /// Render informational metadata.
    pub fn info(&self, text: &str) -> String {
        self.paint(&tokens::STATUS_INFO, text)
    }

    /// Render successful or exported metadata.
    pub fn success(&self, text: &str) -> String {
        self.paint(&tokens::STATUS_SUCCESS, text)
    }

    /// Render language or runtime metadata.
    pub fn accent(&self, text: &str) -> String {
        self.paint(&SYMBOL, text)
    }

    /// Render a typed enum value.
    pub fn enum_value(&self, text: &str) -> String {
        self.paint(&tokens::DATA_FORMAT, text)
    }

    /// Render a scalar property value.
    pub fn value(&self, text: &str) -> String {
        self.paint(&tokens::DATA_NUMBER, text)
    }

    /// Render a `key=value` scalar property.
    pub fn property(&self, key: &str, value: &str) -> String {
        format!("{}{}", self.muted(&format!("{key}=")), self.value(value))
    }

    /// Render a `key=value` property whose value is an enum.
    pub fn enum_property(&self, key: &str, value: &str) -> String {
        format!(
            "{}{}",
            self.muted(&format!("{key}=")),
            self.enum_value(value)
        )
    }

    /// Render a semantic [`Span`] stream by resolving each token against the
    /// theme, mirroring Termosaic's own span rendering.
    ///
    /// Span text is already sanitized by [`Span::new`], so it is emitted as-is:
    /// concatenating the rendered spans reproduces the span texts exactly.
    pub fn render_spans(&self, spans: &[Span]) -> String {
        let mut output = String::new();
        for span in spans {
            let text = span.text.as_str();
            if self.enabled {
                output.push_str(&encode_ansi16(macho_theme().resolve(&span.token), text));
            } else {
                output.push_str(text);
            }
        }
        output
    }

    /// Render one semantic token's text.
    pub fn token(&self, token: &TokenId, text: &str) -> String {
        self.paint(token, text)
    }

    /// Render a trailing instruction comment.
    pub fn comment(&self, text: &str) -> String {
        self.paint(&tokens::SYNTAX_COMMENT, text)
    }

    /// Render a raw encoded-byte column.
    pub fn raw_bytes(&self, text: &str) -> String {
        self.paint(&RAW_BYTES, text)
    }

    /// Render an error label.
    pub fn error(&self, text: &str) -> String {
        self.paint(&tokens::DIAGNOSTIC_ERROR, text)
    }

    /// Render a warning label.
    pub fn warning(&self, text: &str) -> String {
        self.paint(&tokens::DIAGNOSTIC_WARNING, text)
    }

    fn paint(&self, token: &TokenId, text: &str) -> String {
        let text = HumanText::sanitize(text);
        if !self.enabled {
            return text.as_str().to_owned();
        }
        encode_ansi16(macho_theme().resolve(token), text.as_str())
    }
}

/// Clap help and usage styling derived from Macho's Termosaic theme, so
/// generated help text and rendered reports share one palette.
///
/// Clap owns its own renderer and speaks `anstyle`, so each slot resolves the
/// corresponding semantic token and converts the result. Callers decide whether
/// colour applies at all by setting `Command::color`.
pub fn clap_styles() -> clap::builder::Styles {
    let slot = |token: &TokenId| anstyle_from(macho_theme().resolve(token));
    clap::builder::Styles::plain()
        .header(slot(&tokens::TEXT_SUBHEADING))
        .usage(slot(&tokens::TEXT_SUBHEADING))
        .literal(slot(&tokens::SYNTAX_KEYWORD))
        .placeholder(slot(&tokens::SYNTAX_TYPE_BUILTIN))
        .error(slot(&tokens::DIAGNOSTIC_ERROR))
        .valid(slot(&tokens::STATUS_SUCCESS))
        .invalid(slot(&tokens::DIAGNOSTIC_WARNING))
}

/// Convert one resolved Termosaic token style into Clap's `anstyle` equivalent.
fn anstyle_from(style: TokenStyle) -> clap::builder::styling::Style {
    let mut converted = clap::builder::styling::Style::new();
    if let Some(color) = style.foreground {
        let color = match color {
            Color::Ansi(color) => color,
            Color::Rgb { fallback, .. } => fallback,
        };
        converted = converted.fg_color(Some(anstyle_color(color).into()));
    }
    if style.bold {
        converted = converted.bold();
    }
    if style.dim {
        converted = converted.dimmed();
    }
    if style.underline {
        converted = converted.underline();
    }
    converted
}

const fn anstyle_color(color: AnsiColor) -> clap::builder::styling::AnsiColor {
    use clap::builder::styling::AnsiColor as Clap;
    match color {
        AnsiColor::Black => Clap::Black,
        AnsiColor::Red => Clap::Red,
        AnsiColor::Green => Clap::Green,
        AnsiColor::Yellow => Clap::Yellow,
        AnsiColor::Blue => Clap::Blue,
        AnsiColor::Magenta => Clap::Magenta,
        AnsiColor::Cyan => Clap::Cyan,
        AnsiColor::White => Clap::White,
        AnsiColor::BrightBlack => Clap::BrightBlack,
        AnsiColor::BrightRed => Clap::BrightRed,
        AnsiColor::BrightGreen => Clap::BrightGreen,
        AnsiColor::BrightYellow => Clap::BrightYellow,
        AnsiColor::BrightBlue => Clap::BrightBlue,
        AnsiColor::BrightMagenta => Clap::BrightMagenta,
        AnsiColor::BrightCyan => Clap::BrightCyan,
        AnsiColor::BrightWhite => Clap::BrightWhite,
    }
}

fn macho_theme() -> &'static Theme {
    static THEME: OnceLock<Theme> = OnceLock::new();
    THEME.get_or_init(build_macho_theme)
}

fn build_macho_theme() -> Theme {
    Theme::builder("macho")
        .rule(tokens::TEXT, TokenStyle::default())
        .and_then(|theme| theme.rule(tokens::TEXT_HEADING, TokenStyle::emphasized()))
        .and_then(|theme| {
            theme.rule(
                tokens::TEXT_SUBHEADING,
                TokenStyle::bold(Color::Ansi(AnsiColor::Cyan)),
            )
        })
        .and_then(|theme| theme.rule(SEGMENT_NAME, TokenStyle::bold(Color::Ansi(AnsiColor::Blue))))
        .and_then(|theme| {
            theme.rule(
                SECTION_NAME,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Blue)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                ADDRESS,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Cyan)),
            )
        })
        .and_then(|theme| theme.rule(tokens::TEXT_MUTED, TokenStyle::dimmed()))
        .and_then(|theme| {
            theme.rule(
                tokens::STATUS_INFO,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Blue)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::STATUS_SUCCESS,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Green)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                SYMBOL,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Magenta)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::DATA_FORMAT,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Magenta)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::DATA_NUMBER,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Yellow)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::SYNTAX_KEYWORD,
                TokenStyle::bold(Color::Ansi(AnsiColor::Blue)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::SYNTAX_VARIABLE_BUILTIN,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Cyan)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::SYNTAX_NUMBER,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Yellow)),
            )
        })
        .and_then(|theme| theme.rule(tokens::SYNTAX_PUNCTUATION, TokenStyle::dimmed()))
        .and_then(|theme| {
            theme.rule(
                tokens::SYNTAX_TYPE_BUILTIN,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Magenta)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::SYNTAX_COMMENT,
                TokenStyle::foreground(Color::Ansi(AnsiColor::Green)),
            )
        })
        .and_then(|theme| theme.rule(RAW_BYTES, TokenStyle::dimmed()))
        .and_then(|theme| {
            theme.rule(
                tokens::DIAGNOSTIC_ERROR,
                TokenStyle::bold(Color::Ansi(AnsiColor::Red)),
            )
        })
        .and_then(|theme| {
            theme.rule(
                tokens::DIAGNOSTIC_WARNING,
                TokenStyle::bold(Color::Ansi(AnsiColor::Yellow)),
            )
        })
        .and_then(termosaic::ThemeBuilder::build)
        .expect("Macho's static Termosaic theme is valid")
}

fn encode_ansi16(style: TokenStyle, text: &str) -> String {
    let foreground = style.foreground.map(|color| {
        ansi16_code(match color {
            Color::Ansi(color) => color,
            Color::Rgb { fallback, .. } => fallback,
        })
    });
    let codes = [
        style.bold.then_some("1"),
        style.dim.then_some("2"),
        style.underline.then_some("4"),
        foreground,
    ];
    if codes.iter().all(Option::is_none) {
        text.to_owned()
    } else {
        let mut output = String::with_capacity(text.len() + 16);
        output.push_str("\u{1b}[");
        for (index, code) in codes.into_iter().flatten().enumerate() {
            if index != 0 {
                output.push(';');
            }
            output.push_str(code);
        }
        output.push('m');
        output.push_str(text);
        output.push_str(RESET);
        output
    }
}

const fn ansi16_code(color: AnsiColor) -> &'static str {
    match color {
        AnsiColor::Black => "30",
        AnsiColor::Red => "31",
        AnsiColor::Green => "32",
        AnsiColor::Yellow => "33",
        AnsiColor::Blue => "34",
        AnsiColor::Magenta => "35",
        AnsiColor::Cyan => "36",
        AnsiColor::White => "37",
        AnsiColor::BrightBlack => "90",
        AnsiColor::BrightRed => "91",
        AnsiColor::BrightGreen => "92",
        AnsiColor::BrightYellow => "93",
        AnsiColor::BrightBlue => "94",
        AnsiColor::BrightMagenta => "95",
        AnsiColor::BrightCyan => "96",
        AnsiColor::BrightWhite => "97",
    }
}

#[cfg(test)]
mod tests {
    use super::Style;

    #[test]
    fn disabled_style_is_escape_free() {
        assert_eq!(Style::new(false).heading("Header:"), "Header:");
    }

    #[test]
    fn enabled_style_resets_each_fragment() {
        assert_eq!(
            Style::new(true).heading("Header:"),
            "\u{1b}[1;36mHeader:\u{1b}[0m"
        );
    }

    #[test]
    fn styled_text_is_sanitized_by_termosaic() {
        assert_eq!(Style::new(false).accent("safe\u{1b}[31m"), "safe�[31m");
    }
}
