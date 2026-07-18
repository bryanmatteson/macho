const RESET: &str = "\u{1b}[0m";

/// ANSI styling resolved for one human-output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    enabled: bool,
}

impl Style {
    /// Construct a style with ANSI either enabled or disabled.
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether ANSI styling is enabled.
    pub const fn enabled(self) -> bool {
        self.enabled
    }

    /// Render a top-level title.
    pub fn title(self, text: &str) -> String {
        self.paint("1", text)
    }

    /// Render a section heading.
    pub fn heading(self, text: &str) -> String {
        self.paint("1;36", text)
    }

    /// Render a top-level segment name.
    pub fn segment_name(self, text: &str) -> String {
        self.paint("1;34", text)
    }

    /// Render a nested section name.
    pub fn section_name(self, text: &str) -> String {
        self.paint("34", text)
    }

    /// Render an address or other location value.
    pub fn address(self, text: &str) -> String {
        self.paint("36", text)
    }

    /// Render secondary metadata.
    pub fn muted(self, text: &str) -> String {
        self.paint("2", text)
    }

    /// Render informational metadata.
    pub fn info(self, text: &str) -> String {
        self.paint("34", text)
    }

    /// Render successful or exported metadata.
    pub fn success(self, text: &str) -> String {
        self.paint("32", text)
    }

    /// Render language or runtime metadata.
    pub fn accent(self, text: &str) -> String {
        self.paint("35", text)
    }

    /// Render a typed enum value.
    pub fn enum_value(self, text: &str) -> String {
        self.paint("35", text)
    }

    /// Render a scalar property value.
    pub fn value(self, text: &str) -> String {
        self.paint("33", text)
    }

    /// Render a `key=value` scalar property.
    pub fn property(self, key: &str, value: &str) -> String {
        format!("{}{}", self.muted(&format!("{key}=")), self.value(value))
    }

    /// Render a `key=value` property whose value is an enum.
    pub fn enum_property(self, key: &str, value: &str) -> String {
        format!(
            "{}{}",
            self.muted(&format!("{key}=")),
            self.enum_value(value)
        )
    }

    /// Render an error label.
    pub fn error(self, text: &str) -> String {
        self.paint("1;31", text)
    }

    /// Render a warning label.
    pub fn warning(self, text: &str) -> String {
        self.paint("1;33", text)
    }

    fn paint(self, sgr: &str, text: &str) -> String {
        if self.enabled {
            format!("\u{1b}[{sgr}m{text}{RESET}")
        } else {
            text.to_owned()
        }
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
}
