use crate::core::model::addr::ThinFileOffset;

#[derive(Debug, Clone, PartialEq, Eq)]
/// The Severity type.
#[non_exhaustive]
pub enum Severity {
    /// The Error variant.
    Error,
    /// The Warning variant.
    Warning,
    /// The Info variant.
    Info,
}

#[derive(Debug, Clone)]
/// The DiagnosticCode type.
pub struct DiagnosticCode(pub &'static str);

#[derive(Debug, Clone)]
/// The Span type.
pub struct Span {
    /// The offset field.
    pub offset: ThinFileOffset,
    /// The size field.
    pub size: u64,
    /// The label field.
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
/// The Diagnostic type.
pub struct Diagnostic {
    /// The severity field.
    pub severity: Severity,
    /// The code field.
    pub code: DiagnosticCode,
    /// The message field.
    pub message: String,
    /// The spans field.
    pub spans: Vec<Span>,
}

impl Diagnostic {
    /// Performs error.
    pub fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: DiagnosticCode(code),
            message: message.into(),
            spans: Vec::new(),
        }
    }

    /// Performs warning.
    pub fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: DiagnosticCode(code),
            message: message.into(),
            spans: Vec::new(),
        }
    }

    /// Performs info.
    pub fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            code: DiagnosticCode(code),
            message: message.into(),
            spans: Vec::new(),
        }
    }

    /// Performs with_span.
    pub fn with_span(mut self, span: Span) -> Self {
        self.spans.push(span);
        self
    }
}
