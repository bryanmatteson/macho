use crate::addr::ThinFileOffset;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone)]
pub struct DiagnosticCode(pub &'static str);

#[derive(Debug, Clone)]
pub struct Span {
    pub offset: ThinFileOffset,
    pub size: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: DiagnosticCode,
    pub message: String,
    pub spans: Vec<Span>,
}

impl Diagnostic {
    pub fn error(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            code: DiagnosticCode(code),
            message: message.into(),
            spans: Vec::new(),
        }
    }

    pub fn warning(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            code: DiagnosticCode(code),
            message: message.into(),
            spans: Vec::new(),
        }
    }

    pub fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            code: DiagnosticCode(code),
            message: message.into(),
            spans: Vec::new(),
        }
    }

    pub fn with_span(mut self, span: Span) -> Self {
        self.spans.push(span);
        self
    }
}
