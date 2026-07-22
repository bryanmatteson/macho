use super::SyntaxIssue;

pub(super) fn format_syntax_issues(issues: &[SyntaxIssue]) -> String {
    const MAX_DISPLAYED: usize = 4;
    let mut rendered = issues
        .iter()
        .take(MAX_DISPLAYED)
        .map(|issue| {
            format!(
                "{} at {}:{}",
                issue.kind, issue.span.line, issue.span.column
            )
        })
        .collect::<Vec<_>>();
    if issues.len() > MAX_DISPLAYED {
        rendered.push(format!("and {} more", issues.len() - MAX_DISPLAYED));
    }
    rendered.join(", ")
}
