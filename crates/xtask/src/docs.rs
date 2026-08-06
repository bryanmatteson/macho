use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use syn::visit::{self, Visit};
use walkdir::WalkDir;

const BEGIN: &str = "<!-- BEGIN MACHO COMMAND REFERENCE -->";
const END: &str = "<!-- END MACHO COMMAND REFERENCE -->";

pub fn check(root: &Path) -> Result<()> {
    let readme_path = root.join("README.md");
    let readme = fs::read_to_string(&readme_path).context("read README.md")?;
    let expected = generated_reference();
    let committed = marked_region(&readme)?;
    if committed != expected {
        bail!(
            "README command reference is stale; regenerate the marked region from the live router"
        );
    }
    check_examples(&readme)?;
    check_diagnostic_registry(root)?;
    println!("docs: ok");
    Ok(())
}

pub fn generated_reference() -> String {
    let command = macho::cli::clap_command();
    let mut rows = Vec::new();
    for subcommand in command.get_subcommands() {
        rows.push(format!(
            "| `{}` | {} |",
            subcommand.get_name(),
            subcommand
                .get_about()
                .map(|value| value.to_string())
                .unwrap_or_default()
        ));
    }
    format!(
        "{BEGIN}\n| Command | Purpose |\n| --- | --- |\n{}\n{END}",
        rows.join("\n")
    )
}

fn marked_region(readme: &str) -> Result<String> {
    let start = readme
        .find(BEGIN)
        .context("README is missing command-reference begin marker")?;
    let end = readme
        .find(END)
        .context("README is missing command-reference end marker")?
        + END.len();
    Ok(readme[start..end].to_string())
}

fn check_examples(readme: &str) -> Result<()> {
    for line in readme.lines().map(str::trim) {
        if !line.starts_with("macho ") || line.ends_with('\\') {
            continue;
        }
        let args = shell_words(line)?;
        if args.iter().any(|arg| arg.starts_with('<')) {
            continue;
        }
        macho::cli::parse_only(args.into_iter().map(OsString::from))
            .with_context(|| format!("README example is rejected by the live router: {line}"))?;
    }
    Ok(())
}

fn shell_words(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in line.chars() {
        match (quote, ch) {
            (Some(active), value) if value == active => quote = None,
            (Some(_), value) => current.push(value),
            (None, '\'' | '"') => quote = Some(ch),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            (None, value) => current.push(value),
        }
    }
    anyhow::ensure!(
        quote.is_none(),
        "unterminated quote in README command: {line}"
    );
    if !current.is_empty() {
        words.push(current);
    }
    Ok(words)
}

fn check_diagnostic_registry(root: &Path) -> Result<()> {
    let registry_path = root.join("docs/diagnostic-codes.md");
    let registry = fs::read_to_string(&registry_path)
        .with_context(|| format!("read {}", registry_path.display()))?;
    let mut declared = BTreeMap::<String, Vec<String>>::new();
    for entry in WalkDir::new(root.join("crates"))
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "target")
    {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension().and_then(|s| s.to_str()) != Some("rs")
        {
            continue;
        }
        let source = fs::read_to_string(entry.path())?;
        for code in extract_codes(&source)
            .with_context(|| format!("parse diagnostic constants in {}", entry.path().display()))?
        {
            declared
                .entry(code)
                .or_default()
                .push(entry.path().display().to_string());
        }
    }
    let mut registry_codes = BTreeMap::<String, usize>::new();
    for code in registry
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split('`').next())
    {
        *registry_codes.entry(code.to_owned()).or_default() += 1;
    }
    let mut errors = Vec::new();
    for (code, locations) in &declared {
        if locations.len() > 1 {
            errors.push(format!(
                "diagnostic code {code} is declared more than once: {}",
                locations.join(", ")
            ));
        }
        if registry_codes.get(code).copied() != Some(1) {
            errors.push(format!(
                "diagnostic code {code} must appear exactly once in docs/diagnostic-codes.md"
            ));
        }
    }
    for (code, count) in registry_codes {
        if count != 1 {
            errors.push(format!(
                "diagnostic code {code} appears {count} times in docs/diagnostic-codes.md"
            ));
        }
        if !declared.contains_key(&code) {
            errors.push(format!(
                "registry code {code} has no typed code constant in the workspace"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("\n"))
    }
}

fn extract_codes(source: &str) -> syn::Result<Vec<String>> {
    struct CodeCollector {
        codes: Vec<String>,
    }

    impl CodeCollector {
        fn collect(&mut self, name: &syn::Ident, expression: &syn::Expr) {
            let name = name.to_string();
            if name != "CODE" && !name.ends_with("_CODE") {
                return;
            }
            if let syn::Expr::Lit(expression) = expression
                && let syn::Lit::Str(value) = &expression.lit
            {
                self.codes.push(value.value());
            }
        }
    }

    impl<'ast> Visit<'ast> for CodeCollector {
        fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
            self.collect(&item.ident, &item.expr);
            visit::visit_item_const(self, item);
        }

        fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
            self.collect(&item.ident, &item.expr);
            visit::visit_impl_item_const(self, item);
        }
    }

    let syntax = syn::parse_file(source)?;
    let mut collector = CodeCollector { codes: Vec::new() };
    collector.visit_file(&syntax);
    Ok(collector.codes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_reference_contains_live_commands() {
        let generated = generated_reference();
        assert!(generated.contains("| `info` |"));
        assert!(generated.contains("| `cache` |"));
    }

    #[test]
    fn extracts_typed_codes() {
        assert_eq!(
            extract_codes("const INVALID_HEADER_CODE: &str = \"parse.header.invalid\";").unwrap(),
            vec!["parse.header.invalid".to_string()]
        );
    }

    #[test]
    fn extracts_multiline_and_duplicate_code_constants() {
        let source = r#"
const FIRST_CODE: &str =
    "analysis.first.failed";
pub const CODE: &'static str = "analysis.first.failed";
"#;
        assert_eq!(
            extract_codes(source).unwrap(),
            vec![
                "analysis.first.failed".to_string(),
                "analysis.first.failed".to_string(),
            ]
        );
    }
}
