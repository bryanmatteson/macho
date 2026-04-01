use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::header_infer::schema::EvidenceBundle;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub valid: bool,
    #[serde(default)]
    pub syntax_checked: bool,
    #[serde(default)]
    pub syntax_ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<ValidationIssue>,
}

pub trait ModelOutputValidator {
    fn is_syntax_validator(&self) -> bool {
        false
    }

    fn validate(
        &self,
        bundle: &EvidenceBundle,
        output: &crate::header_infer::ModelOutput,
        header_text: &str,
    ) -> crate::Result<Vec<ValidationIssue>>;
}

#[derive(Debug, Default)]
pub struct OutputContractValidator;

impl ModelOutputValidator for OutputContractValidator {
    fn validate(
        &self,
        _bundle: &EvidenceBundle,
        output: &crate::header_infer::ModelOutput,
        _header_text: &str,
    ) -> crate::Result<Vec<ValidationIssue>> {
        let mut issues = Vec::new();

        if output.header_name.trim().is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                code: "HI007".into(),
                message: "header_name must not be empty".into(),
                entity_id: None,
            });
        }

        let mut seen_decl_entities = BTreeSet::new();
        for decl in &output.declarations {
            if decl.label.trim().is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: "HI008".into(),
                    message: "declaration label must not be empty".into(),
                    entity_id: decl.entity_id.clone(),
                });
            }
            if decl.code.trim().is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: "HI009".into(),
                    message: "declaration code must not be empty".into(),
                    entity_id: decl.entity_id.clone(),
                });
            }
            if let Some(entity_id) = decl.entity_id.as_deref()
                && !seen_decl_entities.insert(entity_id)
            {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    code: "HI010".into(),
                    message: format!("multiple declarations emitted for entity '{entity_id}'"),
                    entity_id: Some(entity_id.to_string()),
                });
            }
        }

        for unresolved in &output.unresolved {
            if unresolved.reason.trim().is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: "HI011".into(),
                    message: "unresolved reason must not be empty".into(),
                    entity_id: Some(unresolved.entity_id.clone()),
                });
            }
        }

        Ok(issues)
    }
}

#[derive(Debug, Default)]
pub struct EntityCoverageValidator;

impl ModelOutputValidator for EntityCoverageValidator {
    fn validate(
        &self,
        bundle: &EvidenceBundle,
        output: &crate::header_infer::ModelOutput,
        _header_text: &str,
    ) -> crate::Result<Vec<ValidationIssue>> {
        let known_entities: BTreeSet<&str> = bundle
            .entities
            .iter()
            .map(|entity| entity.id.as_str())
            .collect();
        let declared_entities: BTreeSet<&str> = output
            .declarations
            .iter()
            .filter_map(|decl| decl.entity_id.as_deref())
            .collect();
        let unresolved_entities: BTreeSet<&str> = output
            .unresolved
            .iter()
            .map(|unresolved| unresolved.entity_id.as_str())
            .collect();

        let mut issues = Vec::new();

        for decl in &output.declarations {
            if let Some(entity_id) = decl.entity_id.as_deref() {
                if !known_entities.contains(entity_id) {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Error,
                        code: "HI001".into(),
                        message: format!("declaration references unknown entity '{entity_id}'"),
                        entity_id: Some(entity_id.to_string()),
                    });
                }
            }

            for reference in &decl.references {
                if bundle.fact(reference).is_none() && bundle.entity(reference).is_none() {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Warning,
                        code: "HI002".into(),
                        message: format!(
                            "declaration references unknown fact or entity '{reference}'"
                        ),
                        entity_id: decl.entity_id.clone(),
                    });
                }
            }
        }

        for dependency in &output.dependencies {
            if !known_entities.contains(dependency.as_str()) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    code: "HI003".into(),
                    message: format!("dependency references unknown entity '{dependency}'"),
                    entity_id: Some(dependency.clone()),
                });
            }
        }

        for unresolved in &output.unresolved {
            if !known_entities.contains(unresolved.entity_id.as_str()) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: "HI004".into(),
                    message: format!(
                        "unresolved entry references unknown entity '{}'",
                        unresolved.entity_id
                    ),
                    entity_id: Some(unresolved.entity_id.clone()),
                });
            }
        }

        for required in bundle.required_entity_ids() {
            if !declared_entities.contains(required) && !unresolved_entities.contains(required) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    code: "HI005".into(),
                    message: format!(
                        "required entity '{required}' is neither declared nor marked unresolved"
                    ),
                    entity_id: Some(required.to_string()),
                });
            }
        }

        Ok(issues)
    }
}

#[derive(Debug, Default)]
pub struct ClangSyntaxValidator;

impl ModelOutputValidator for ClangSyntaxValidator {
    fn is_syntax_validator(&self) -> bool {
        true
    }

    fn validate(
        &self,
        bundle: &EvidenceBundle,
        _output: &crate::header_infer::ModelOutput,
        header_text: &str,
    ) -> crate::Result<Vec<ValidationIssue>> {
        let header_path = temp_path("header-infer", "h");
        std::fs::write(&header_path, header_text)
            .map_err(|err| crate::Error::Validation(format!("write temp header: {err}")))?;

        let output = Command::new("clang")
            .arg("-x")
            .arg(bundle.header_unit.language.clang_language())
            .arg(format!("-std={}", bundle.header_unit.language.clang_std()))
            .arg("-fsyntax-only")
            .arg(OsStr::new(&header_path))
            .output()
            .map_err(|err| crate::Error::Validation(format!("run clang: {err}")))?;

        let _ = std::fs::remove_file(&header_path);

        if output.status.success() {
            return Ok(Vec::new());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok(vec![ValidationIssue {
            severity: ValidationSeverity::Error,
            code: "HI006".into(),
            message: if stderr.is_empty() {
                "clang syntax validation failed".into()
            } else {
                format!("clang syntax validation failed: {stderr}")
            },
            entity_id: None,
        }])
    }
}

pub fn validate_output(
    bundle: &EvidenceBundle,
    output: &crate::header_infer::ModelOutput,
    validators: &[&dyn ModelOutputValidator],
) -> crate::Result<ValidationReport> {
    let header_text = crate::header_infer::render_header(output);
    let mut issues = Vec::new();
    let mut seen_issues = BTreeSet::new();
    let mut syntax_checked = false;
    let mut syntax_ok = true;

    let contract = OutputContractValidator;
    let coverage = EntityCoverageValidator;
    let builtins: [&dyn ModelOutputValidator; 2] = [&contract, &coverage];

    for validator in builtins.into_iter().chain(validators.iter().copied()) {
        if validator.is_syntax_validator() {
            syntax_checked = true;
        }
        let mut validator_issues = validator.validate(bundle, output, &header_text)?;
        if validator.is_syntax_validator() && !validator_issues.is_empty() {
            syntax_ok = false;
        }
        for issue in validator_issues.drain(..) {
            let key = (
                issue.severity,
                issue.code.clone(),
                issue.message.clone(),
                issue.entity_id.clone(),
            );
            if seen_issues.insert(key) {
                issues.push(issue);
            }
        }
    }

    Ok(ValidationReport {
        valid: !issues
            .iter()
            .any(|issue| issue.severity == ValidationSeverity::Error),
        syntax_checked,
        syntax_ok,
        issues,
    })
}

fn temp_path(prefix: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{prefix}-{nanos}.{ext}"))
}
