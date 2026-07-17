//! Delivery-owned host integrations for compilers and platform tools.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use macho::analysis::reconstruct::{
    EvidenceBundle, ModelOutput, ModelOutputValidator, ValidationIssue, ValidationSeverity,
};
use macho::header_infer::{
    CapabilityError, HeaderLanguage, HeaderValidator, SdkLocator, ValidationOutcome,
    ValidationRequest,
};
use macho::mutate::{SignatureProvider, SignatureProviderError, SignatureRequest};
use macho::swift::{SwiftDemangler, SwiftError};

/// Performs validate_c_header.
pub fn validate_c_header(source: &str) -> Result<()> {
    let path = temp_path("c-header", "h");
    std::fs::write(&path, source).context("write temporary C header")?;
    let output = Command::new("clang")
        .args(["-x", "c", "-fsyntax-only"])
        .arg(&path)
        .output()
        .or_else(|_| {
            Command::new("xcrun")
                .args(["clang", "-x", "c", "-fsyntax-only"])
                .arg(&path)
                .output()
        })
        .context("invoke clang for C header validation")?;
    let _ = std::fs::remove_file(&path);
    if !output.status.success() {
        bail!(
            "clang rejected rendered header: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Performs validate_cpp_header.
pub fn validate_cpp_header(path: &Path) -> Result<()> {
    let output = Command::new("xcrun")
        .arg("clang++")
        .arg("-std=c++17")
        .arg("-x")
        .arg("c++-header")
        .arg("-fsyntax-only")
        .arg(path)
        .output()
        .context("invoke clang++ for header validation")?;
    if !output.status.success() {
        bail!("{}", String::from_utf8_lossy(&output.stderr).trim());
    }
    Ok(())
}

/// `xcrun clang` implementation of both header validation contracts.
#[derive(Debug, Default)]
pub struct XcrunClangValidator;

impl ModelOutputValidator for XcrunClangValidator {
    fn is_syntax_validator(&self) -> bool {
        true
    }

    fn validate(
        &self,
        bundle: &EvidenceBundle,
        _output: &ModelOutput,
        header_text: &str,
    ) -> macho::analysis::Result<Vec<ValidationIssue>> {
        let path = temp_path("header-infer", "h");
        std::fs::write(&path, header_text).map_err(|error| {
            macho::analysis::AnalysisError::validation(format!("write temp header: {error}"))
        })?;
        let output = Command::new("clang")
            .arg("-x")
            .arg(bundle.header_unit.language.clang_language())
            .arg(format!("-std={}", bundle.header_unit.language.clang_std()))
            .arg("-fsyntax-only")
            .arg(OsStr::new(&path))
            .output()
            .map_err(|error| {
                macho::analysis::AnalysisError::validation(format!("run clang: {error}"))
            })?;
        let _ = std::fs::remove_file(&path);
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

impl HeaderValidator for XcrunClangValidator {
    fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> std::result::Result<ValidationOutcome, CapabilityError> {
        let path = temp_path("header-validator", "h");
        std::fs::write(&path, request.source).map_err(|error| CapabilityError::Malformed {
            capability: "clang",
            detail: error.to_string(),
        })?;
        let language = match request.language {
            HeaderLanguage::C => "c",
            HeaderLanguage::Cpp => "c++",
            HeaderLanguage::ObjectiveC => "objective-c",
            _ => {
                return Err(CapabilityError::Unavailable {
                    capability: "unknown header language",
                });
            }
        };
        let mut command = Command::new("xcrun");
        command.args(["clang", "-x", language, "-fsyntax-only"]);
        for root in request.include_roots {
            command.arg("-I").arg(root);
        }
        let output = command
            .arg(&path)
            .output()
            .map_err(|_| CapabilityError::Unavailable {
                capability: "xcrun clang",
            })?;
        let _ = std::fs::remove_file(&path);
        let diagnostics = String::from_utf8(output.stderr)
            .map_err(|error| CapabilityError::Malformed {
                capability: "clang",
                detail: error.to_string(),
            })?
            .lines()
            .map(str::to_owned)
            .collect();
        Ok(ValidationOutcome {
            accepted: output.status.success(),
            diagnostics,
        })
    }
}

/// `xcrun --show-sdk-path` include-root locator.
#[derive(Debug, Default)]
pub struct XcrunSdkLocator;

impl SdkLocator for XcrunSdkLocator {
    fn include_roots(
        &self,
        _language: HeaderLanguage,
    ) -> std::result::Result<Vec<PathBuf>, CapabilityError> {
        let output = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .map_err(|_| CapabilityError::Unavailable {
                capability: "xcrun sdk locator",
            })?;
        if !output.status.success() {
            return Err(CapabilityError::Unavailable {
                capability: "macOS SDK",
            });
        }
        let root =
            String::from_utf8(output.stdout).map_err(|error| CapabilityError::Malformed {
                capability: "xcrun sdk locator",
                detail: error.to_string(),
            })?;
        let root = PathBuf::from(root.trim());
        Ok(vec![
            root.join("usr/include"),
            root.join("System/Library/Frameworks"),
        ])
    }
}

/// `xcrun swift-demangle` adapter.
#[derive(Debug, Default)]
pub struct XcrunSwiftDemangler;

impl SwiftDemangler for XcrunSwiftDemangler {
    fn demangle(&self, symbol: &str) -> std::result::Result<Option<String>, SwiftError> {
        let output = Command::new("xcrun")
            .args(["swift-demangle", "--compact", symbol])
            .output()
            .map_err(|_| SwiftError::unsupported("xcrun swift-demangle is unavailable"))?;
        if !output.status.success() {
            return Err(SwiftError::unsupported(format!(
                "swift-demangle exited with {}",
                output.status
            )));
        }
        let value = String::from_utf8(output.stdout).map_err(|error| {
            SwiftError::format(format!("invalid swift-demangle output: {error}"))
        })?;
        let value = value.trim();
        Ok((!value.is_empty() && value != symbol).then(|| value.to_owned()))
    }
}

/// Host-backed `codesign` adapter operating through a private temporary file.
#[derive(Debug, Default)]
pub struct HostSignatureProvider;

impl SignatureProvider for HostSignatureProvider {
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
        let path = temp_path("codesign", "bin");
        std::fs::write(&path, bytes)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        let identity = request.identity.as_deref().unwrap_or("-");
        let output = Command::new("xcrun")
            .args(["codesign", "-f", "-s", identity])
            .arg(&path)
            .output()
            .map_err(|_| SignatureProviderError::Unavailable("xcrun codesign".into()))?;
        if !output.status.success() {
            let _ = std::fs::remove_file(&path);
            return Err(SignatureProviderError::Failed(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let signed = std::fs::read(&path)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        let _ = std::fs::remove_file(&path);
        Ok(signed)
    }
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("macho-{prefix}-{nanos}.{extension}"))
}
