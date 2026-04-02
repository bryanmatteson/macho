use crate::audit::{AuditFinding, AuditRule, AuditSeverity};
use crate::snapshot::SliceSnapshot;

pub struct UnreadableCodeSignature;

impl AuditRule for UnreadableCodeSignature {
    fn id(&self) -> &'static str {
        "CS000"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        let has_codesign_load_command = slice
            .load_commands
            .iter()
            .any(|lc| lc.name == "LC_CODE_SIGNATURE");

        if !has_codesign_load_command || slice.codesign.is_some() {
            return;
        }

        for issue in slice
            .analysis_issues
            .iter()
            .filter(|issue| issue.component == "codesign")
        {
            findings.push(AuditFinding {
                rule_id: self.id(),
                severity: AuditSeverity::Error,
                title: "code signature data could not be analyzed".into(),
                body: "The binary advertises LC_CODE_SIGNATURE data, but the signature payload \
                       could not be parsed. Security findings derived from code-signing state are \
                       incomplete until the signature blob is fixed or re-signed."
                    .into(),
                evidence: vec![issue.message.clone()],
                remediation: Some(
                    "Rebuild or re-sign the binary so LC_CODE_SIGNATURE points to a valid signature blob".into(),
                ),
            });
        }
    }
}

pub struct UnsignedBinary;

impl AuditRule for UnsignedBinary {
    fn id(&self) -> &'static str {
        "CS001"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        // Only relevant for executables and dylibs
        let ft = &slice.header.file_type;
        if ft != "MH_EXECUTE" && ft != "MH_DYLIB" && ft != "MH_BUNDLE" {
            return;
        }
        let has_codesign_load_command = slice
            .load_commands
            .iter()
            .any(|lc| lc.name == "LC_CODE_SIGNATURE");
        if !has_codesign_load_command {
            findings.push(AuditFinding {
                rule_id: self.id(),
                severity: AuditSeverity::Error,
                title: "binary is not code-signed".into(),
                body: "Executables and dylibs should be code-signed for macOS \
                       Gatekeeper and notarization."
                    .into(),
                evidence: vec![format!("file_type={ft}, no LC_CODE_SIGNATURE")],
                remediation: Some("Sign with `codesign -s <identity> <binary>`".into()),
            });
        }
    }
}

pub struct MissingEntitlements;

impl AuditRule for MissingEntitlements {
    fn id(&self) -> &'static str {
        "CS002"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        if let Some(ref cs) = slice.codesign {
            if cs.has_cms_signature && !cs.has_entitlements {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: AuditSeverity::Info,
                    title: "signed binary has no entitlements".into(),
                    body: "The binary has a CMS signature but no entitlements blob. \
                           This is normal for many binaries but notable for app-store \
                           or sandbox-requiring contexts."
                        .into(),
                    evidence: vec!["CMS signature present, entitlements absent".into()],
                    remediation: None,
                });
            }
        }
    }
}

pub struct WeakHashAlgorithm;

impl AuditRule for WeakHashAlgorithm {
    fn id(&self) -> &'static str {
        "CS003"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        if let Some(ref cs) = slice.codesign {
            if cs.hash_type == "SHA-1" {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: AuditSeverity::Warning,
                    title: "code signature uses SHA-1".into(),
                    body: "SHA-1 is considered weak. Modern binaries should use SHA-256.".into(),
                    evidence: vec![format!("hash_type={}", cs.hash_type)],
                    remediation: Some("Re-sign with `--digest-algorithm=sha256`".into()),
                });
            }
        }
    }
}

pub struct SuspiciousEntitlements;

impl AuditRule for SuspiciousEntitlements {
    fn id(&self) -> &'static str {
        "CS005"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        let cs = match &slice.codesign {
            Some(cs) => cs,
            None => return,
        };
        if cs.entitlement_keys.is_empty() {
            return;
        }

        // Dangerous entitlement keys that weaken security posture
        let dangerous_keys: &[(&str, &str, AuditSeverity, bool)] = &[
            (
                "com.apple.security.cs.allow-jit",
                "allows JIT code generation, weakening code-signing guarantees",
                AuditSeverity::Warning,
                false,
            ),
            (
                "com.apple.security.cs.disable-library-validation",
                "disables library validation, allowing unsigned dylibs to be loaded",
                AuditSeverity::Error,
                false,
            ),
            (
                "com.apple.security.cs.allow-unsigned-executable-memory",
                "allows unsigned executable memory mappings",
                AuditSeverity::Error,
                false,
            ),
            (
                "com.apple.security.cs.disable-executable-page-protection",
                "disables executable page protection",
                AuditSeverity::Critical,
                false,
            ),
            (
                "com.apple.security.get-task-allow",
                "allows debugger attachment; should not ship in production builds",
                AuditSeverity::Warning,
                false,
            ),
            (
                "com.apple.private.",
                "uses private Apple entitlement prefix",
                AuditSeverity::Warning,
                true,
            ),
        ];

        for (key, description, severity, prefix_match) in dangerous_keys {
            let matched = if *prefix_match {
                cs.entitlement_keys
                    .iter()
                    .any(|candidate| candidate.starts_with(key))
            } else {
                cs.entitlement_keys.iter().any(|candidate| candidate == key)
            };

            if matched {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: *severity,
                    title: format!("suspicious entitlement: {key}"),
                    body: description.to_string(),
                    evidence: vec![format!("entitlements contain key: {key}")],
                    remediation: Some(format!(
                        "Review whether {key} is required; remove if not needed"
                    )),
                });
            }
        }
    }
}

pub struct MissingTeamId;

impl AuditRule for MissingTeamId {
    fn id(&self) -> &'static str {
        "CS004"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        if let Some(ref cs) = slice.codesign {
            if cs.team_id.is_none() && cs.has_cms_signature {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: AuditSeverity::Warning,
                    title: "signed binary missing team ID".into(),
                    body: "A CMS-signed binary without a team ID may fail notarization \
                           or Gatekeeper checks."
                        .into(),
                    evidence: vec!["CMS signature present, team_id absent".into()],
                    remediation: Some(
                        "Sign with a Developer ID certificate that includes a team ID".into(),
                    ),
                });
            }
        }
    }
}
