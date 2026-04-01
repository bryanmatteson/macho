use crate::analysis::audit::{AuditFinding, AuditRule, AuditSeverity};
use crate::analysis::snapshot::SliceSnapshot;

pub struct AbsoluteRpath;

impl AuditRule for AbsoluteRpath {
    fn id(&self) -> &'static str {
        "LP001"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        for lc in &slice.load_commands {
            if lc.name != "LC_RPATH" {
                continue;
            }
            let path = &lc.summary;
            if path.starts_with('/')
                && !path.starts_with("/usr/lib")
                && !path.starts_with("/System")
            {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: AuditSeverity::Warning,
                    title: format!("absolute rpath outside system directories: {path}"),
                    body: "Absolute rpaths that point outside /usr/lib or /System may \
                           break on other machines or indicate a build configuration issue."
                        .into(),
                    evidence: vec![format!("LC_RPATH={path}")],
                    remediation: Some(
                        "Use @executable_path, @loader_path, or @rpath-relative paths".into(),
                    ),
                });
            }
        }
    }
}

pub struct RelativeRpath;

impl AuditRule for RelativeRpath {
    fn id(&self) -> &'static str {
        "LP002"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        for lc in &slice.load_commands {
            if lc.name != "LC_RPATH" {
                continue;
            }
            let path = &lc.summary;
            // Relative path that doesn't use @-variables
            if !path.starts_with('/') && !path.starts_with('@') && !path.is_empty() {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: AuditSeverity::Error,
                    title: format!("relative rpath without @-prefix: {path}"),
                    body: "A relative rpath is resolved from the process working directory, \
                           which is unpredictable and a potential hijack vector."
                        .into(),
                    evidence: vec![format!("LC_RPATH={path}")],
                    remediation: Some(
                        "Use @executable_path/../Frameworks or @loader_path/... instead".into(),
                    ),
                });
            }
        }
    }
}

pub struct AbsoluteDylibPath;

impl AuditRule for AbsoluteDylibPath {
    fn id(&self) -> &'static str {
        "LP003"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        for lc in &slice.load_commands {
            if !is_dylib_path_command(&lc.name) {
                continue;
            }
            let path = &lc.summary;
            if path.starts_with('/')
                && !path.starts_with("/usr/lib")
                && !path.starts_with("/System")
            {
                findings.push(AuditFinding {
                    rule_id: self.id(),
                    severity: AuditSeverity::Warning,
                    title: format!("dylib load path outside system directories: {path}"),
                    body: "Loading dylibs from non-system absolute paths may fail on \
                           other machines or indicate a misconfigured build."
                        .into(),
                    evidence: vec![format!("{}={path}", lc.name)],
                    remediation: Some("Use @rpath-relative dylib references".into()),
                });
            }
        }
    }
}

pub struct WritableLocationDylib;

impl AuditRule for WritableLocationDylib {
    fn id(&self) -> &'static str {
        "LP004"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        let writable_prefixes = ["/tmp", "/var/tmp", "/Users/"];

        for lc in &slice.load_commands {
            if !is_dylib_path_command(&lc.name) && lc.name != "LC_RPATH" {
                continue;
            }
            let path = &lc.summary;
            for prefix in &writable_prefixes {
                if path.starts_with(prefix) {
                    findings.push(AuditFinding {
                        rule_id: self.id(),
                        severity: AuditSeverity::Critical,
                        title: format!("load path in writable location: {path}"),
                        body: "Loading code from a user-writable directory is a \
                               dylib hijacking risk."
                            .into(),
                        evidence: vec![format!("{}={path}", lc.name)],
                        remediation: Some(
                            "Remove or replace with a system or app-relative path".into(),
                        ),
                    });
                    break;
                }
            }
        }
    }
}

fn is_dylib_path_command(name: &str) -> bool {
    matches!(
        name,
        "LC_ID_DYLIB"
            | "LC_LOAD_DYLIB"
            | "LC_LOAD_WEAK_DYLIB"
            | "LC_REEXPORT_DYLIB"
            | "LC_LAZY_LOAD_DYLIB"
            | "LC_LOAD_UPWARD_DYLIB"
    )
}
