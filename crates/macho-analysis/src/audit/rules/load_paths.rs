use crate::audit::AuditInput;
use crate::audit::{AuditFinding, AuditRule, AuditSeverity};

/// Absolute path prefixes that are legitimate on modern macOS installations.
///
/// Flagging these produces alert fatigue on systems where developer tooling
/// is installed via Homebrew or MacPorts, or where Apple ships legitimate
/// libraries in `/Library`. The list is conservative: any path under these
/// prefixes is considered acceptable for rpath and dylib references.
const ACCEPTABLE_ABSOLUTE_PREFIXES: &[&str] = &[
    "/usr/lib",
    "/System",
    "/Library/Apple",
    "/Library/Frameworks",
    "/opt/homebrew",
    "/usr/local",
];

fn is_acceptable_absolute(path: &str) -> bool {
    ACCEPTABLE_ABSOLUTE_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Whether an @rpath-/@loader_path-/@executable_path-prefixed path uses
/// parent-directory traversal to escape its anchor. Paths like
/// `@loader_path/../../../private/tmp/evil.dylib` are syntactically legal but
/// commonly indicate a configuration bug or a deliberate escape attempt.
fn has_parent_traversal(path: &str) -> bool {
    path.split('/').any(|segment| segment == "..")
}

pub struct AbsoluteRpath;

impl AuditRule for AbsoluteRpath {
    fn id(&self) -> &'static str {
        "LP001"
    }

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        for lc in slice.load_commands() {
            if lc.name != "LC_RPATH" {
                continue;
            }
            let path = &lc.summary;
            if path.starts_with('/') && !is_acceptable_absolute(path) {
                findings.push(AuditFinding {
                    rule_id: self.id().to_owned(),
                    severity: AuditSeverity::Warning,
                    title: format!("absolute rpath outside common system directories: {path}"),
                    body: "Absolute rpaths that point outside well-known system or \
                           package-manager directories may break on other machines \
                           or indicate a build configuration issue."
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

/// LP005: warn on @rpath/@loader_path/@executable_path paths that use `..`
/// to climb out of the anchoring directory. These can bypass intended
/// isolation of bundled libraries and are a common dylib-hijack vector.
pub struct RpathTraversal;

impl AuditRule for RpathTraversal {
    fn id(&self) -> &'static str {
        "LP005"
    }

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        for lc in slice.load_commands() {
            let is_path_command = lc.name == "LC_RPATH" || is_dylib_path_command(&lc.name);
            if !is_path_command {
                continue;
            }
            let path = &lc.summary;
            let anchored = path.starts_with('@');
            if anchored && has_parent_traversal(path) {
                findings.push(AuditFinding {
                    rule_id: self.id().to_owned(),
                    severity: AuditSeverity::Warning,
                    title: format!("anchored path escapes its anchor via `..`: {path}"),
                    body: "An @rpath, @loader_path, or @executable_path reference that \
                           uses `..` can leave the bundle or framework directory and \
                           resolve to attacker-controlled locations."
                        .into(),
                    evidence: vec![format!("{}={path}", lc.name)],
                    remediation: Some(
                        "Rewrite the path to stay within the bundle, or use an \
                         absolute path into a trusted system directory."
                            .into(),
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

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        for lc in slice.load_commands() {
            if lc.name != "LC_RPATH" {
                continue;
            }
            let path = &lc.summary;
            // Relative path that doesn't use @-variables
            if !path.starts_with('/') && !path.starts_with('@') && !path.is_empty() {
                findings.push(AuditFinding {
                    rule_id: self.id().to_owned(),
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

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        for lc in slice.load_commands() {
            if !is_dylib_path_command(&lc.name) {
                continue;
            }
            let path = &lc.summary;
            if path.starts_with('/') && !is_acceptable_absolute(path) {
                findings.push(AuditFinding {
                    rule_id: self.id().to_owned(),
                    severity: AuditSeverity::Warning,
                    title: format!("dylib load path outside common system directories: {path}"),
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

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        let writable_prefixes = ["/tmp", "/var/tmp", "/Users/"];

        for lc in slice.load_commands() {
            if !is_dylib_path_command(&lc.name) && lc.name != "LC_RPATH" {
                continue;
            }
            let path = &lc.summary;
            for prefix in &writable_prefixes {
                if path.starts_with(prefix) {
                    findings.push(AuditFinding {
                        rule_id: self.id().to_owned(),
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
