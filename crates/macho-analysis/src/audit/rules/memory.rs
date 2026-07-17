use crate::audit::AuditInput;
use crate::audit::{AuditFinding, AuditRule, AuditSeverity};

pub struct WritableExecutableSegment;

impl AuditRule for WritableExecutableSegment {
    fn id(&self) -> &'static str {
        "MEM001"
    }

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        for seg in slice.segments() {
            // Check both init_prot and max_prot. A segment with max_prot=rwx
            // can be made W+X at runtime via mprotect even if init_prot is safe.
            for (prot_field, prot) in [("init_prot", &seg.init_prot), ("max_prot", &seg.max_prot)] {
                if prot.contains('w') && prot.contains('x') {
                    findings.push(AuditFinding {
                        rule_id: self.id().to_owned(),
                        severity: AuditSeverity::Critical,
                        title: format!(
                            "segment {} is writable and executable ({})",
                            seg.name, prot_field
                        ),
                        body: "W+X memory regions defeat DEP/NX protections and are \
                               a common exploitation primitive."
                            .into(),
                        evidence: vec![format!(
                            "segment={} {}={} vm_addr={:#x}",
                            seg.name, prot_field, prot, seg.vm_addr
                        )],
                        remediation: Some(
                            "Ensure segment permissions are either writable or executable, \
                             not both"
                                .into(),
                        ),
                    });
                }
            }
        }
    }
}

pub struct MissingPie;

impl AuditRule for MissingPie {
    fn id(&self) -> &'static str {
        "MEM002"
    }

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        let Some(header) = slice.header() else {
            return;
        };
        if header.file_type != "MH_EXECUTE" {
            return;
        }
        if !header.flags.iter().any(|f| f == "PIE") {
            findings.push(AuditFinding {
                rule_id: self.id().to_owned(),
                severity: AuditSeverity::Error,
                title: "executable not built as PIE".into(),
                body: "Position-Independent Executables enable ASLR, which is a \
                       critical exploit mitigation."
                    .into(),
                evidence: vec!["MH_PIE flag not set in header".into()],
                remediation: Some("Link with `-pie` or use a modern Xcode toolchain".into()),
            });
        }
    }
}

pub struct AllowStackExecution;

impl AuditRule for AllowStackExecution {
    fn id(&self) -> &'static str {
        "MEM003"
    }

    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>) {
        let Some(header) = slice.header() else {
            return;
        };
        if header.flags.iter().any(|f| f == "ALLOW_STACK_EXECUTION") {
            findings.push(AuditFinding {
                rule_id: self.id().to_owned(),
                severity: AuditSeverity::Critical,
                title: "binary allows stack execution".into(),
                body: "The MH_ALLOW_STACK_EXECUTION flag disables NX on the stack, \
                       enabling stack-based code execution attacks."
                    .into(),
                evidence: vec!["MH_ALLOW_STACK_EXECUTION flag set".into()],
                remediation: Some("Remove the -allow_stack_execute linker flag".into()),
            });
        }
    }
}
