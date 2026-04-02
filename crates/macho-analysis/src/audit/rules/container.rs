use crate::audit::{AuditFinding, AuditRule, AuditSeverity};
use crate::snapshot::SliceSnapshot;

pub struct MissingPagezero;

impl AuditRule for MissingPagezero {
    fn id(&self) -> &'static str {
        "CTR001"
    }

    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>) {
        if slice.header.file_type != "MH_EXECUTE" {
            return;
        }

        let has_pagezero = slice
            .segments
            .iter()
            .any(|s| s.name == "__PAGEZERO" && s.vm_size > 0);

        if !has_pagezero {
            findings.push(AuditFinding {
                rule_id: self.id(),
                severity: AuditSeverity::Warning,
                title: "executable missing __PAGEZERO segment".into(),
                body: "__PAGEZERO maps the low address range as inaccessible, \
                       protecting against NULL pointer dereference exploits."
                    .into(),
                evidence: vec!["no __PAGEZERO segment found".into()],
                remediation: Some(
                    "Ensure the linker produces a __PAGEZERO segment (default for standard builds)"
                        .into(),
                ),
            });
        }
    }
}
