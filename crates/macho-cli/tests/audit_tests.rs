use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use macho::analysis::analyzer::DomainObserver;
use macho::analysis::audit::AuditReport;
use macho::analysis::{
    AnalysisDomain, AnalysisError, Analyzer, AuditPlan, DomainPayload, DomainState,
};

#[derive(Default)]
struct Counter(Mutex<BTreeMap<AnalysisDomain, usize>>);

impl DomainObserver for Counter {
    fn before_domain(&self, domain: AnalysisDomain) -> Result<(), AnalysisError> {
        *self
            .0
            .lock()
            .expect("counter lock")
            .entry(domain)
            .or_default() += 1;
        Ok(())
    }
}

#[test]
fn disabled_audit_rules_do_not_expand_or_execute_their_domains() {
    let mut plan = AuditPlan::default();
    for spec in AuditPlan::rule_specs() {
        if spec.id != "MEM002" {
            plan = plan.excluding_rule(spec.id);
        }
    }
    let compiled = plan.compile();
    assert_eq!(
        compiled.domains(),
        &BTreeSet::from([AnalysisDomain::Header, AnalysisDomain::Audit])
    );

    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse");
    let counter = Counter::default();
    let document = Analyzer
        .run_with_observer(&container, &compiled, &counter)
        .expect("audit");
    assert_eq!(
        *counter.0.lock().expect("counter lock"),
        BTreeMap::from([(AnalysisDomain::Header, 1), (AnalysisDomain::Audit, 1)])
    );

    let DomainState::Complete {
        value: DomainPayload::Audit(value),
        ..
    } = &document.slices[0].domains[&AnalysisDomain::Audit]
    else {
        panic!("audit did not complete")
    };
    let report: AuditReport = serde_json::from_value(value.clone()).expect("audit report");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule_id == "MEM002")
    );
}
