use macho::edit::resign::ResignPlan;
use macho::edit::transaction::PatchTransaction;
use macho::model::container::MachContainer;

#[test]
fn resign_plan_for_signed_binary() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };

    let plan = ResignPlan::from_mach(mach);
    assert!(plan.was_signed);
    assert!(plan.identifier.is_some());
    assert!(plan.hash_type.is_some());
    assert!(plan.has_cms_signature);
    assert!(plan.suggested_command.contains("codesign"));
}

#[test]
fn resign_plan_includes_identifier_in_command() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };

    let plan = ResignPlan::from_mach(mach);
    if let Some(ref id) = plan.identifier {
        assert!(
            plan.suggested_command.contains(id),
            "suggested command should include the identifier"
        );
    }
}

#[test]
fn resign_plan_serializes() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };

    let plan = ResignPlan::from_mach(mach);
    let json = serde_json::to_string(&plan).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed["was_signed"], true);
}

#[test]
fn resign_plan_display() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };

    let plan = ResignPlan::from_mach(mach);
    let display = format!("{plan}");
    assert!(display.contains("Re-sign assistance:"));
    assert!(display.contains("codesign"));
}

#[test]
fn resign_plan_for_unsigned_binary_is_explicit() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };

    let mut txn = PatchTransaction::new(mach);
    txn.remove_code_signature();
    let bytes = txn.commit().expect("commit");
    let reparsed = macho::parse(&bytes).expect("reparse");
    let unsigned = reparsed.first_mach();

    let plan = ResignPlan::from_mach(unsigned);
    assert!(!plan.was_signed);
    assert!(plan.identifier.is_none());
    assert!(!plan.has_cms_signature);
    assert!(format!("{plan}").contains("no re-signing needed"));
}
