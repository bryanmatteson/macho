use macho_core::format::constants::{
    CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};
use macho_core::model::header::{ArchSpec, CpuSubtype, CpuType};

fn spec(cpu_type: i32, cpu_subtype: i32) -> ArchSpec {
    ArchSpec {
        cpu_type: CpuType(cpu_type),
        cpu_subtype: CpuSubtype(cpu_subtype),
    }
}

#[test]
fn family_and_qualified_architecture_selectors_have_distinct_scope() {
    let arm64 = spec(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    let arm64e = spec(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E);
    let x86_64 = spec(CPU_TYPE_X86_64, 3);

    assert!(arm64.matches_selector("arm64"));
    assert!(!arm64.matches_selector("arm64e"));
    assert!(arm64e.matches_selector("arm64"));
    assert!(arm64e.matches_selector("arm64e"));
    assert!(arm64e.matches_selector("ARM64E"));
    assert!(!x86_64.matches_selector("arm64"));

    let x86_64h = spec(
        CPU_TYPE_X86_64,
        macho_core::format::constants::CPU_SUBTYPE_X86_64_H,
    );
    assert_eq!(x86_64h.name(), "x86_64h");
    assert!(x86_64h.matches_selector("x86_64"));
    assert!(x86_64h.matches_selector("x86_64h"));
    assert!(!x86_64.matches_selector("x86_64h"));
}
