mod codesign;
mod container;
mod load_paths;
mod memory;

use super::AuditRule;

pub fn all_rules() -> Vec<Box<dyn AuditRule>> {
    vec![
        Box::new(codesign::UnreadableCodeSignature),
        Box::new(codesign::UnsignedBinary),
        Box::new(codesign::MissingEntitlements),
        Box::new(codesign::WeakHashAlgorithm),
        Box::new(codesign::MissingTeamId),
        Box::new(codesign::SuspiciousEntitlements),
        Box::new(load_paths::AbsoluteRpath),
        Box::new(load_paths::RelativeRpath),
        Box::new(load_paths::AbsoluteDylibPath),
        Box::new(load_paths::WritableLocationDylib),
        Box::new(memory::WritableExecutableSegment),
        Box::new(memory::MissingPie),
        Box::new(memory::AllowStackExecution),
        Box::new(container::MissingPagezero),
    ]
}
