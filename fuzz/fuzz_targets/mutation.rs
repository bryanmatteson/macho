#![no_main]

use libfuzzer_sys::fuzz_target;
use macho::mutate::{PatchOp, PatchPlan, PatchTransaction};

fn run(data: &[u8]) -> Option<Vec<u8>> {
    let plan = PatchPlan::new(vec![PatchOp::PatchBytes {
        offset: 0,
        bytes: Vec::new(),
    }]);
    let container = macho::core::parse(data).ok()?;
    let image = container.first_macho()?;
    let mut transaction = PatchTransaction::new(image);
    transaction.add_op(plan.operations()[0].clone());
    let prepared = transaction.prepare().ok()?;
    assert!(macho::core::parse(&prepared.bytes).is_ok());
    Some(prepared.bytes)
}

fuzz_target!(|data: &[u8]| {
    let original = data.to_vec();
    let first = run(data);
    let second = run(data);
    assert_eq!(first, second);
    if first.is_none() {
        assert_eq!(data, original.as_slice());
    }
});
