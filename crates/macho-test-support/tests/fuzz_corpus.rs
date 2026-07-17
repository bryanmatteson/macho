use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn committed_corpus_exactly_matches_shared_valid_and_invalid_fixtures() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("test-support crate is under <workspace>/crates")
        .join("fuzz/corpus");
    let mut expected_paths = BTreeSet::new();
    for case in macho_test_support::fuzz_corpus_cases() {
        let relative = PathBuf::from(case.target).join(case.name);
        expected_paths.insert(relative.clone());
        assert_eq!(
            fs::read(root.join(&relative)).expect("committed corpus entry"),
            case.bytes,
            "corpus entry {} drifted from its shared fixture",
            relative.display()
        );
    }

    let mut actual_paths = BTreeSet::new();
    for target in fs::read_dir(&root).expect("fuzz corpus directory") {
        let target = target.expect("target corpus entry");
        for entry in fs::read_dir(target.path()).expect("target corpus directory") {
            let entry = entry.expect("corpus entry");
            assert!(entry.file_type().expect("corpus entry type").is_file());
            actual_paths.insert(
                entry
                    .path()
                    .strip_prefix(&root)
                    .expect("corpus path under root")
                    .to_path_buf(),
            );
        }
    }
    assert_eq!(actual_paths, expected_paths);
}
