use std::fs;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("test-support crate is under <workspace>/crates")
        .to_path_buf();
    let corpus = workspace.join("fuzz/corpus");
    if corpus.exists() {
        fs::remove_dir_all(&corpus)?;
    }
    for case in macho_test_support::fuzz_corpus_cases() {
        let directory = corpus.join(case.target);
        fs::create_dir_all(&directory)?;
        fs::write(directory.join(case.name), case.bytes)?;
    }
    Ok(())
}
