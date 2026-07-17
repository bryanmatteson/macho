#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TempBinaryFixture {
    path: PathBuf,
}

pub struct CliStatus(u8);

impl CliStatus {
    pub fn success(&self) -> bool {
        self.0 == 0
    }
}

pub struct CliOutput {
    pub status: CliStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl TempBinaryFixture {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempBinaryFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub fn temp_file_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{name}-{nanos}.bin"))
}

pub fn copy_macho_fixture(source: &str, name: &str) -> TempBinaryFixture {
    let path = temp_file_path(name);
    std::fs::copy(source, &path).unwrap_or_else(|err| {
        panic!(
            "failed to copy fixture {source} to {}: {err}",
            path.display()
        )
    });
    let permissions = std::fs::metadata(source)
        .unwrap_or_else(|err| panic!("failed to read metadata for fixture {source}: {err}"))
        .permissions();
    std::fs::set_permissions(&path, permissions).unwrap_or_else(|err| {
        panic!(
            "failed to preserve permissions for fixture copy {}: {err}",
            path.display()
        )
    });
    TempBinaryFixture { path }
}

pub fn run_cli<I, S>(args: I) -> CliOutput
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let argv: Vec<String> = args
        .into_iter()
        .map(|arg| arg.as_ref().to_owned())
        .collect();
    let output = macho_cli::run_captured(argv.iter().map(String::as_str));

    CliOutput {
        status: CliStatus(output.code),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}
