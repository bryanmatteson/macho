//! The sole production host-process adapter: opt-in code signing.

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use macho::mutate::{SignatureProvider, SignatureProviderError, SignatureRequest};

/// Host-backed `codesign` adapter operating through a private temporary file.
#[derive(Debug, Default)]
pub struct HostSignatureProvider;

impl SignatureProvider for HostSignatureProvider {
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> Result<Vec<u8>, SignatureProviderError> {
        let path = temp_path("codesign", "bin");
        std::fs::write(&path, bytes)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        let identity = request.identity.as_deref().unwrap_or("-");
        let output = Command::new("xcrun")
            .args(["codesign", "-f", "-s", identity])
            .arg(&path)
            .output()
            .map_err(|_| SignatureProviderError::Unavailable("xcrun codesign".into()))?;
        if !output.status.success() {
            let _ = std::fs::remove_file(&path);
            return Err(SignatureProviderError::Failed(
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            ));
        }
        let signed = std::fs::read(&path)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        let _ = std::fs::remove_file(&path);
        Ok(signed)
    }
}

fn temp_path(prefix: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("macho-{prefix}-{nanos}.{extension}"))
}
