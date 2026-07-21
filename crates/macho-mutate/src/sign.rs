//! In-process code signing for Mach-O binaries.
//!
//! Signing is a bytes-in/bytes-out capability. Providers never choose paths,
//! discover host tools, launch processes, or perform network operations.

use apple_codesign::cryptography::{InMemoryPrivateKey, parse_pfx_data};
use apple_codesign::{
    MachFile, MachOSigner, SettingsScope, SigningSettings, VerificationProblemType,
    verify_macho_data,
};
use x509_certificate::CapturedX509Certificate;

/// Per-binary metadata supplied to an injected signing capability.
///
/// Signing key material belongs to the provider so requests remain safe to
/// inspect, clone, and include in workflow diagnostics.
#[derive(Debug, Clone, Default)]
pub struct SignatureRequest {
    /// Optional bundle identifier override.
    pub identifier: Option<String>,
    /// Optional XML property-list entitlements override.
    pub entitlements_xml: Option<String>,
}

/// The kind of signature produced by a signing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureKind {
    /// A digest-only ad-hoc signature without a CMS signature.
    AdHoc,
    /// A certificate-backed signature containing CMS data.
    Certificate,
    /// A signature whose mechanism is intentionally hidden by an external
    /// provider.
    Opaque,
}

impl std::fmt::Display for SignatureKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AdHoc => "ad-hoc",
            Self::Certificate => "certificate",
            Self::Opaque => "opaque",
        })
    }
}

/// Typed signing capability failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureProviderError {
    /// The configured signing capability is unavailable.
    #[error("signing capability unavailable: {0}")]
    Unavailable(String),
    /// Explicit credential material could not be loaded or parsed.
    #[error("invalid signing credentials: {0}")]
    InvalidCredentials(String),
    /// Signing rejected the candidate bytes or settings.
    #[error("signing failed: {0}")]
    Failed(String),
    /// The produced signature failed in-process integrity verification.
    #[error("signed output failed verification: {0}")]
    VerificationFailed(String),
}

/// Injectable signing provider. Implementations never choose output paths.
///
/// External services, hardware tokens, and other adapters may omit
/// [`kind`](Self::kind); they are reported as producing an opaque signature.
/// Implementations remain responsible for returning bytes whose signature has
/// passed their own integrity checks.
pub trait SignatureProvider: Send + Sync {
    /// Return a signed replacement buffer without modifying the input.
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError>;

    /// Describe the signature produced by this provider.
    fn kind(&self) -> SignatureKind {
        SignatureKind::Opaque
    }
}

struct CertificateIdentity {
    certificate: CapturedX509Certificate,
    private_key: InMemoryPrivateKey,
}

/// Pure in-process Mach-O signing provider.
///
/// The provider is configured as either ad-hoc or certificate-backed. PKCS#12
/// passwords are consumed during construction and are not retained.
pub struct InProcessSignatureProvider {
    identity: Option<CertificateIdentity>,
}

impl InProcessSignatureProvider {
    /// Construct an ad-hoc signing provider.
    pub const fn adhoc() -> Self {
        Self { identity: None }
    }

    /// Construct a certificate-backed provider from PKCS#12/PFX bytes.
    pub fn from_pkcs12(
        bytes: &[u8],
        password: &str,
    ) -> std::result::Result<Self, SignatureProviderError> {
        let (certificate, private_key) = parse_pfx_data(bytes, password)
            .map_err(|error| SignatureProviderError::InvalidCredentials(error.to_string()))?;
        Ok(Self {
            identity: Some(CertificateIdentity {
                certificate,
                private_key,
            }),
        })
    }

    /// Validate request metadata without signing a binary.
    ///
    /// Delivery layers use this to reject malformed entitlement XML before
    /// mutation work begins. Binary-dependent settings are still validated
    /// during signing.
    pub fn validate_request(
        &self,
        request: &SignatureRequest,
    ) -> std::result::Result<(), SignatureProviderError> {
        if let Some(entitlements_xml) = &request.entitlements_xml {
            SigningSettings::default()
                .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        }
        Ok(())
    }

    fn configure_settings<'key>(
        &'key self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<SigningSettings<'key>, SignatureProviderError> {
        self.validate_request(request)?;
        let mut settings = SigningSettings::default();

        if let Some(identity) = &self.identity {
            settings.set_signing_key(&identity.private_key, identity.certificate.clone());
            settings.chain_apple_certificates();
            settings.set_team_id_from_signing_certificate();
        }

        if let Some(identifier) = &request.identifier {
            settings.set_binary_identifier(SettingsScope::Main, identifier);
        }
        if let Some(entitlements_xml) = &request.entitlements_xml {
            settings
                .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        }

        // Explicit request settings above take precedence. Everything else is
        // imported so re-signing conserves the existing binary's metadata.
        settings
            .import_settings_from_macho(bytes)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;

        if settings.binary_identifier(SettingsScope::Main).is_none() {
            if self.identity.is_some() {
                return Err(SignatureProviderError::Failed(
                    "certificate signing an unidentified binary requires an explicit identifier"
                        .to_string(),
                ));
            }
            settings.set_binary_identifier(SettingsScope::Main, "adhoc-signed");
        }

        Ok(settings)
    }
}

impl Default for InProcessSignatureProvider {
    fn default() -> Self {
        Self::adhoc()
    }
}

impl SignatureProvider for InProcessSignatureProvider {
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
        let settings = self.configure_settings(bytes, request)?;
        let signer = MachOSigner::new(bytes)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        let mut signed = Vec::new();
        signer
            .write_signed_binary(&settings, &mut signed)
            .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
        verify_signed_binary(&signed, self.kind())?;
        Ok(signed)
    }

    fn kind(&self) -> SignatureKind {
        if self.identity.is_some() {
            SignatureKind::Certificate
        } else {
            SignatureKind::AdHoc
        }
    }
}

/// Verify a signed Mach-O using the same digest and CMS model as the signing
/// backend.
///
/// An ad-hoc signature is expected to lack CMS data. Every other verification
/// problem is rejected for both signing modes.
pub fn verify_signed_binary(
    bytes: &[u8],
    kind: SignatureKind,
) -> std::result::Result<(), SignatureProviderError> {
    let permits_absent_cms = matches!(kind, SignatureKind::AdHoc | SignatureKind::Opaque);
    let empty_adhoc_cms = permits_absent_cms && all_cms_slots_are_empty(bytes);
    let problems = verify_macho_data(bytes)
        .into_iter()
        .filter(|problem| {
            let expected_absent_cms = permits_absent_cms
                && matches!(
                    &problem.problem,
                    VerificationProblemType::NoCryptographicSignature
                );
            // apple-codesign emits an empty BlobWrapper for ad-hoc signing.
            // Its high-level verifier attempts to parse that empty payload as
            // CMS and reports CmsError, while EmbeddedSignature::signed_data
            // correctly classifies the same payload as absent CMS. Only allow
            // the verifier's false-positive when every slice independently
            // proves it carries the canonical empty wrapper.
            let canonical_empty_wrapper =
                empty_adhoc_cms && matches!(&problem.problem, VerificationProblemType::CmsError(_));
            !(expected_absent_cms || canonical_empty_wrapper)
        })
        .map(|problem| problem.to_string())
        .collect::<Vec<_>>();

    if problems.is_empty() {
        Ok(())
    } else {
        Err(SignatureProviderError::VerificationFailed(
            problems.join("; "),
        ))
    }
}

fn all_cms_slots_are_empty(bytes: &[u8]) -> bool {
    let Ok(file) = MachFile::parse(bytes) else {
        return false;
    };
    let mut slice_count = 0usize;
    for macho in file.into_iter() {
        slice_count += 1;
        let Ok(Some(signature)) = macho.code_signature() else {
            return false;
        };
        let Ok(None) = signature.signed_data() else {
            return false;
        };
        let Ok(Some(raw_cms)) = signature.signature_data() else {
            return false;
        };
        if !raw_cms.is_empty() {
            return false;
        }
    }
    slice_count > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>"#;

    #[test]
    fn malformed_pkcs12_is_a_typed_credential_error() {
        let error = InProcessSignatureProvider::from_pkcs12(b"not a p12", "")
            .err()
            .expect("malformed credentials must fail");
        assert!(matches!(
            error,
            SignatureProviderError::InvalidCredentials(_)
        ));
    }

    #[test]
    fn wrong_pkcs12_password_is_a_typed_credential_error() {
        let error = InProcessSignatureProvider::from_pkcs12(
            &macho_test_support::test_signing_identity_pkcs12(),
            "wrong-password",
        )
        .err()
        .expect("wrong password must fail");
        assert!(matches!(
            error,
            SignatureProviderError::InvalidCredentials(_)
        ));
    }

    fn signed_fixture() -> Vec<u8> {
        let thin = macho_test_support::signable_thin64_x86_64(2);
        InProcessSignatureProvider::adhoc()
            .sign(&thin, &SignatureRequest::default())
            .expect("ad-hoc signing succeeds")
    }

    #[test]
    fn adhoc_signing_is_deterministic_and_verified() {
        for input in [
            macho_test_support::signable_thin64_x86_64(2),
            macho_test_support::signable_thin64_arm64(2),
        ] {
            let provider = InProcessSignatureProvider::adhoc();
            let first = provider
                .sign(&input, &SignatureRequest::default())
                .expect("first signing succeeds");
            let second = provider
                .sign(&input, &SignatureRequest::default())
                .expect("second signing succeeds");
            assert_eq!(first, second);
            verify_signed_binary(&first, SignatureKind::AdHoc).expect("signature verifies");
        }
    }

    #[test]
    fn covered_byte_tampering_is_rejected() {
        let mut signed = signed_fixture();
        let parsed = macho_core::parse(&signed).expect("parse signed output");
        let mach = parsed.first_macho().expect("contains a Mach-O slice");
        let signature = mach
            .ext::<macho_codesign::CodeSignature<'_>>()
            .expect("parse signature");
        let code_limit = signature
            .code_directories()
            .first()
            .expect("CodeDirectory")
            .code_limit as usize;
        let tamper_offset = code_limit.checked_sub(1).expect("nonempty code range");
        signed[tamper_offset] ^= 0x01;

        let error = verify_signed_binary(&signed, SignatureKind::AdHoc)
            .expect_err("covered-byte tampering must fail");
        assert!(error.to_string().contains("code digest mismatch"));
    }

    #[test]
    fn resigning_preserves_identifier_and_entitlements() {
        let provider = InProcessSignatureProvider::adhoc();
        let first = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest {
                    identifier: Some("dev.matteson.macho.fixture".into()),
                    entitlements_xml: Some(ENTITLEMENTS.into()),
                },
            )
            .expect("initial signing succeeds");
        let resigned = provider
            .sign(&first, &SignatureRequest::default())
            .expect("re-signing succeeds");
        let parsed = macho_core::parse(&resigned).expect("parse re-signed output");
        let signature = parsed
            .first_macho()
            .expect("contains Mach-O")
            .ext::<macho_codesign::CodeSignature<'_>>()
            .expect("parse signature");
        assert_eq!(signature.identifier(), Some("dev.matteson.macho.fixture"));
        assert!(
            signature
                .entitlements_xml()
                .is_some_and(|xml| xml.contains("com.apple.security.get-task-allow"))
        );
    }

    #[test]
    fn resigning_applies_explicit_identifier_and_entitlement_overrides() {
        let provider = InProcessSignatureProvider::adhoc();
        let first = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest {
                    identifier: Some("dev.matteson.macho.original".into()),
                    entitlements_xml: None,
                },
            )
            .expect("initial signing succeeds");
        let resigned = provider
            .sign(
                &first,
                &SignatureRequest {
                    identifier: Some("dev.matteson.macho.override".into()),
                    entitlements_xml: Some(ENTITLEMENTS.into()),
                },
            )
            .expect("re-signing with overrides succeeds");
        let parsed = macho_core::parse(&resigned).expect("parse re-signed output");
        let signature = parsed
            .first_macho()
            .expect("contains Mach-O")
            .ext::<macho_codesign::CodeSignature<'_>>()
            .expect("parse signature");
        assert_eq!(signature.identifier(), Some("dev.matteson.macho.override"));
        assert!(
            signature
                .entitlements_xml()
                .is_some_and(|xml| xml.contains("com.apple.security.get-task-allow"))
        );
    }

    #[test]
    fn universal_binary_signing_verifies_every_slice() {
        let input = macho_test_support::fat32(&[
            (
                macho_test_support::CPU_TYPE_X86_64,
                3,
                macho_test_support::signable_thin64_x86_64(2),
            ),
            (
                macho_test_support::CPU_TYPE_ARM64,
                0,
                macho_test_support::signable_thin64_arm64(2),
            ),
        ]);
        let signed = InProcessSignatureProvider::adhoc()
            .sign(&input, &SignatureRequest::default())
            .expect("universal signing succeeds");
        verify_signed_binary(&signed, SignatureKind::AdHoc).expect("all slices verify");
        assert_eq!(
            macho_core::parse(&signed)
                .expect("parse signed universal")
                .macho_files()
                .count(),
            2
        );
    }

    #[test]
    fn pkcs12_certificate_signing_produces_verified_cms() {
        let provider = InProcessSignatureProvider::from_pkcs12(
            &macho_test_support::test_signing_identity_pkcs12(),
            macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD,
        )
        .expect("parse test identity");
        let signed = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest {
                    identifier: Some("dev.matteson.macho.certificate-fixture".into()),
                    entitlements_xml: None,
                },
            )
            .expect("certificate signing succeeds");
        verify_signed_binary(&signed, SignatureKind::Certificate)
            .expect("certificate signature verifies");
        let parsed = macho_core::parse(&signed).expect("parse signed output");
        let signature = parsed
            .first_macho()
            .expect("contains Mach-O")
            .ext::<macho_codesign::CodeSignature<'_>>()
            .expect("parse signature");
        assert!(signature.cms_signature_present());
    }

    #[test]
    fn corrupted_nonempty_cms_is_rejected_in_both_modes() {
        // A populated-but-tampered CMS must never verify. The ad-hoc
        // empty-wrapper exception only forgives a canonical *empty* CMS
        // wrapper, so it must not rescue a non-empty, corrupted payload.
        let provider = InProcessSignatureProvider::from_pkcs12(
            &macho_test_support::test_signing_identity_pkcs12(),
            macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD,
        )
        .expect("parse test identity");
        let signed = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest {
                    identifier: Some("dev.matteson.macho.corrupt-cms".into()),
                    entitlements_xml: None,
                },
            )
            .expect("certificate signing succeeds");

        // Locate the populated CMS payload through the repository's own parser.
        let cms_payload = {
            let parsed = macho_core::parse(&signed).expect("parse signed output");
            let signature = parsed
                .first_macho()
                .expect("contains Mach-O")
                .ext::<macho_codesign::CodeSignature<'_>>()
                .expect("parse signature");
            signature
                .blobs()
                .iter()
                .find(|blob| blob.blob_type == macho_codesign::BlobType::Signature)
                .and_then(|blob| blob.data.get(8..))
                .filter(|payload| !payload.is_empty())
                .expect("certificate mode produces a non-empty CMS payload")
                .to_vec()
        };

        // Flip a byte inside the embedded CMS payload.
        let start = signed
            .windows(cms_payload.len())
            .position(|window| window == cms_payload.as_slice())
            .expect("locate CMS payload in signed bytes");
        let mut corrupted = signed.clone();
        corrupted[start + cms_payload.len() / 2] ^= 0xFF;

        // Certificate mode validates the CMS and must reject the tampered payload.
        verify_signed_binary(&corrupted, SignatureKind::Certificate)
            .expect_err("certificate mode must reject a corrupted CMS");
        // The ad-hoc empty-wrapper exception must not forgive a non-empty,
        // corrupted CMS payload.
        verify_signed_binary(&corrupted, SignatureKind::AdHoc)
            .expect_err("ad-hoc mode must also reject a non-empty corrupted CMS");
    }
}
