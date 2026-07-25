//! In-process and externally delegated code signing for Mach-O binaries.
//!
//! Signing is a bytes-in/bytes-out capability. Providers never choose paths,
//! discover host tools, launch processes, or perform network operations.

#[cfg(feature = "signing")]
use apple_codesign::cryptography::{InMemoryPrivateKey, parse_pfx_data};
#[cfg(feature = "signing")]
use apple_codesign::{
    MachFile, MachOSigner, SettingsScope, SigningSettings, VerificationProblemType,
    verify_macho_data,
};
#[cfg(feature = "signing")]
use bytes::Bytes;
#[cfg(feature = "signing")]
use sha2::{Digest, Sha256, Sha384};
#[cfg(feature = "signing")]
use signature::Signer;
#[cfg(feature = "signing")]
use x509_certificate::{
    CapturedX509Certificate, EcdsaCurve, KeyAlgorithm, Sign, Signature, SignatureAlgorithm,
};
#[cfg(feature = "signing")]
use zeroize::Zeroizing;

#[cfg(not(feature = "signing"))]
mod minimal;

/// Per-binary metadata supplied to an injected signing capability.
///
/// Signing key material belongs to the provider so requests remain safe to
/// inspect, clone, and include in workflow diagnostics.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SignatureRequest {
    /// Optional bundle identifier override.
    identifier: Option<String>,
    /// Optional XML property-list entitlements override.
    entitlements_xml: Option<String>,
}

impl SignatureRequest {
    /// Construct an empty signing request.
    pub const fn new() -> Self {
        Self {
            identifier: None,
            entitlements_xml: None,
        }
    }

    /// Set the bundle identifier override.
    pub fn with_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set the XML property-list entitlements override.
    pub fn with_entitlements_xml(mut self, entitlements_xml: impl Into<String>) -> Self {
        self.entitlements_xml = Some(entitlements_xml.into());
        self
    }

    /// Return the requested bundle identifier override.
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    /// Return the requested XML entitlements override.
    pub fn entitlements_xml(&self) -> Option<&str> {
        self.entitlements_xml.as_deref()
    }
}

/// The kind of signature produced by a signing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureKind {
    /// A digest-only ad-hoc signature without a CMS signature.
    AdHoc,
    /// A certificate-backed signature containing CMS data.
    Certificate,
    /// A signature whose mechanism is hidden by an external provider.
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

/// Pure ad-hoc signer that produces a deterministic digest-only signature.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdHocSignatureProvider;

impl SignatureProvider for AdHocSignatureProvider {
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
        #[cfg(not(feature = "signing"))]
        {
            minimal::sign_adhoc(bytes, request)
        }
        #[cfg(feature = "signing")]
        {
            let mut settings = SigningSettings::default();
            if let Some(identifier) = request.identifier() {
                settings.set_binary_identifier(SettingsScope::Main, identifier);
            }
            if let Some(entitlements_xml) = request.entitlements_xml() {
                settings
                    .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
                    .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            }
            settings
                .import_settings_from_macho(bytes)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            if settings.binary_identifier(SettingsScope::Main).is_none() {
                settings.set_binary_identifier(SettingsScope::Main, "adhoc-signed");
            }
            let signer = MachOSigner::new(bytes)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            let mut signed = Vec::new();
            signer
                .write_signed_binary(&settings, &mut signed)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            verify_signed_binary(&signed, SignatureKind::AdHoc)?;
            Ok(signed)
        }
    }

    fn kind(&self) -> SignatureKind {
        SignatureKind::AdHoc
    }
}

/// Opaque digest-signing capability used by external credential services.
///
/// Implementations expose public certificate material and accept only digests;
/// private key bytes never cross this boundary.
pub trait ExternalDigestSigner: Send + Sync {
    /// Stable public identity used to derive a fallback binary identifier.
    fn public_identity(&self) -> String;

    /// Supported algorithm names, ordered by provider preference.
    fn algorithms(&self) -> Vec<String>;

    /// DER-encoded certificate chain, with the leaf certificate first.
    fn certificate_chain(&self) -> Vec<Vec<u8>>;

    /// Sign a pre-hashed digest using the named algorithm.
    fn sign_digest(
        &self,
        algorithm: &str,
        digest: &[u8],
    ) -> std::result::Result<Vec<u8>, SignatureProviderError>;
}

/// Mach-O signature provider backed by an opaque external digest signer.
pub struct ExternalSignatureProvider<'provider> {
    signer: &'provider dyn ExternalDigestSigner,
}

impl<'provider> ExternalSignatureProvider<'provider> {
    /// Adapt an external digest signer to Mach-O bytes-in/bytes-out signing.
    pub const fn new(signer: &'provider dyn ExternalDigestSigner) -> Self {
        Self { signer }
    }
}

#[cfg(feature = "signing")]
struct ExternalKey<'provider> {
    signer: &'provider dyn ExternalDigestSigner,
    algorithm_name: &'static str,
    key_algorithm: KeyAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    public_key: Bytes,
}

#[cfg(feature = "signing")]
impl Signer<Signature> for ExternalKey<'_> {
    fn try_sign(&self, message: &[u8]) -> std::result::Result<Signature, signature::Error> {
        let digest = match self.signature_algorithm {
            SignatureAlgorithm::EcdsaSha384 => Sha384::digest(message).to_vec(),
            _ => Sha256::digest(message).to_vec(),
        };
        let signature = self
            .signer
            .sign_digest(self.algorithm_name, &digest)
            .map_err(|_| signature::Error::new())?;
        if signature.is_empty() {
            return Err(signature::Error::new());
        }
        Ok(Signature::from(signature))
    }
}

#[allow(deprecated)]
#[cfg(feature = "signing")]
impl Sign for ExternalKey<'_> {
    fn sign(
        &self,
        message: &[u8],
    ) -> std::result::Result<(Vec<u8>, SignatureAlgorithm), x509_certificate::X509CertificateError>
    {
        let signature = self
            .try_sign(message)
            .map_err(x509_certificate::X509CertificateError::from)?;
        Ok((signature.into(), self.signature_algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        Some(self.key_algorithm)
    }

    fn public_key_data(&self) -> Bytes {
        self.public_key.clone()
    }

    fn signature_algorithm(
        &self,
    ) -> std::result::Result<SignatureAlgorithm, x509_certificate::X509CertificateError> {
        Ok(self.signature_algorithm)
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        None
    }

    fn rsa_primes(
        &self,
    ) -> std::result::Result<
        Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>,
        x509_certificate::X509CertificateError,
    > {
        Ok(None)
    }
}

#[cfg(feature = "signing")]
impl x509_certificate::KeyInfoSigner for ExternalKey<'_> {}

#[cfg(feature = "signing")]
fn external_algorithm(
    algorithms: &[String],
    certificate: &CapturedX509Certificate,
) -> std::result::Result<(&'static str, KeyAlgorithm, SignatureAlgorithm), SignatureProviderError> {
    let key_algorithm = certificate.key_algorithm().ok_or_else(|| {
        SignatureProviderError::InvalidCredentials(
            "leaf certificate uses an unsupported public-key algorithm".to_string(),
        )
    })?;
    let candidates = match key_algorithm {
        KeyAlgorithm::Rsa => [
            Some(("rsa-pkcs1-sha256", SignatureAlgorithm::RsaSha256)),
            None,
        ],
        KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1) => [
            Some(("ecdsa-p256-sha256", SignatureAlgorithm::EcdsaSha256)),
            None,
        ],
        KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1) => [
            Some(("ecdsa-p384-sha384", SignatureAlgorithm::EcdsaSha384)),
            None,
        ],
        _ => [None, None],
    };
    candidates
        .into_iter()
        .flatten()
        .find(|(name, _)| algorithms.iter().any(|algorithm| algorithm == name))
        .map(|(name, signature)| (name, key_algorithm, signature))
        .ok_or_else(|| {
            SignatureProviderError::Unavailable(
                "external signer and leaf certificate have no compatible algorithm".to_string(),
            )
        })
}

impl SignatureProvider for ExternalSignatureProvider<'_> {
    fn sign(
        &self,
        bytes: &[u8],
        request: &SignatureRequest,
    ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
        #[cfg(not(feature = "signing"))]
        {
            minimal::sign_external(bytes, request, self.signer)
        }
        #[cfg(feature = "signing")]
        {
            let certificate_bytes = self.signer.certificate_chain();
            let mut certificates = certificate_bytes
                .iter()
                .map(|certificate| {
                    CapturedX509Certificate::from_der(certificate.clone()).map_err(|error| {
                        SignatureProviderError::InvalidCredentials(error.to_string())
                    })
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if certificates.is_empty() {
                return Err(SignatureProviderError::InvalidCredentials(
                    "external signer returned an empty certificate chain".to_string(),
                ));
            }
            let leaf = certificates.remove(0);
            let (algorithm_name, key_algorithm, signature_algorithm) =
                external_algorithm(&self.signer.algorithms(), &leaf)?;
            let key = ExternalKey {
                signer: self.signer,
                algorithm_name,
                key_algorithm,
                signature_algorithm,
                public_key: leaf.public_key_data(),
            };

            let mut settings = SigningSettings::default();
            settings.set_signing_key(&key, leaf);
            for certificate in certificates {
                settings.chain_certificate(certificate);
            }
            if let Some(identifier) = request.identifier() {
                settings.set_binary_identifier(SettingsScope::Main, identifier);
            }
            if let Some(entitlements_xml) = request.entitlements_xml() {
                settings
                    .set_entitlements_xml(SettingsScope::Main, entitlements_xml)
                    .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            }
            settings
                .import_settings_from_macho(bytes)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            if settings.binary_identifier(SettingsScope::Main).is_none() {
                let digest = Sha256::digest(self.signer.public_identity().as_bytes());
                let identity = digest
                    .iter()
                    .take(12)
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                settings.set_binary_identifier(SettingsScope::Main, format!("external.{identity}"));
            }

            let signer = MachOSigner::new(bytes)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            let mut signed = Vec::new();
            signer
                .write_signed_binary(&settings, &mut signed)
                .map_err(|error| SignatureProviderError::Failed(error.to_string()))?;
            verify_signed_binary(&signed, SignatureKind::Certificate)?;
            Ok(signed)
        }
    }

    fn kind(&self) -> SignatureKind {
        SignatureKind::Certificate
    }
}

#[cfg(feature = "signing")]
struct CertificateIdentity {
    certificate: CapturedX509Certificate,
    private_key: InMemoryPrivateKey,
}

/// Pure in-process Mach-O signing provider.
///
/// The provider is configured as either ad-hoc or certificate-backed. PKCS#12
/// passwords are consumed during construction and are not retained.
#[cfg(feature = "signing")]
pub struct InProcessSignatureProvider {
    identity: Option<CertificateIdentity>,
}

#[cfg(feature = "signing")]
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
        if let Some(entitlements_xml) = request.entitlements_xml() {
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

        if let Some(identifier) = request.identifier() {
            settings.set_binary_identifier(SettingsScope::Main, identifier);
        }
        if let Some(entitlements_xml) = request.entitlements_xml() {
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

#[cfg(feature = "signing")]
impl Default for InProcessSignatureProvider {
    fn default() -> Self {
        Self::adhoc()
    }
}

#[cfg(feature = "signing")]
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
/// Ad-hoc signatures may lack CMS data. Opaque signatures cannot be verified
/// by this generic verifier and must be checked by the provider that produced
/// them.
pub fn verify_signed_binary(
    bytes: &[u8],
    kind: SignatureKind,
) -> std::result::Result<(), SignatureProviderError> {
    #[cfg(not(feature = "signing"))]
    {
        minimal::verify_signed_binary(bytes, kind)
    }
    #[cfg(feature = "signing")]
    {
        if kind == SignatureKind::Opaque {
            return Err(SignatureProviderError::Unavailable(
                "opaque signatures must be verified by their signing provider".to_string(),
            ));
        }
        let permits_absent_cms = kind == SignatureKind::AdHoc;
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
                let canonical_empty_wrapper = empty_adhoc_cms
                    && matches!(&problem.problem, VerificationProblemType::CmsError(_));
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
}

#[cfg(feature = "signing")]
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

    struct EmptyExternalSigner;

    impl ExternalDigestSigner for EmptyExternalSigner {
        fn public_identity(&self) -> String {
            "test.empty".to_string()
        }

        fn algorithms(&self) -> Vec<String> {
            vec!["ecdsa-p256-sha256".to_string()]
        }

        fn certificate_chain(&self) -> Vec<Vec<u8>> {
            Vec::new()
        }

        fn sign_digest(
            &self,
            _algorithm: &str,
            _digest: &[u8],
        ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
            unreachable!("certificate validation must precede signing")
        }
    }

    #[test]
    fn external_signing_rejects_an_empty_certificate_chain_before_signing() {
        let provider = ExternalSignatureProvider::new(&EmptyExternalSigner);
        let error = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest::default(),
            )
            .expect_err("an external signer requires a leaf certificate");
        assert!(matches!(
            error,
            SignatureProviderError::InvalidCredentials(_)
        ));
    }

    #[cfg(not(feature = "signing"))]
    struct MinimalExternalSigner;

    #[cfg(not(feature = "signing"))]
    impl ExternalDigestSigner for MinimalExternalSigner {
        fn public_identity(&self) -> String {
            "test.minimal".to_string()
        }

        fn algorithms(&self) -> Vec<String> {
            vec!["ecdsa-p256-sha256".to_string()]
        }

        fn certificate_chain(&self) -> Vec<Vec<u8>> {
            // The feature-minimal encoder needs only the DER certificate's
            // issuer and serial fields; credential validation remains the
            // external provider's responsibility.
            vec![vec![
                0x30, 0x0f, // Certificate
                0x30, 0x0d, // TBSCertificate
                0x02, 0x01, 0x01, // serial
                0x30, 0x02, 0x06, 0x00, // signature algorithm
                0x30, 0x04, 0x31, 0x02, 0x30, 0x00, // issuer
            ]]
        }

        fn sign_digest(
            &self,
            _algorithm: &str,
            digest: &[u8],
        ) -> std::result::Result<Vec<u8>, SignatureProviderError> {
            assert_eq!(digest.len(), 32);
            Ok(vec![0x30, 0x00])
        }
    }

    #[test]
    #[cfg(not(feature = "signing"))]
    fn feature_minimal_external_signing_emits_verified_cms_without_private_key_loading() {
        let provider = ExternalSignatureProvider::new(&MinimalExternalSigner);
        let signed = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest::default(),
            )
            .expect("minimal external signing succeeds");
        verify_signed_binary(&signed, SignatureKind::Certificate)
            .expect("minimal external signature verifies structurally");
    }

    #[test]
    #[cfg(feature = "signing")]
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
    #[cfg(feature = "signing")]
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
        AdHocSignatureProvider
            .sign(&thin, &SignatureRequest::default())
            .expect("ad-hoc signing succeeds")
    }

    #[test]
    fn adhoc_signing_is_deterministic_and_verified() {
        for input in [
            macho_test_support::signable_thin64_x86_64(2),
            macho_test_support::signable_thin64_arm64(2),
        ] {
            let provider = AdHocSignatureProvider;
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
    fn generic_verifier_rejects_opaque_signature_kinds() {
        let signed = signed_fixture();
        let error = verify_signed_binary(&signed, SignatureKind::Opaque)
            .expect_err("opaque verification belongs to the provider");
        assert!(matches!(error, SignatureProviderError::Unavailable(_)));
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
        let provider = AdHocSignatureProvider;
        let first = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest::new()
                    .with_identifier("dev.matteson.macho.fixture")
                    .with_entitlements_xml(ENTITLEMENTS),
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
        let provider = AdHocSignatureProvider;
        let first = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest::new().with_identifier("dev.matteson.macho.original"),
            )
            .expect("initial signing succeeds");
        let resigned = provider
            .sign(
                &first,
                &SignatureRequest::new()
                    .with_identifier("dev.matteson.macho.override")
                    .with_entitlements_xml(ENTITLEMENTS),
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
        let signed = AdHocSignatureProvider
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
    #[cfg(feature = "signing")]
    fn pkcs12_certificate_signing_produces_verified_cms() {
        let provider = InProcessSignatureProvider::from_pkcs12(
            &macho_test_support::test_signing_identity_pkcs12(),
            macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD,
        )
        .expect("parse test identity");
        let signed = provider
            .sign(
                &macho_test_support::signable_thin64_x86_64(2),
                &SignatureRequest::new().with_identifier("dev.matteson.macho.certificate-fixture"),
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
    #[cfg(feature = "signing")]
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
                &SignatureRequest::new().with_identifier("dev.matteson.macho.corrupt-cms"),
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
