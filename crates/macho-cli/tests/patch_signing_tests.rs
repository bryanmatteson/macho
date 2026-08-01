mod support;

use macho::metadata::codesign::CodeSignature;
use macho::model::container::MachoContainer;
use macho::mutate::{SignatureKind, verify_signed_binary};
use support::{run_cli, temp_file_path};

fn write_signable_fat(name: &str) -> std::path::PathBuf {
    let path = temp_file_path(name);
    let bytes = macho_test_support::fat32(&[
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
    std::fs::write(&path, bytes).expect("write portable signing fixture");
    path
}

#[test]
fn patch_signing_adhoc_is_user_visible_and_verified() {
    let input_path = write_signable_fat("patch-signing-input");
    let output_path = temp_file_path("patch-signing-adhoc");
    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-adhoc",
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(stdout.contains("verified ad-hoc signature applied"));

    let signed = std::fs::read(&output_path).expect("read signed output");
    verify_signed_binary(&signed, SignatureKind::AdHoc).expect("output verifies");
    let parsed = macho::parse(&signed).expect("parse signed output");
    for mach in parsed.macho_files() {
        let signature = mach.ext::<CodeSignature<'_>>().expect("parse signature");
        assert!(!signature.cms_signature_present());
    }

    let inspect = run_cli(["codesign", output_path.to_str().expect("UTF-8 temp path")]);
    assert!(inspect.status.success());
    assert!(
        String::from_utf8(inspect.stdout)
            .expect("UTF-8 inspection")
            .contains("CMS Signature: none")
    );
    std::fs::remove_file(input_path).expect("remove input fixture");
    std::fs::remove_file(output_path).expect("remove signed output");
}

#[test]
fn patch_signing_json_and_dry_run_report_verified_mode() {
    let input_path = write_signable_fat("patch-signing-dry-run-input");
    let dry = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-adhoc",
        "--dry-run",
        "--format",
        "json",
    ]);
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&dry.stdout).expect("JSON dry-run report");
    assert_eq!(report["data"]["signing"]["requested"], true);
    assert_eq!(report["data"]["signing"]["mode"], "ad_hoc");
    assert_eq!(report["data"]["signing"]["verified"], true);
    assert_eq!(report["data"]["written"], false);
    assert!(
        report["data"]["previews"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    );
    std::fs::remove_file(input_path).expect("remove dry-run input");
}

#[test]
fn malformed_credentials_fail_before_destination_replacement() {
    let input_path = write_signable_fat("credential-failure-input");
    let p12_path = temp_file_path("malformed-p12");
    let output_path = temp_file_path("credential-failure-destination");
    std::fs::write(&p12_path, b"not a p12").expect("write malformed identity");
    std::fs::write(&output_path, b"sentinel").expect("write destination sentinel");

    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-p12",
        p12_path.to_str().expect("UTF-8 temp path"),
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        std::fs::read(&output_path).expect("read preserved destination"),
        b"sentinel"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid signing credentials"));
    std::fs::remove_file(input_path).expect("remove input fixture");
    std::fs::remove_file(p12_path).expect("remove malformed identity");
    std::fs::remove_file(output_path).expect("remove destination");
}

#[test]
fn wrong_password_fails_before_destination_replacement() {
    const WRONG_SECRET: &str = "incorrect-but-secret-credential";
    let input_path = write_signable_fat("bad-credential-input");
    let p12_path = temp_file_path("bad-credential-identity");
    let password_path = temp_file_path("bad-credential-secret");
    let output_path = temp_file_path("bad-credential-destination");
    std::fs::write(
        &p12_path,
        macho_test_support::test_signing_identity_pkcs12(),
    )
    .expect("write test identity");
    std::fs::write(&password_path, format!("{WRONG_SECRET}\n")).expect("write wrong password");
    std::fs::write(&output_path, b"sentinel").expect("write destination sentinel");

    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-p12",
        p12_path.to_str().expect("UTF-8 temp path"),
        "--p12-password-file",
        password_path.to_str().expect("UTF-8 temp path"),
        "--identifier",
        "dev.matteson.macho.bad-credential",
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);

    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(&output_path).expect("read preserved destination"),
        b"sentinel"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid signing credentials"));
    assert!(
        !output
            .stdout
            .windows(WRONG_SECRET.len())
            .any(|window| window == WRONG_SECRET.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(WRONG_SECRET.len())
            .any(|window| window == WRONG_SECRET.as_bytes())
    );
    for path in [input_path, p12_path, password_path, output_path] {
        std::fs::remove_file(path).expect("remove wrong-password test file");
    }
}

#[test]
fn malformed_entitlements_fail_before_destination_replacement() {
    let input_path = write_signable_fat("malformed-entitlements-input");
    let entitlements_path = temp_file_path("malformed-entitlements");
    let output_path = temp_file_path("malformed-entitlements-destination");
    std::fs::write(&entitlements_path, b"<plist><dict>").expect("write bad entitlements");
    std::fs::write(&output_path, b"sentinel").expect("write destination sentinel");

    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-adhoc",
        "--entitlements",
        entitlements_path.to_str().expect("UTF-8 temp path"),
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);

    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(&output_path).expect("read preserved destination"),
        b"sentinel"
    );
    assert!(
        String::from_utf8(output.stderr)
            .expect("UTF-8 stderr")
            .contains("signing failed")
    );
    for path in [input_path, entitlements_path, output_path] {
        std::fs::remove_file(path).expect("remove malformed-entitlement test file");
    }
}

#[test]
fn contradictory_signing_options_are_usage_errors() {
    let input_path = write_signable_fat("signing-option-conflict-input");
    let output_path = temp_file_path("signing-option-conflict-output");
    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-adhoc",
        "--strip-signature",
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);

    assert!(!output.status.success());
    assert!(!output_path.exists());
    assert!(
        String::from_utf8(output.stderr)
            .expect("UTF-8 stderr")
            .contains("cannot be used with")
    );
    std::fs::remove_file(input_path).expect("remove option-conflict fixture");
}

#[test]
fn selected_fat_slice_signing_preserves_unselected_slice_bytes() {
    let input_path = write_signable_fat("selected-fat-input");
    let original = std::fs::read(&input_path).expect("read fixture");
    let parsed = macho::parse(&original).expect("parse fixture");
    let MachoContainer::Fat(fat) = &parsed else {
        return;
    };
    if fat.arches().len() < 2 {
        return;
    }
    let selected_name = fat.arches()[0].spec().name();
    let original_unselected = fat.arches()[1].macho().bytes().to_vec();
    let output_path = temp_file_path("selected-fat-signing");

    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--arch",
        &selected_name,
        "--sign-adhoc",
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let rebuilt = std::fs::read(&output_path).expect("read rebuilt fat binary");
    let reparsed = macho::parse(&rebuilt).expect("parse rebuilt fat binary");
    let MachoContainer::Fat(rebuilt_fat) = reparsed else {
        panic!("rebuilt fixture must remain fat");
    };
    assert_eq!(
        rebuilt_fat.arches()[1].macho().bytes(),
        original_unselected,
        "unselected slice bytes changed"
    );
    verify_signed_binary(
        rebuilt_fat.arches()[0].macho().bytes(),
        SignatureKind::AdHoc,
    )
    .expect("selected slice verifies");
    std::fs::remove_file(input_path).expect("remove input fixture");
    std::fs::remove_file(output_path).expect("remove rebuilt output");
}

#[test]
fn patch_signing_pkcs12_produces_verified_cms_without_secret_output() {
    let input_path = temp_file_path("certificate-input");
    let p12_path = temp_file_path("certificate-identity");
    let password_path = temp_file_path("certificate-password");
    let output_path = temp_file_path("certificate-output");
    std::fs::write(&input_path, macho_test_support::signable_thin64_x86_64(2))
        .expect("write signing input");
    std::fs::write(
        &p12_path,
        macho_test_support::test_signing_identity_pkcs12(),
    )
    .expect("write test identity");
    std::fs::write(
        &password_path,
        format!("{}\n", macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD),
    )
    .expect("write password file");

    let output = run_cli([
        "patch",
        input_path.to_str().expect("UTF-8 temp path"),
        "--sign-p12",
        p12_path.to_str().expect("UTF-8 temp path"),
        "--p12-password-file",
        password_path.to_str().expect("UTF-8 temp path"),
        "--identifier",
        "dev.matteson.macho.cli-certificate",
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output
            .stdout
            .windows(macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD.len())
            .any(|window| window == macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD.len())
            .any(|window| window == macho_test_support::TEST_SIGNING_IDENTITY_PASSWORD.as_bytes())
    );

    let signed = std::fs::read(&output_path).expect("read certificate-signed output");
    verify_signed_binary(&signed, SignatureKind::Certificate).expect("certificate output verifies");
    let parsed = macho::parse(&signed).expect("parse certificate output");
    let signature = parsed
        .first_macho()
        .expect("contains Mach-O")
        .ext::<CodeSignature<'_>>()
        .expect("parse certificate signature");
    assert!(signature.cms_signature_present());
    assert!(
        signature
            .code_directories()
            .iter()
            .any(|directory| directory.hash_type.name() == "SHA-256")
    );
    assert_eq!(
        signature.identifier(),
        Some("dev.matteson.macho.cli-certificate")
    );

    let audit = run_cli([
        "audit",
        output_path.to_str().expect("UTF-8 temp path"),
        "--format",
        "json",
    ]);
    assert!(
        audit.status.success(),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let audit: serde_json::Value = serde_json::from_slice(&audit.stdout).expect("parse audit JSON");
    assert!(
        !audit.to_string().contains("\"rule_id\":\"CS003\""),
        "built-in certificate re-signing must resolve CS003: {audit}"
    );

    for path in [input_path, p12_path, password_path, output_path] {
        std::fs::remove_file(path).expect("remove certificate test file");
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "test-only Apple verifier oracle; production signing is process-free"]
fn macos_codesign_oracle() {
    let output_path = temp_file_path("codesign-oracle");
    let output = run_cli([
        "patch",
        "/usr/bin/true",
        "--sign-adhoc",
        "--output",
        output_path.to_str().expect("UTF-8 temp path"),
    ]);
    assert!(output.status.success());

    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=4"])
        .arg(&output_path)
        .status()
        .expect("run test-only Apple verifier");
    assert!(status.success());
    std::fs::remove_file(output_path).expect("remove oracle output");
}
