use macho::metadata::codesign::{HashType, parse_code_signature};

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn parse_code_signature_true() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        let sig = parse_code_signature(macho).expect("failed to parse signature");
        assert!(!sig.blobs().is_empty(), "expected blobs");
        assert!(
            !sig.code_directories().is_empty(),
            "expected code directory"
        );
    }
}

#[test]
fn code_directory_has_identifier() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let sig = parse_code_signature(macho).expect("failed to parse signature");
    let id = sig.identifier();
    assert!(id.is_some(), "expected identifier");
    assert!(
        id.unwrap().contains("true"),
        "expected 'true' in identifier"
    );
}

#[test]
fn code_directory_hash_type() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let sig = parse_code_signature(macho).expect("failed to parse signature");
    let cd = &sig.code_directories()[0];
    // Modern binaries use SHA-256
    assert!(
        matches!(cd.hash_type, HashType::Sha256 | HashType::Sha384),
        "expected SHA-256 or SHA-384, got {:?}",
        cd.hash_type
    );
    assert!(cd.hash_size > 0);
    assert!(cd.n_code_slots > 0);
}

#[test]
fn cms_signature_present() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let sig = parse_code_signature(macho).expect("failed to parse signature");
    assert!(sig.cms_signature_present(), "expected CMS signature");
}

#[test]
fn blob_types_are_valid() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let sig = parse_code_signature(macho).expect("failed to parse signature");
    for blob in sig.blobs() {
        assert!(blob.size > 0, "blob should have non-zero size");
        assert!(!blob.data.is_empty(), "blob should have data");
    }
}

#[test]
fn no_signature_graceful() {
    // Minimal binary without LC_CODE_SIGNATURE
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0x19u32.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 64]);

    let container = macho::parse(&data).expect("parse failed");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");
    assert!(parse_code_signature(macho).is_err());
}

#[test]
fn code_signature_via_ext_trait() {
    use macho::metadata::codesign::CodeSignature;

    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let sig: CodeSignature = macho.ext().expect("ext failed");
    assert!(!sig.blobs().is_empty());
}
