mod support;

use support::{run_cli, temp_file_path, write_macho_fixture};

const CACHE_BASE: u64 = 0x1_8000_0000;

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_thin_image(bytes: &mut [u8], offset: usize, vmaddr: u64) {
    put_u32(bytes, offset, 0xfeed_facf);
    put_u32(bytes, offset + 4, 0x0100_000c);
    put_u32(bytes, offset + 8, 2);
    put_u32(bytes, offset + 12, 6);
    put_u32(bytes, offset + 16, 1);
    put_u32(bytes, offset + 20, 72);
    put_u32(bytes, offset + 24, 0x85);
    put_u32(bytes, offset + 32, 0x19);
    put_u32(bytes, offset + 36, 72);
    bytes[offset + 40..offset + 46].copy_from_slice(b"__TEXT");
    put_u64(bytes, offset + 56, vmaddr);
    put_u64(bytes, offset + 64, 104);
    put_u64(bytes, offset + 72, 0);
    put_u64(bytes, offset + 80, 104);
    put_u32(bytes, offset + 88, 7);
    put_u32(bytes, offset + 92, 5);
}

fn cache_fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x1400];
    bytes[..14].copy_from_slice(b"dyld_v1  arm64");
    put_u32(&mut bytes, 16, 32);
    put_u32(&mut bytes, 20, 1);
    put_u32(&mut bytes, 24, 64);
    put_u32(&mut bytes, 28, 2);
    put_u64(&mut bytes, 32, CACHE_BASE);
    put_u64(&mut bytes, 40, 0x1000);
    put_u64(&mut bytes, 48, 0x400);
    put_u32(&mut bytes, 56, 5);
    put_u32(&mut bytes, 60, 5);
    put_u64(&mut bytes, 64, CACHE_BASE);
    put_u32(&mut bytes, 88, 128);
    put_u64(&mut bytes, 96, CACHE_BASE + 0x100);
    put_u32(&mut bytes, 120, 160);
    let first = b"/usr/lib/libAlpha.dylib\0";
    bytes[128..128 + first.len()].copy_from_slice(first);
    let second = b"/usr/lib/libBeta.dylib\0";
    bytes[160..160 + second.len()].copy_from_slice(second);
    put_thin_image(&mut bytes, 0x400, CACHE_BASE);
    put_thin_image(&mut bytes, 0x500, CACHE_BASE + 0x100);
    bytes
}

#[test]
fn json_extraction_materializes_parseable_output_and_refuses_collision() {
    let cache = write_macho_fixture(&cache_fixture(), "cache-extraction", false);
    let output = temp_file_path("cache-output");
    let result = run_cli([
        "cache",
        cache.path().to_str().expect("cache path"),
        "--extract",
        "/usr/lib/libAlpha.dylib",
        "--output",
        output.to_str().expect("output path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).expect("JSON output");
    assert_eq!(json["data"]["operation"], "extract");
    assert_eq!(json["data"]["written"], true);
    assert_eq!(
        json["data"]["result"]["completeness"]["segments"]["state"],
        "complete"
    );
    let extracted = std::fs::read(&output).expect("extracted bytes");
    macho::parse(&extracted).expect("downstream core parse");

    let collision = run_cli([
        "cache",
        cache.path().to_str().expect("cache path"),
        "--extract",
        "/usr/lib/libAlpha.dylib",
        "--output",
        output.to_str().expect("output path"),
        "--color",
        "never",
    ]);
    assert!(!collision.status.success());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("refusing to overwrite"));
    assert_eq!(std::fs::read(&output).expect("unchanged output"), extracted);
    let _ = std::fs::remove_file(output);
}

#[test]
fn ambiguous_extraction_refuses_and_search_remains_a_list_operation() {
    let cache = write_macho_fixture(&cache_fixture(), "cache-ambiguous", false);
    let output = temp_file_path("cache-ambiguous-output");
    let ambiguous = run_cli([
        "cache",
        cache.path().to_str().expect("cache path"),
        "--extract",
        "lib",
        "--output",
        output.to_str().expect("output path"),
        "--color",
        "never",
    ]);
    assert!(!ambiguous.status.success());
    assert!(String::from_utf8_lossy(&ambiguous.stderr).contains("ambiguous"));
    assert!(!output.exists());

    let search = run_cli([
        "cache",
        cache.path().to_str().expect("cache path"),
        "--search",
        "lib",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(search.status.success());
    let json: serde_json::Value = serde_json::from_slice(&search.stdout).expect("search JSON");
    assert_eq!(json["data"]["operation"], "search");
    assert_eq!(json["data"]["images"].as_array().expect("images").len(), 2);
}
