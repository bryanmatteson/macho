mod support;

use support::{run_cli, temp_file_path};

#[test]
fn analysis_domain_commands_accept_arch_on_fat_input() {
    let path = temp_file_path("analysis-arch-selection");
    std::fs::write(&path, macho_test_support::disassembly_fat()).expect("write fat fixture");
    let path = path.to_str().expect("UTF-8 fixture path");

    for command in ["xrefs", "strings", "ranges", "vtables"] {
        let output = run_cli([command, path, "--arch", "x86_64", "--color", "never"]);
        assert!(
            output.status.success(),
            "{command} --arch x86_64 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    std::fs::remove_file(path).expect("remove fat fixture");
}
