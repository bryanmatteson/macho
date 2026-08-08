#![cfg(feature = "cli")]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use macho_test_support::SymbolFixture;

fn fixture_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-output-{name}-{nonce}"))
}

fn write_fixture(name: &str) -> PathBuf {
    let path = fixture_path(name);
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "_helper",
            external: false,
            defined: true,
        },
        SymbolFixture {
            name: "__Z3foov",
            external: true,
            defined: true,
        },
    ]);
    std::fs::write(&path, bytes).expect("write Mach-O fixture");
    path
}

fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.next_if_eq(&'[').is_some() {
            for sequence_character in characters.by_ref() {
                if sequence_character == 'm' {
                    break;
                }
            }
        } else {
            plain.push(character);
        }
    }
    plain
}

#[test]
fn info_text_uses_stable_columns_without_trailing_whitespace() {
    let path = write_fixture("columns");
    let output = macho::cli::run_captured([
        "info",
        path.to_str().expect("UTF-8 fixture path"),
        "--color",
        "never",
    ]);
    let _ = std::fs::remove_file(path);

    assert_eq!(
        output.code,
        0,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&0x1b));

    let text = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(text.lines().all(|line| !line.ends_with(' ')));

    let header_lines = text
        .lines()
        .filter(|line| {
            [
                "  CPU:",
                "  File type:",
                "  Bitness:",
                "  Endian:",
                "  Commands:",
                "  Cmd size:",
                "  Flags:",
            ]
            .iter()
            .any(|label| line.starts_with(label))
        })
        .collect::<Vec<_>>();
    assert_eq!(header_lines.len(), 7);
    let value_offsets = header_lines
        .iter()
        .map(|line| {
            let (_, value) = line.split_once(':').expect("header label");
            line.find(value.trim_start()).expect("header value")
        })
        .collect::<Vec<_>>();
    assert!(value_offsets.windows(2).all(|pair| pair[0] == pair[1]));

    let load_commands = text
        .lines()
        .filter(|line| line.contains("LC_SEGMENT_64") || line.contains("LC_SYMTAB"))
        .collect::<Vec<_>>();
    assert_eq!(load_commands.len(), 2);
    assert!(load_commands[0].starts_with("    0  "));
    assert!(load_commands[1].starts_with("    1  "));
    assert!(load_commands.iter().all(|line| !line.contains('[')));
    let off_offsets = load_commands
        .iter()
        .map(|line| line.find("off=").expect("load-command offset"))
        .collect::<Vec<_>>();
    let size_offsets = load_commands
        .iter()
        .map(|line| line.find("size=").expect("load-command size"))
        .collect::<Vec<_>>();
    assert_eq!(off_offsets[0], off_offsets[1]);
    assert_eq!(size_offsets[0], size_offsets[1]);
}

#[test]
fn explicit_color_styles_human_info_only() {
    let path = write_fixture("color");
    let path = path.to_str().expect("UTF-8 fixture path").to_owned();

    let human = macho::cli::run_captured(["info", &path, "--color", "always"]);
    let plain = macho::cli::run_captured(["info", &path, "--color", "never"]);
    assert_eq!(human.code, 0);
    assert!(human.stdout.contains(&0x1b));
    let human = String::from_utf8(human.stdout).expect("UTF-8 human output");
    let plain = String::from_utf8(plain.stdout).expect("UTF-8 plain output");
    assert_eq!(strip_ansi(&human), plain);
    assert!(human.contains("\u{1b}[1;34m__TEXT\u{1b}[0m"));
    assert!(human.contains("\u{1b}[34m__text\u{1b}[0m"));
    assert!(human.contains("\u{1b}[35mS_REGULAR\u{1b}[0m"));
    assert!(human.contains("\u{1b}[2moff=\u{1b}[0m\u{1b}[33m0x00000100\u{1b}[0m"));

    let machine = macho::cli::run_captured(["info", &path, "--format", "json", "--color", "never"]);
    let _ = std::fs::remove_file(path);
    assert_eq!(machine.code, 0);
    assert!(!machine.stdout.contains(&0x1b));
    let envelope: serde_json::Value =
        serde_json::from_slice(&machine.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["command"], "info");
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["data"]["schema_version"], 1);
}

#[test]
fn info_rejects_explicit_color_for_json_with_typed_usage_diagnostic() {
    let path = write_fixture("json-color-rejected");
    let output = macho::cli::run_captured([
        "info",
        path.to_str().expect("UTF-8 fixture path"),
        "--format",
        "json",
        "--color",
        "always",
    ]);
    let _ = std::fs::remove_file(path);

    assert_eq!(output.code, 2);
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.contains(&0x1b));
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("valid JSON failure envelope");
    assert_eq!(envelope["command"], "info");
    assert_eq!(envelope["ok"], false);
    assert_eq!(
        envelope["diagnostics"][0]["code"],
        "cli.usage.color_machine"
    );
    assert_eq!(
        envelope["diagnostics"][0]["message"],
        "--color always is incompatible with machine output"
    );
}

#[test]
fn deps_uses_shared_human_style_and_keeps_json_escape_free() {
    let path = write_fixture("deps-color");
    let path = path.to_str().expect("UTF-8 fixture path").to_owned();

    let colored = macho::cli::run_captured(["deps", &path, "--color", "always"]);
    let plain = macho::cli::run_captured(["deps", &path, "--color", "never"]);
    let machine = macho::cli::run_captured(["deps", &path, "--format", "json", "--color", "never"]);
    let _ = std::fs::remove_file(path);

    assert_eq!(colored.code, 0);
    assert_eq!(plain.code, 0);
    assert!(colored.stdout.contains(&0x1b));
    let colored = String::from_utf8(colored.stdout).expect("UTF-8 colored output");
    let plain = String::from_utf8(plain.stdout).expect("UTF-8 plain output");
    assert_eq!(strip_ansi(&colored), plain);
    assert!(colored.contains("\u{1b}[1;36mLinked dylibs (0):\u{1b}[0m"));
    assert!(colored.contains("\u{1b}[2mtotal=\u{1b}[0m\u{1b}[33m0\u{1b}[0m"));

    assert_eq!(machine.code, 0);
    assert!(!machine.stdout.contains(&0x1b));
    let envelope: serde_json::Value =
        serde_json::from_slice(&machine.stdout).expect("valid JSON envelope");
    assert_eq!(envelope["command"], "deps");
    assert_eq!(envelope["ok"], true);
}

#[test]
fn ranges_aligns_columns_with_and_without_color() {
    let path = write_fixture("range-columns");
    let path = path.to_str().expect("UTF-8 fixture path").to_owned();

    let colored = macho::cli::run_captured(["ranges", &path, "--demangle", "--color", "always"]);
    let plain = macho::cli::run_captured(["ranges", &path, "--demangle", "--color", "never"]);
    let machine = macho::cli::run_captured([
        "ranges",
        &path,
        "--demangle",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    let _ = std::fs::remove_file(path);

    assert_eq!(colored.code, 0);
    assert_eq!(plain.code, 0);
    assert!(colored.stdout.contains(&0x1b));
    let colored = String::from_utf8(colored.stdout).expect("UTF-8 colored output");
    let plain = String::from_utf8(plain.stdout).expect("UTF-8 plain output");
    assert_eq!(strip_ansi(&colored), plain);

    let rows = plain
        .lines()
        .filter(|line| line.starts_with("  0x"))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 3);
    let source_offsets = rows
        .iter()
        .map(|line| line.find("[nlist]").expect("range source"))
        .collect::<Vec<_>>();
    assert!(source_offsets.windows(2).all(|pair| pair[0] == pair[1]));

    assert_eq!(machine.code, 0);
    assert!(!machine.stdout.contains(&0x1b));
    serde_json::from_slice::<serde_json::Value>(&machine.stdout).expect("valid JSON envelope");
}

#[test]
fn help_follows_the_color_policy_and_uses_the_shared_theme() {
    // Piped output defaults to `auto`, which must stay escape-free so help
    // goldens and redirected output remain plain text.
    let piped = macho::cli::run_captured(["disassemble", "--help"]);
    assert_eq!(piped.code, 0);
    assert!(
        !piped.stdout.contains(&0x1b),
        "auto help must not colorize a non-terminal stream"
    );

    let never = macho::cli::run_captured(["disassemble", "--help", "--color", "never"]);
    assert_eq!(never.code, 0);
    assert!(!never.stdout.contains(&0x1b));

    // `--color always` overrides the terminal check, and Clap renders through
    // Macho's theme rather than its own default palette.
    let always = macho::cli::run_captured(["disassemble", "--help", "--color", "always"]);
    assert_eq!(always.code, 0);
    assert!(
        always.stdout.contains(&0x1b),
        "explicit color must colorize help"
    );
    let colored = String::from_utf8(always.stdout).expect("UTF-8 help");

    // Section headers take the subheading token (bold cyan), literals take the
    // keyword token (bold blue), and placeholders the builtin-type token.
    assert!(
        colored.contains("\u{1b}[1m\u{1b}[36mUsage:\u{1b}[0m"),
        "{colored:?}"
    );
    assert!(colored.contains("\u{1b}[1m\u{1b}[36mOptions:\u{1b}[0m"));
    assert!(colored.contains("\u{1b}[1m\u{1b}[34m--arch\u{1b}[0m"));
    assert!(colored.contains("\u{1b}[35m<PATH>\u{1b}[0m"));

    // Colour is presentation only: stripping it reproduces the plain help.
    assert_eq!(
        strip_ansi(&colored),
        String::from_utf8(never.stdout).unwrap()
    );
}

#[test]
fn usage_errors_stay_plain_text_under_every_color_choice() {
    for choice in ["auto", "never", "always"] {
        let result = macho::cli::run_captured(["not-a-command", "--color", choice]);
        assert_eq!(result.code, 2, "usage errors exit 2");
        assert!(result.stdout.is_empty());
        let stderr = String::from_utf8(result.stderr).expect("UTF-8 stderr");

        // The diagnostic renderer sanitizes what it writes, so Clap's own
        // escapes are stripped beforehand; otherwise they would arrive as
        // replacement characters.
        assert!(
            !stderr.contains('\u{fffd}'),
            "clap escapes must not survive into the sanitizer: {stderr:?}"
        );
        assert!(stderr.contains("unrecognized subcommand 'not-a-command'"));
        assert!(stderr.contains("Usage: macho <COMMAND> [OPTIONS]"));

        // Only the label carries theme styling, and only when colour is on.
        if choice == "always" {
            assert!(stderr.contains("\u{1b}[1;31mError:\u{1b}[0m"));
        } else {
            assert!(!stderr.contains('\u{1b}'));
        }
    }
}
