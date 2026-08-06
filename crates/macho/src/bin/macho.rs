fn main() -> std::process::ExitCode {
    use std::io::IsTerminal;

    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let stdout_is_terminal = stdout.is_terminal();
    let stderr_is_terminal = stderr.is_terminal();
    let mut io = macho::cli::CliIo {
        stdout: &mut stdout,
        stderr: &mut stderr,
        stdout_is_terminal,
        stderr_is_terminal,
    };
    std::process::ExitCode::from(macho::cli::run_from(std::env::args_os(), &mut io).code())
}
