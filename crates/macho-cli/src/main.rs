fn main() -> std::process::ExitCode {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let mut io = macho_cli::CliIo {
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    std::process::ExitCode::from(macho_cli::run_from(std::env::args_os(), &mut io).code())
}
