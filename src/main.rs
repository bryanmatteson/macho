fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(macho::cli::run_env())
}
