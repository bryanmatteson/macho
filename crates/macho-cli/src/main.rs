fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(macho::commands::run_env())
}
