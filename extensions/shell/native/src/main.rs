//! Shell (`org.calve.shell`): the native OpenAEVC extension.

fn main() -> std::process::ExitCode {
    calve_domain::language::serve_language("shell")
}
