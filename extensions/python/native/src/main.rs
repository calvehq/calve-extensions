//! Python (`org.calve.python`): the native OpenAEVC extension.

fn main() -> std::process::ExitCode {
    calve_domain::language::serve_language("python")
}
