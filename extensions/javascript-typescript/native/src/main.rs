//! JavaScript/TypeScript (`org.calve.javascript-typescript`): the native OpenAEVC extension.

fn main() -> std::process::ExitCode {
    calve_domain::language::serve_language("javascript-typescript")
}
