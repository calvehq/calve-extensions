//! General project (`org.calve.general`): the native OpenAEVC extension.

fn main() -> std::process::ExitCode {
    calve_domain::general::serve()
}
