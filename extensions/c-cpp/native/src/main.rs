//! C/C++ (`org.calve.c-cpp`): the native OpenAEVC extension.

fn main() -> std::process::ExitCode {
    calve_domain::language::serve_language("c-cpp")
}
