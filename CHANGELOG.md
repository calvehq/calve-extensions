# Changelog

All notable changes to the first-party Calve extensions are documented here.

## Unreleased

### Added

- First-party packages: `software`, `general`, and language packages for Rust, Go, Python,
  JavaScript/TypeScript, Java, C/C++, Shell and HCL, each with signed metadata, a CIC module and a
  native OpenAEVC extension.
- Chunked software snapshots and `calve.refs/1` documents.
- Rename-aware snapshot verifier.
- Release tooling: per-target native builds, and a delegated `calve` publisher role with thresholds
  and key rotation.
- A dependency check that keeps extensions away from Calve's private crates.
