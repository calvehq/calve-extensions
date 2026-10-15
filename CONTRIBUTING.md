# Contributing

- Domain semantics live in `crates/calve-domain`: pure modules (`ignore`, `language`,
  `software`) compile to wasm32 for the CIC modules; the OpenAEVC servers are behind the
  `native` feature. Keep CIC code deterministic: no `std::fs`, `std::net`, `std::env`,
  `std::process`, `std::thread`, clocks or randomness (`cargo xtask check-architecture` enforces
  this).
- `unsafe` is allowed only in `crates/cic-guest` (the wasm ABI glue). Every block states its
  SAFETY invariant.
- New dependencies need an entry in the allowlist in `xtask/src/main.rs` and a line in the
  dependency-vetting notes of the pull request.
- A change to a module's observable behaviour changes its golden transcript
  (`crates/conformance/goldens`). Review the diff of the behaviour, then rerun
  `UPDATE_GOLDENS=1 cargo conformance` and commit the new goldens with the change.
- Rename pairing is mutation-tested: `cargo mutants --in-place -p calve-domain --features native
  --file crates/calve-domain/src/software.rs --re relate_group` must report no missed mutants.
- Signing keys never live in a repository: `xtask keygen` and `xtask publish` refuse key
  directories inside a git worktree.

Before a pull request: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, `cargo test --workspace`, `cargo conformance`, `cargo xtask check-architecture` and
`cargo xtask check-contract`.
