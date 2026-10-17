# Contract pins

calve-extensions builds against the Calve Integration Contract (`calve-integration-contract`) and
tests against Calve's host crates (`calve-app`, `calve-testkit`), all from calve-cli at one commit
(ADR 0019): `git = "https://github.com/calvehq/calve-cli.git", rev = "<40-hex>"` in the workspace
`Cargo.toml`. Reproducibility comes from the commit hash in `Cargo.lock`.

Until that commit is public, `source scripts/dev-env.sh [path to calve-cli]` points cargo's git
fetches at a local checkout for the current shell (`GIT_CONFIG_*` `url.<local>.insteadOf`; no
global git configuration, and the lockfile keeps the public URL).

To move to a newer contract, run `scripts/bump-contract.sh <calve-cli commit> [calve binary]`: it
rewrites the rev, updates the lock, runs the tests, the conformance suite, the architecture check
and — with a calve binary — every calve-cli example against a freshly published catalog of these
packages, then appends a row below. `cargo xtask check-contract` requires the newest row to be the
pinned rev.

| calve-cli | Contract | calve-extensions | Cross-repo e2e | Date |
|---|---|---|---|---|
| `d102949f853eabd7546f70d8fa4eb6324e66a347` | 1.0.0-alpha.1 | `d955731c6a68a090d2e1ff065da232f17aa071bd` (+ this pin) | PASS (calve, all examples) | 2026-10-15 |
| `f7f6a37b2980f982b98dd183316d2288acdb5667` | 1.0.0-alpha.1 | `bd49926bd42c21705ff845bc6096ef344fcbd233` (+ this pin) | PASS (calve, all examples) | 2026-10-15 |
| `ef8158ae0fa3c0a3862270ac925b591561b0b810` | 1.0.0-alpha.1 | `ffcbe66d28fde2edd0a0ce35089e8a1c7e52439d` (+ this pin) | PASS (calve, all examples) | 2026-10-15 |
| `0fb1601592571557563669096afe2fce69ba91fc` | 1.0.0-alpha.1 | `8c1239cb64e6ca9e22cf7de55a7d1bf6529d5fed` (+ this pin) | PASS (calve, all examples) | 2026-10-17 |
