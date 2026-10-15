#!/usr/bin/env bash
# Moves the contract pin to a calve-cli commit (already checked out in ../calve-cli) and runs
# everything that depends on it.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -eq 1 ]] || { echo "usage: $0 <calve-cli commit>" >&2; exit 2; }
rev=$(git -C ../calve-cli rev-parse --verify "$1^{commit}")
echo "$rev" > CONTRACT_PIN
cargo xtask check-contract
cargo test --workspace --locked
cargo conformance --locked
cargo xtask check-architecture
echo "pinned $rev; add a row to docs/contract-pins.md"
