#!/usr/bin/env bash
# Prepares a development environment: the pinned toolchain with the wasm32 target, and a sibling
# ../calve-cli checkout at the commit in CONTRACT_PIN.
set -euo pipefail
cd "$(dirname "$0")/.."
rustup target add wasm32-unknown-unknown >/dev/null
if [[ ! -d ../calve-cli/.git ]]; then
  echo "clone calve-cli next to this repository (../calve-cli) and check out $(cat CONTRACT_PIN)" >&2
  exit 1
fi
cargo xtask check-contract
