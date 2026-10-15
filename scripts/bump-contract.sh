#!/usr/bin/env bash
# Coordinated contract advance (ADR 0019): pins every calve-cli dependency to <commit>, runs the
# tests, conformance and the cross-repo examples, and appends the result to
# docs/contract-pins.md. Commit the result afterwards.
#   scripts/bump-contract.sh <calve-cli commit> [calve binary for the e2e examples]
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -ge 1 ]] || { echo "usage: $0 <calve-cli commit> [calve binary]" >&2; exit 2; }
rev=$1
[[ $rev =~ ^[0-9a-f]{40}$ ]] || { echo "the rev must be a full 40-hex commit" >&2; exit 2; }
sed -i -E "s|(git = \"https://github.com/calvehq/calve-cli.git\", rev = \")[0-9a-f]{40}|\1$rev|" Cargo.toml
cargo update --workspace >/dev/null
version=$(cargo metadata --format-version 1 --locked |
  python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="calve-integration-contract"))')
cargo test --workspace --locked
cargo conformance --locked
cargo xtask check-architecture
e2e="not run"
if [[ $# -ge 2 ]]; then
  out=$(mktemp -d)
  trap 'chmod -R u+w "$out"; rm -rf "$out"' EXIT
  # Throwaway signing keys, outside any git worktree (xtask refuses one).
  keys=$(mktemp -d "$HOME/.calve-bump-keys.XXXXXX")
  cargo xtask keygen --keys "$keys/k" >/dev/null
  cargo xtask dist --out "$out/dist" >/dev/null
  cargo xtask publish --keys "$keys/k" --dist "$out/dist" --repo "$out/repo" >/dev/null
  rm -rf "$keys"
  root="$out/repo/metadata/1.root.json"
  export CALVE_CATALOG_ADD
  CALVE_CATALOG_ADD=$(printf 'extension\ncatalog\nadd\ncalve\n%s\n--root\n%s\n--root-digest\n%s' \
    "$out/repo" "$root" "$(sha256sum "$root" | cut -d' ' -f1)")
  for ex in "$(git -C "$(dirname "$2")" rev-parse --show-toplevel 2>/dev/null || echo ../calve-cli)"/examples/*/run.sh; do
    CALVE="$2" bash "$ex" >/dev/null
  done
  e2e="PASS ($(basename "$2"), all examples)"
fi
echo "| \`$rev\` | $version | \`$(git rev-parse HEAD)\` (+ this pin) | $e2e | $(date -u +%F) |" >> docs/contract-pins.md
cargo xtask check-contract
echo "pinned $rev; review docs/contract-pins.md and commit"
