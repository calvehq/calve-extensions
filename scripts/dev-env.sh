# Source this file (`source scripts/dev-env.sh [path to calve-cli]`) before building while the
# pinned calve-cli commit is not public yet: it points cargo's git fetches of calve-cli at a
# local checkout for this shell only. Only the transport changes; Cargo.lock keeps the public
# URL and the pinned commit (ADR 0019).
cli="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/../../calve-cli}" && pwd)"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0="url.file://$cli.insteadOf"
export GIT_CONFIG_VALUE_0="https://github.com/calvehq/calve-cli.git"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
echo "calve-cli fetched from $cli"
