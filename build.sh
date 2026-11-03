#!/usr/bin/env bash
# Builds Keystone Vault into one executable with the console embedded: target/release/keystone
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v cargo >/dev/null || { echo "Rust is required: https://rustup.rs"; exit 1; }
command -v npm >/dev/null || { echo "Node 22.12+ / 24 is required for the console"; exit 1; }

echo "==> Console"
[ -d ui/node_modules ] || npm --prefix ui ci
npm --prefix ui run build

echo "==> Server (console embedded)"
cargo build --release -p keystone

echo
echo "Built: $(pwd)/target/release/keystone ($(./target/release/keystone version))"
echo "Run:   ./target/release/keystone            (http://127.0.0.1:8090, data in ~/.keystone)"
echo "Help:  ./target/release/keystone help"
