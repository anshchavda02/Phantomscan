#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v go >/dev/null 2>&1; then
  (cd "$ROOT/engines/go" && mkdir -p bin && go build -o bin/phantomscan-go .)
else
  printf '\033[33m[skip]\033[0m go not installed\n'
fi

if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT/engines/rust" && cargo build --release)
else
  printf '\033[33m[skip]\033[0m cargo not installed\n'
fi

if command -v node >/dev/null 2>&1; then
  (cd "$ROOT/engines/node" && node --test)
else
  printf '\033[33m[skip]\033[0m node not installed\n'
fi

