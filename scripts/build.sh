#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '\033[1;36mBuilding PhantomScan cross-language engines...\033[0m\n'

# Go Port Scanner
if command -v go >/dev/null 2>&1; then
  printf 'Building Go port scanner...\n'
  (cd "$ROOT/engines/go" && mkdir -p bin && go build -o bin/phantomscan-go .)
  printf '\033[32m[ok]\033[0m Go engine built.\n'
else
  printf '\033[33m[skip]\033[0m go compiler not installed.\n'
fi

# Rust TLS Inspector
if command -v cargo >/dev/null 2>&1; then
  printf 'Building Rust TLS inspector...\n'
  (cd "$ROOT/engines/rust" && cargo build --release)
  printf '\033[32m[ok]\033[0m Rust engine built.\n'
else
  printf '\033[33m[skip]\033[0m cargo not installed.\n'
fi

# Node Headless Browser Engine
if command -v npm >/dev/null 2>&1; then
  printf 'Setting up Node headless browser engine...\n'
  (cd "$ROOT/engines/node" && npm install --no-audit --no-fund && npx playwright install chromium || true)
  printf '\033[32m[ok]\033[0m Node engine & Chromium setup.\n'
else
  printf '\033[33m[skip]\033[0m npm/node not installed.\n'
fi

printf '\033[1;32mBuild step completed.\033[0m\n'
