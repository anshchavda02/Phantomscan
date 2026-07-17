#!/usr/bin/env bash
set -euo pipefail

missing=0
for cmd in python go cargo node; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '\033[32m[ok]\033[0m %s\n' "$cmd"
  else
    printf '\033[33m[missing]\033[0m %s\n' "$cmd"
    missing=2
  fi
done
exit "$missing"

