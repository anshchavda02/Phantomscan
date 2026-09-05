#!/usr/bin/env bash
set -euo pipefail

missing=0

# Python check
if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
  py_cmd="$(command -v python3 || command -v python)"
  printf '\033[32m[ok]\033[0m python (%s)\n' "$py_cmd"
else
  printf '\033[31m[missing]\033[0m python (3.10+ required)\n'
  missing=1
fi

# Optional polyglot engines
for cmd in go cargo node npm; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '\033[32m[ok]\033[0m %s\n' "$cmd"
  else
    printf '\033[33m[optional-missing]\033[0m %s\n' "$cmd"
  fi
done

exit "$missing"
