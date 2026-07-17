#!/usr/bin/env bash
set -euo pipefail

if ! command -v nmap >/dev/null 2>&1; then
  printf '\033[33m[missing]\033[0m nmap is optional and not installed\n'
  exit 2
fi

target="${1:-}"
if [[ -z "$target" ]]; then
  printf 'usage: %s <target>\n' "$0" >&2
  exit 1
fi

nmap -sV --version-light -oX - "$target"

