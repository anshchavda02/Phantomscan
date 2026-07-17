#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
BIN_DIR="${HOME}/.local/bin"
LAUNCHER="${BIN_DIR}/phantomscan"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  printf '\033[31m[error]\033[0m Python 3.10+ is required. Install it with Homebrew: brew install python\n' >&2
  exit 1
fi

"$PYTHON_BIN" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip
if [[ -f "$ROOT/requirements.txt" ]]; then
  "$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt" || true
fi

mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$ROOT"
exec "$ROOT/.venv/bin/python" "$ROOT/phantomscan.py" "\$@"
EOF
chmod +x "$LAUNCHER"

printf '\033[32m[ok]\033[0m PhantomScan installed for macOS.\n'
printf 'Add this to PATH if needed: export PATH="$HOME/.local/bin:$PATH"\n'
printf 'Run: cd %s && phantomscan --target example.com --profile passive\n' "$ROOT"
