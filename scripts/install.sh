#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
BIN_DIR="${HOME}/.local/bin"
LAUNCHER="${BIN_DIR}/phantomscan"

printf '\033[1;36m============================================================\033[0m\n'
printf '\033[1;36mPhantomScan Linux CLI Installer\033[0m\n'
printf '\033[1;36mAuthorized security assessment use only.\033[0m\n'
printf '\033[1;36m============================================================\033[0m\n\n'

# 1. Check Python
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  printf '\033[31m[error]\033[0m %s is required. Install Python 3.10+ first.\n' "$PYTHON_BIN" >&2
  exit 1
fi

PY_VER="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
printf '\033[32m[ok]\033[0m Found Python %s (%s)\n' "$PY_VER" "$("$PYTHON_BIN" -c 'import sys; print(sys.executable)')"

# 2. Virtual Environment Setup
printf '\n\033[1;33m[1/4] Setting up Python virtual environment...\033[0m\n'
"$PYTHON_BIN" -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/python" -m pip install --upgrade pip --quiet

if [[ -f "$ROOT/requirements.txt" ]]; then
  printf 'Installing dependencies from requirements.txt...\n'
  "$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt" --quiet
fi
printf '\033[32m[ok]\033[0m Python virtual environment ready.\n'

# 3. Compile Go Engine (Optional / High-Performance Port Scanner)
printf '\n\033[1;33m[2/4] Building Go Port Scanner Engine...\033[0m\n'
if command -v go >/dev/null 2>&1; then
  mkdir -p "$ROOT/engines/go/bin"
  (cd "$ROOT/engines/go" && go build -o bin/phantomscan-go .)
  printf '\033[32m[ok]\033[0m Compiled Go engine (bin/phantomscan-go)\n'
else
  printf '\033[33m[skip]\033[0m go compiler not found on PATH. Python native fallback will be used.\n'
fi

# 4. Compile Rust Engine (Optional / Deep TLS Inspector)
printf '\n\033[1;33m[3/4] Building Rust TLS Inspector Engine...\033[0m\n'
if command -v cargo >/dev/null 2>&1; then
  (cd "$ROOT/engines/rust" && cargo build --release --quiet)
  printf '\033[32m[ok]\033[0m Compiled Rust engine (target/release/phantomscan-rust)\n'
else
  printf '\033[33m[skip]\033[0m cargo compiler not found on PATH. Python native fallback will be used.\n'
fi

# 5. Setup Node Headless Browser Engine
printf '\n\033[1;33m[4/4] Setting up Node Headless Browser Engine...\033[0m\n'
if command -v npm >/dev/null 2>&1; then
  (cd "$ROOT/engines/node" && npm install --no-audit --no-fund --quiet && npx playwright install chromium --quiet || true)
  printf '\033[32m[ok]\033[0m Node browser engine & Chromium ready.\n'
else
  printf '\033[33m[skip]\033[0m npm/node not found on PATH. Python native fallback will be used.\n'
fi

# 6. Create Global CLI Launcher
mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd "$ROOT"
exec "$ROOT/.venv/bin/python" "$ROOT/phantomscan.py" "\$@"
EOF
chmod +x "$LAUNCHER"

printf '\n\033[1;32m============================================================\033[0m\n'
printf '\033[1;32mPhantomScan installation complete!\033[0m\n'
printf '\033[1;32m============================================================\033[0m\n'
printf '\nLauncher installed to: %s\n' "$LAUNCHER"
printf 'If not already in your PATH, add: \033[1;33mexport PATH="$HOME/.local/bin:$PATH"\033[0m\n\n'
printf 'Run your first scan:\n'
printf '  \033[1;37mphantomscan --target example.com --profile passive\033[0m\n'
printf '  \033[1;37mphantomscan --target example.com --profile full --debug\033[0m\n\n'
