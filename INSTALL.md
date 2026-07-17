# PhantomScan Installation and Usage Guide

PhantomScan is for authorized security assessment only. Run it only against systems you own or have explicit written permission to test.

## Windows

1. Install Python 3.10 or newer from <https://www.python.org/downloads/windows/>.
2. Download or clone this repository.
3. Open the `Phantomscan` folder.
4. Double-click `install.bat`.
5. The installer creates a virtual environment, installs Python dependencies, creates `phantomscan-cli.bat`, and places `PhantomScan Launcher.bat` on your Desktop.

Start the option-based launcher:

```bat
PhantomScan Launcher.bat
```

Run the CLI directly:

```bat
phantomscan-cli.bat --target example.com --profile passive
phantomscan-cli.bat --target example.com --profile full --debug
phantomscan-cli.bat --target 127.0.0.1 --profile network --ports top100
```

## Linux

1. Install Python 3.10 or newer.
2. Clone the repository.
3. Run the installer.

```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install.sh
```

If `~/.local/bin` is not already in your shell PATH, run:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

After that, start PhantomScan from inside the project folder:

```bash
cd phantomscan
phantomscan --target example.com --profile passive
```

## macOS

1. Install Python 3.10 or newer. With Homebrew:

```bash
brew install python
```

2. Clone and install:

```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install_macos.sh
```

3. Add `~/.local/bin` to PATH if needed:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

4. Run:

```bash
phantomscan --target example.com --profile passive
```

## Option-Based Launcher

The Windows launcher opens a menu with:

- Passive scan: HTTP/DNS/email checks only.
- Quick scan: real HTTP/DNS plus TCP/TLS fallback checks.
- Full scan: real TCP port scanning and TLS inspection.
- API scan: API-oriented profile.
- Network scan: network-oriented profile.
- Custom profile: choose from available profiles.
- JSON output toggle.
- HTML auto-open toggle.
- Debug logging toggle.

Reports are saved in `reports/`. Logs are saved in `logs/`.

## CLI Reference

Basic scans:

```bash
phantomscan --target example.com
phantomscan --target example.com --profile passive
phantomscan --target example.com --profile full
phantomscan --target https://example.com/app --profile quick
```

Port options:

```bash
phantomscan --target example.com --ports top100
phantomscan --target example.com --ports top1000
phantomscan --target example.com --ports 80,443,8080
phantomscan --target example.com --ports 1-1000
```

Reporting:

```bash
phantomscan --target example.com --json
phantomscan --target example.com --json-out findings.json
phantomscan --target example.com --checklist
phantomscan --target example.com --compliance owasp
```

Debugging:

```bash
phantomscan --target example.com --profile full --debug
phantomscan --target example.com --log-file logs/example.log
```

## Output Files

- HTML report: `reports/<target>.html`
- JSON report: `reports/<target>.json`
- False-positive log: `reports/fp_log_<target>.json`
- Scan logs: `logs/phantomscan_<target>_<timestamp>.log`

## Notes

Full scans perform real network checks and can take 20-60 seconds depending on target reachability, DNS latency, and selected ports.
