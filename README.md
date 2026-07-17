# PhantomScan

PhantomScan 2.0.0 is an authorized security assessment platform for systems the operator owns or has explicit written authorization to test.

```
                +--------------------+
                | phantomscan.py CLI |
                +---------+----------+
                          |
       +------------------+------------------+
       |                  |                  |
  Python recon       Go port engine     Rust TLS engine
       |                  |                  |
       +------------------+------------------+
                          |
                    SQLite + reports
                          |
                    Node browser engine
```

## Quick Start

Windows option-based launcher:

```bat
install.bat
PhantomScan Launcher.bat
```

Linux:

```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install.sh
phantomscan --target example.com --profile passive
```

macOS:

```bash
git clone https://github.com/anshchavda02/Phantomscan.git phantomscan
cd phantomscan
bash scripts/install_macos.sh
phantomscan --target example.com --profile passive
```

Local development:

```bash
python phantomscan.py --target example.com --profile passive
python phantomscan.py --target example.com --json
```

See [INSTALL.md](INSTALL.md) for the full step-by-step guide for Windows, Linux, macOS, CLI usage, and option-based launcher usage.

## Installation

Linux, macOS, or Windows WSL:

```bash
bash scripts/check_deps.sh
bash scripts/build.sh
python phantomscan.py --target example.com --profile passive
```

## Dependencies

| Feature | Required | Optional |
| --- | --- | --- |
| CLI, reports, SQLite | Python 3.10+ | none |
| TCP port scan | Go 1.21+ | nmap |
| TLS reachability | Rust 2021 toolchain | full TLS parser build |
| Browser signals | Node.js 18+ | Playwright |

## Ethical Use Policy

Run PhantomScan only against targets you own or are explicitly authorized to assess. The tool prints an authorization warning on startup, normalizes the supplied target, and keeps generated checks scoped to that target.

## CLI Examples

```bash
python phantomscan.py --target example.com
python phantomscan.py --target https://example.com/app --profile passive --json
python phantomscan.py --batch targets.txt --threads 5
python phantomscan.py --target example.com --ports top100
python phantomscan.py --target example.com --confidence high
```
