# Engines

## Go Port Scanner

Purpose: concurrent TCP connect checks and service exposure classification.

Build:

```bash
cd engines/go
go build -o bin/phantomscan-go .
```

Test:

```bash
go test ./...
```

## Rust TLS Engine

Purpose: TLS inspection hook with conservative grading. The lightweight build checks TLS port reachability and is structured for deeper certificate parsing.

Build:

```bash
cd engines/rust
cargo build --release
```

Test:

```bash
cargo test
```

## Node Browser Engine

Purpose: safe page signal detection for login pages and browser-visible behavior.

Test:

```bash
cd engines/node
node --test
```

