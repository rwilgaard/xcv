# xcv (X.509 Certificate Verifier)

`xcv` is a command-line tool for inspecting, validating, and comparing X.509 certificate chains. Written in Go.

Works on macOS, Linux, and Windows.

## What it does

- Pull and verify a live TLS certificate chain from any host
- Validate signatures, expiration, and PEM order (`Leaf → Intermediates → Root`)
- Detect RFC 5280 violations and show key usage per certificate
- Compare two bundles side-by-side to inspect what changed between renewals

## Installation

### From source

```bash
make build    # produces ./xcv binary
make install  # moves binary to /usr/local/bin/xcv
```

### Using go install

```bash
go install github.com/rwilgaard/xcv/cmd/xcv@latest
```

To uninstall:
```bash
make uninstall
```

## Usage

```
xcv [--no-color] [--no-pager] [--quiet] [--version] <subcommand> [flags] <args>
```

Global flags work before or after the subcommand.

### Global flags

| Flag | Description |
|------|-------------|
| `--no-color` | Strip ANSI color codes (useful for log files and CI) |
| `--no-pager` | Print directly to stdout instead of opening a pager |
| `--quiet` | Suppress all output; rely on exit codes only |
| `--version` | Print version and exit |
| `--help` | Show help |

---

### 1. Live TLS Check

Fetch and verify certificates directly from a host:

```bash
xcv check example.com
xcv check example.com:8443
xcv check https://example.com
xcv check example.com --port 8443
```

Checks expiry, signatures, and the order the server presented. Missing root CA is informational — servers normally don't send it.

---

### 2. Single-File Chain Validation

Validate a PEM certificate chain file:

```bash
xcv validate cert_chain.pem
```

Checks the chain is complete, signatures are valid, nothing is expired, certs are in the right order, and RFC 5280 is satisfied.

---

### 3. Certificate Inspection

Display detailed information about a PEM file without running chain validation:

```bash
xcv inspect cert.pem
```

Shows subject, issuer, serial, validity, key usage, and any RFC issues. No PASS/FAIL — just information. Useful when you have a single cert or an incomplete bundle and don't need full chain verification.

---

### 4. Renewal Comparison

Compare two certificate bundles side-by-side (old on left, new on right):

```bash
xcv compare old_chain.pem new_chain.pem
```

Shows each chain position as identical, renewed, different, added, or removed. No PASS/FAIL — inspect the diff and decide.

---

### Subcommand help

```bash
xcv check --help
xcv validate --help
xcv inspect --help
xcv compare --help
```

### Shell completions

```bash
xcv completion bash   # or: zsh, fish, powershell
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Passed — chain valid, renewal clean, or parse succeeded |
| `1` | Failed — broken chain, expired cert, wrong order, or unexpected changes |

Works well in pre-commit hooks, CI pipelines, or deployment scripts.

## License

MIT — see [LICENSE](LICENSE).
