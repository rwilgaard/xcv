# xcv (X.509 Certificate Verifier)

`xcv` is a command-line utility written in pure Go for inspecting, validating, and comparing X.509 certificate chains.

It performs all certificate parsing, cryptographic signature validation, expiration checking, RFC 5280 compliance analysis, and ordering verification entirely in-memory using Go's standard library (`crypto/x509`). Portable across macOS, Linux, and Windows.

## Features

- **Live TLS Inspection:** Connect to any host and retrieve the presented certificate chain directly over TLS.
- **Logical Chain Reconstruction:** Identifies the leaf certificate and traces parentage up to the root, regardless of physical PEM order.
- **Physical Order Enforcement:** Validates that certificates in a PEM bundle appear in the correct order (`Leaf → Intermediates → Root`), required by most web servers, proxies, and load balancers.
- **Cryptographic Signature Verification:** Confirms that every certificate in the chain was signed by the one above it.
- **Expiration & Status Check:** Reports active days remaining, or warns if a certificate is expired or not yet active.
- **RFC 5280 Compliance:** Detects common violations — non-positive serial numbers, oversized serials, missing BasicConstraints on CA certificates, non-critical KeyUsage extensions, and more.
- **Key Usage Display:** Shows Key Usage and Extended Key Usage attributes per certificate.
- **Side-by-Side Comparison:** Compare two PEM bundles to confirm only the leaf certificate changed — intermediates and root untouched.
- **Self-Signed Detection:** Distinguishes genuine root CAs (`CA:TRUE` + self-signed) from self-signed leaf certificates with no CA constraints.

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
xcv [--no-color] [--quiet] [--version] <subcommand> [flags] <args>
```

Global flags can appear before or after the subcommand.

### Global flags

| Flag | Description |
|------|-------------|
| `--no-color` | Strip ANSI color codes (useful for log files and CI) |
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

Validates expiry, cryptographic signatures, and server-presented order. Root CA absence is treated as informational — servers normally omit the root.

---

### 2. Single-File Chain Validation

Validate a PEM certificate chain file:

```bash
xcv validate cert_chain.pem
```

Checks chain completeness, cryptographic signatures, expiration, physical PEM order, and RFC 5280 compliance.

---

### 3. Certificate Inspection

Display detailed information about certificates in a PEM file without chain validation:

```bash
xcv inspect cert.pem
```

Shows subject, issuer, serial, validity, key usage, and any RFC compliance issues. No PASS/FAIL — information only. Useful for inspecting a single certificate or a bundle without needing a complete chain.

---

### 4. Dual-File Renewal Verification

Compare a new certificate bundle against an old one:

```bash
xcv compare new_chain.pem old_chain.pem
```

Passes when only the leaf certificate changed (clean renewal). Fails if intermediates or root certificates were modified, dropped, or replaced.

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

Suitable for pre-commit hooks, CI/CD pipelines, and deployment verification scripts.

## License

MIT — see [LICENSE](LICENSE).
