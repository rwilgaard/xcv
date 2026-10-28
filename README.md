# xcv (X.509 Certificate Verifier)

`xcv` is a command-line tool for inspecting, validating, and comparing X.509 certificate chains. Written in Go.

Works on macOS, Linux, and Windows.

## What it does

- Pull and verify a live TLS certificate chain from any host
- Validate signatures, expiration, and PEM order (`Leaf → Intermediates → Root`)
- Detect RFC 5280 violations and show key usage per certificate
- Compare two bundles side-by-side to inspect what changed between renewals
- Verify a private key corresponds to a certificate's public key
- Rewrite a bundle in the correct chain order

## Installation

### Homebrew

```bash
brew install rwilgaard/tap/xcv
```

Also available as a Nix package: [rwilgaard/nix-packages](https://github.com/rwilgaard/nix-packages).

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
xcv [--no-color] [--no-pager] [--quiet] [--short] [--version] <subcommand> [flags] <args>
```

Global flags work before or after the subcommand.

### Global flags

| Flag | Description |
|------|-------------|
| `--no-color` | Strip ANSI color codes (useful for log files and CI) |
| `--no-pager` | Print directly to stdout instead of opening a pager |
| `--quiet` | Suppress all output; rely on exit codes only |
| `-s`, `--short` | One line per certificate (role, validity, days left, SHA-256 fingerprint prefix, CN) plus a summary of the checks; applies to `check`, `validate` and `show` |
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

Checks expiry, signatures, hostname match, completeness, and the order the server presented. A missing root certificate is informational — servers normally don't send it. Connections time out after 10 seconds.

A server that sends only its leaf certificate fails when the leaf's issuer is an intermediate. xcv fetches the issuer from the certificate's AIA URL to tell an intermediate from a root, and prints the URL so you can add it. Browsers often fetch missing intermediates themselves, so a site can look fine in Chrome and still break curl, Java, and mobile clients.

Roles come from chain structure, not names: a cross-signed root (e.g. "GTS Root R4" issued by GlobalSign) is not self-signed, so it shows as an intermediate.

---

### 2. Single-File Chain Validation

Validate a PEM certificate chain file:

```bash
xcv validate cert_chain.pem
```

Checks signatures are valid, nothing is expired, certs are in the right order, and RFC 5280 is satisfied. A missing root certificate is informational — most bundles don't ship it. Pass `--require-root` to fail without one:

```bash
xcv validate --require-root full_chain.pem
```

Like `check`, a leaf-only file fails when its issuer is an intermediate. This fetches the issuer over AIA; pass `--offline` to skip the fetch (the result is then a warning).

Read from stdin with `-`, or pipe directly into `validate`/`show`:

```bash
kubectl get secret tls -o jsonpath='{.data.tls\.crt}' | base64 -d | xcv validate
```

---

### 3. Certificate Inspection

Display detailed information about a PEM file without running chain validation:

```bash
xcv show cert.pem
```

Shows subject, issuer, serial, validity, key usage, and any RFC issues. No PASS/FAIL — just information. Useful when you have a single cert or an incomplete bundle and don't need full chain verification.

---

### 4. Renewal Comparison

Compare two certificate bundles side-by-side (old on left, new on right):

```bash
xcv diff old_chain.pem new_chain.pem
```

Shows each chain position as identical, renewed, different, added, or removed. No PASS/FAIL — inspect the diff and decide.

---

### 5. Cert/Key Match

Verify a certificate and private key correspond:

```bash
xcv match cert.pem key.pem
```

Works regardless of argument order — xcv detects which file is the cert and which is the key. If the cert file holds a chain, the key is matched against the leaf.

---

### 6. Chain Reorder

Rewrite a PEM bundle in chain order (`Leaf → Intermediates → Root`):

```bash
xcv reorder bundle.pem > fixed.pem
xcv reorder bundle.pem -o bundle.pem   # in place
```

Certificates that aren't part of the chain, and duplicates, are dropped with a note on stderr. Stdout only ever gets PEM, so it's safe to pipe into `xcv validate`.

---

### Subcommand help

```bash
xcv check --help
xcv validate --help
xcv show --help
xcv diff --help
xcv match --help
xcv reorder --help
```

### Shell completions

```bash
xcv completion bash   # or: zsh, fish, powershell
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Passed — chain valid, renewal clean, or parse succeeded |
| `1` | Failed — broken chain, expired cert, wrong order, or key mismatch |

Works well in pre-commit hooks, CI pipelines, or deployment scripts.

## License

MIT — see [LICENSE](LICENSE).
