# xcv (X.509 Chain Validator)

`xcv` is a high-performance, zero-dependency command-line utility written in pure Go for validating X.509 certificate chains, enforcing correct physical PEM ordering, and comparing old and new certificate bundles side-by-side.

Unlike standard scripts that run external OpenSSL subprocesses, `xcv` performs all certificate parsing, cryptographic signature validation, expiration checking, and ordering verification entirely in-memory using Go's built-in standard library (`crypto/x509`). It is 100% portable and behaves identically on macOS, Linux, and Windows, regardless of the host's OpenSSL version.

## Key Features

- **Logical Chain Reconstruction:** Automatically extracts all PEM blocks, identifies the leaf (end-entity) certificate, and traces parentage up to the root, regardless of the physical order of blocks in the file.
- **Physical Order Enforcement:** Validates that the physical certificates in your PEM bundle appear in the correct structural order (`Leaf` -> `Intermediates` -> `Root`), which is required by proxies, web servers, and load balancers.
- **Cryptographic Signature Verification:** Natively executes full path validation, confirming that every certificate in the chain indeed signed the one below it.
- **Expiration & Status Check:** Automatically analyzes expiration dates, reporting active days remaining or detailed warnings if a certificate is expired or not yet active.
- **Side-by-Side Comparison:** Compare old and new PEM bundles to guarantee that **only the leaf certificate was renewed**, ensuring that intermediate or root certificates were not accidentally dropped or changed.
- **Zero Dependencies:** Compiles into a single static binary. No Python, no pip libraries, and no OpenSSL installations required.

## Installation

Compile into a standalone executable using `make`:

```bash
make build
```

Move the compiled binary to your bin path for global access:
```bash
make install
```

To uninstall:
```bash
make uninstall
```

## Usage

### Global flags

```
xcv [--no-color] [--quiet] [--version] [--help] <subcommand> ...
```

| Flag | Description |
|------|-------------|
| `--no-color` | Strip ANSI color codes (useful for log files and CI) |
| `--quiet` | Suppress all output; rely on exit codes only |
| `--version` | Print version and exit |
| `--help` | Show help |

**Note:** Global flags must appear before the subcommand: `xcv --quiet validate cert.pem`, not `xcv validate --quiet cert.pem`.

### 1. Single-File Chain Validation

Verify that a PEM certificate chain is complete, cryptographically valid, and in the correct physical order:

```bash
xcv validate cert_chain.pem
```

### 2. Dual-File Renewal Verification

Verify that a new certificate bundle is a clean renewal of the old one:

```bash
xcv compare new_chain.pem old_chain.pem
```

### Subcommand help

```bash
xcv validate --help
xcv compare --help
```

## Exit Codes
- `0`: Validation/Comparison succeeded (perfect chain / perfect leaf renewal).
- `1`: Validation/Comparison failed (broken chain, expired certificates, incorrect physical order, or unexpected intermediate changes).

Ideal for usage in pre-commit hooks, CI/CD deployment pipelines, or gateway verification scripts.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
