package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

var version = "dev"

func main() {
	root := flag.NewFlagSet("xcv", flag.ContinueOnError)
	root.SetOutput(os.Stdout)
	noColorFlag := root.Bool("no-color", false, "Strip ANSI color codes from output")
	quietFlag := root.Bool("quiet", false, "Suppress all output; rely on exit codes only")
	versionFlag := root.Bool("version", false, "Print version and exit")
	root.Usage = func() {
		fmt.Printf(`xcv - X.509 certificate chain validator

Usage:
  xcv [--no-color] [--quiet] <subcommand> [subcommand-flags] <args>
  xcv --version
  xcv --help

Subcommands:
  check <host[:port]>     Fetch and validate TLS certificates from a live host
  inspect <file>          Display certificate details without chain validation
  validate <file>         Validate a PEM certificate chain file
  compare <new> <old>     Compare two PEM certificate chain files

Flags:
  --no-color    Strip ANSI color codes from output
  --quiet       Suppress all output; rely on exit codes only
  --version     Print version and exit
  --help        Show this help

Note:
  Global flags must appear before the subcommand.

Exit codes:
  0   Validation or comparison passed
  1   Validation or comparison failed, or error
`)
	}

	if err := root.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Printf("xcv version %s\n", version)
		os.Exit(0)
	}

	noColor = *noColorFlag
	quiet = *quietFlag
	if noColor {
		Green, Red, Yellow, Cyan, Bold, Reset = "", "", "", "", "", ""
	}

	args := root.Args()
	if len(args) == 0 {
		root.Usage()
		os.Exit(1)
	}

	switch args[0] {
	case "check":
		runCheck(args[1:])
	case "inspect":
		runInspect(args[1:])
	case "validate":
		runValidate(args[1:])
	case "compare":
		runCompare(args[1:])
	default:
		printErr(fmt.Sprintf("unknown subcommand %q", args[0]))
		root.Usage()
		os.Exit(1)
	}
}

// parseHostPort extracts host and port from user input.
// Accepts: example.com, example.com:8443, https://example.com, https://example.com:8443
func parseHostPort(input string, defaultPort int) (host string, port int, err error) {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	if i := strings.Index(input, "/"); i != -1 {
		input = input[:i]
	}
	h, p, splitErr := net.SplitHostPort(input)
	if splitErr != nil {
		return input, defaultPort, nil
	}
	portNum, convErr := strconv.Atoi(p)
	if convErr != nil {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, portNum, nil
}

func runCheck(args []string) {
	fs := flag.NewFlagSet("xcv check", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	portFlag := fs.Int("port", 443, "TCP port to connect to (overridden by port in host argument)")
	fs.Usage = func() {
		fmt.Print(`Usage:
  xcv check <host[:port]>

Fetch and validate TLS certificates from a live host. Checks certificate
expiry, cryptographic signatures, and chain order. Root CA absence is
treated as informational — servers normally omit the root.

Accepts: example.com, example.com:8443, https://example.com

Flags:
  --port    TCP port (default: 443, overridden if port given in host arg)

Exit codes:
  0   All certificates valid and correctly ordered
  1   Validation failed or connection error
`)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	host, port, err := parseHostPort(fs.Arg(0), *portFlag)
	if err != nil {
		printErr(err.Error())
		os.Exit(1)
	}

	r, err := Check(host, port)
	if err != nil {
		printErr(err.Error())
		os.Exit(1)
	}
	PrintCheckResult(r)
	if !r.Passed {
		os.Exit(1)
	}
}

func runInspect(args []string) {
	fs := flag.NewFlagSet("xcv inspect", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Print(`Usage:
  xcv inspect <file>

Display certificate details from a PEM file without chain validation.
Shows subject, issuer, serial, validity, key usage, and RFC compliance
issues for each certificate. No PASS/FAIL — information only.

Exit codes:
  0   File parsed successfully
  1   File could not be parsed
`)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	r, err := Inspect(fs.Arg(0))
	if err != nil {
		printErr(err.Error())
		os.Exit(1)
	}
	PrintInspectResult(r)
}

func runValidate(args []string) {
	fs := flag.NewFlagSet("xcv validate", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Print(`Usage:
  xcv validate <file>

Validate a PEM certificate chain file. Checks certificate expiry,
cryptographic signatures, chain completeness, and physical PEM ordering.

Exit codes:
  0   Chain is valid
  1   Chain is invalid or file could not be parsed
`)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	r, err := Validate(fs.Arg(0))
	if err != nil {
		printErr(err.Error())
		os.Exit(1)
	}
	PrintValidationResult(r)
	if !r.Passed {
		os.Exit(1)
	}
}

func runCompare(args []string) {
	fs := flag.NewFlagSet("xcv compare", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Print(`Usage:
  xcv compare <new_file> <old_file>

Compare two PEM certificate chain files. Passes when only the leaf
certificate has changed (a clean renewal), or when chains are identical.

Exit codes:
  0   Leaf-only renewal or identical chains
  1   Unexpected changes or file could not be parsed
`)
	}

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if fs.NArg() < 2 {
		fs.Usage()
		os.Exit(1)
	}

	r, err := Compare(fs.Arg(0), fs.Arg(1))
	if err != nil {
		printErr(err.Error())
		os.Exit(1)
	}
	PrintComparisonResult(r)
	if !r.Passed {
		os.Exit(1)
	}
}
