package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rwilgaard/xcv/internal/xcv"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:           "xcv",
		Short:         "X.509 certificate chain validator",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if xcv.NoColor {
				xcv.Green, xcv.Red, xcv.Yellow, xcv.Cyan, xcv.Bold, xcv.Reset = "", "", "", "", "", ""
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().BoolVar(&xcv.NoColor, "no-color", false, "Strip ANSI color codes from output")
	rootCmd.PersistentFlags().BoolVar(&xcv.Quiet, "quiet", false, "Suppress all output; rely on exit codes only")

	rootCmd.AddCommand(newCheckCmd(), newInspectCmd(), newValidateCmd(), newCompareCmd())

	if err := rootCmd.Execute(); err != nil {
		printErr(err.Error())
		os.Exit(1)
	}
}

func printErr(msg string) {
	fmt.Fprintf(os.Stderr, "%s%sError:%s %s\n", xcv.Red, xcv.Bold, xcv.Reset, msg)
}

func newCheckCmd() *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "check <host[:port]>",
		Short: "Fetch and validate TLS certificates from a live host",
		Long: `Connect to a host over TLS, retrieve the presented certificate chain,
and validate expiry, cryptographic signatures, and chain order.
Root CA absence is treated as informational — servers normally omit the root.

Accepts: example.com, example.com:8443, https://example.com`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			host, p, err := xcv.ParseHostPort(args[0], port)
			if err != nil {
				return err
			}
			r, err := xcv.Check(host, p)
			if err != nil {
				return err
			}
			xcv.PrintCheckResult(r)
			if !r.Passed {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&port, "port", 443, "TCP port (overridden if port given in host argument)")
	return cmd
}

func newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file>",
		Short: "Display certificate details without chain validation",
		Long: `Parse a PEM file and display certificate details (subject, issuer, serial,
validity, key usage, RFC compliance issues) for each certificate.
No chain validation, no PASS/FAIL — information only.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := xcv.Inspect(args[0])
			if err != nil {
				return err
			}
			xcv.PrintInspectResult(r)
			return nil
		},
	}
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a PEM certificate chain file",
		Long: `Validate a PEM certificate chain file. Checks certificate expiry,
cryptographic signatures, chain completeness, and physical PEM ordering.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := xcv.Validate(args[0])
			if err != nil {
				return err
			}
			xcv.PrintValidationResult(r)
			if !r.Passed {
				os.Exit(1)
			}
			return nil
		},
	}
}

func newCompareCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "compare <new_file> <old_file>",
		Short: "Compare two PEM certificate chain files",
		Long: `Compare two PEM certificate chain files. Passes when only the leaf
certificate has changed (a clean renewal), or when chains are identical.`,
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := xcv.Compare(args[0], args[1])
			if err != nil {
				return err
			}
			xcv.PrintComparisonResult(r)
			if !r.Passed {
				os.Exit(1)
			}
			return nil
		},
	}
}
