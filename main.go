package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n  Single Validation: %s <file>\n  Chain Comparison:  %s <new_file> <old_file>\n", os.Args[0], os.Args[0])
		os.Exit(1)
	}

	if len(os.Args) >= 3 {
		r, err := Compare(os.Args[1], os.Args[2])
		if err != nil {
			printErr(err.Error())
			os.Exit(1)
		}
		PrintComparisonResult(r)
		if !r.Passed {
			os.Exit(1)
		}
	} else {
		r, err := Validate(os.Args[1])
		if err != nil {
			printErr(err.Error())
			os.Exit(1)
		}
		PrintValidationResult(r)
		if !r.Passed {
			os.Exit(1)
		}
	}
}
