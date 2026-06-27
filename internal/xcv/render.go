package xcv

import (
	"fmt"
	"strings"
	"time"
)

var (
	Green  = "\033[92m"
	Red    = "\033[91m"
	Yellow = "\033[93m"
	Cyan   = "\033[96m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

var (
	NoColor bool
	Quiet   bool
)

var (
	sepEq   = strings.Repeat("=", 80)
	sepDash = strings.Repeat("-", 80)
)

func printChainTree(ordered []*CertDetails) {
	fmt.Printf("%s[Chain Structure]%s\n", Bold, Reset)
	if len(ordered) == 0 {
		fmt.Println("  Empty chain")
		return
	}

	n := len(ordered)
	for i := range n {
		idx := n - 1 - i
		cert := ordered[idx]
		indent := strings.Repeat("  ", i)

		var label string
		switch i {
		case 0:
			switch {
			case cert.IsSelfSigned && cert.Cert.IsCA:
				label = fmt.Sprintf("%s[Root]%s        ", Cyan, Reset)
			case cert.IsSelfSigned:
				label = fmt.Sprintf("%s[Leaf*]%s       ", Green, Reset)
			default:
				label = fmt.Sprintf("%s[Anchor]%s      ", Yellow, Reset)
			}
		case n - 1:
			label = fmt.Sprintf("%s[Leaf]%s        ", Green, Reset)
		default:
			label = fmt.Sprintf("%s[Interm %d]%s    ", Yellow, n-1-i, Reset)
		}

		connector := ""
		if i > 0 {
			connector = "└── "
		}
		fmt.Printf("  %s%s%sCN=%s%s%s\n", label, indent, connector, Bold, cert.SubjectCN, Reset)
	}
	fmt.Println()
}

// PrintCheckResult renders a CheckResult to stdout.
func PrintCheckResult(r *CheckResult) {
	if Quiet {
		return
	}
	fmt.Printf("%s%sTLS Certificate Check%s\n", Bold, Cyan, Reset)
	fmt.Printf("Host: %s:%d\n", r.Host, r.Port)
	fmt.Println(sepEq)
	fmt.Println()

	fmt.Printf("Server presented %d certificate(s).\n", len(r.Certs))
	if !r.RootPresent {
		fmt.Printf("%sNote: Root CA not included in server response (normal for TLS).%s\n", Yellow, Reset)
	}
	fmt.Println(sepDash)
	fmt.Println()

	printChainTree(r.Ordered)
	fmt.Println(sepDash)
	fmt.Println()

	for idx, s := range r.Statuses {
		cert := s.Cert
		color := Yellow
		if idx == 0 {
			color = Green
		} else if idx == len(r.Statuses)-1 && cert.IsSelfSigned && cert.Cert.IsCA {
			color = Cyan
		}
		fmt.Printf("[%d] %s%sCertificate Role: %s%s\n", idx+1, color, Bold, s.Role, Reset)
		fmt.Printf("    Subject CN:   %s%s%s\n", Bold, cert.SubjectCN, Reset)
		fmt.Printf("    Subject DN:   %s\n", cert.SubjectDN)
		fmt.Printf("    Issuer CN:    %s\n", cert.IssuerCN)
		fmt.Printf("    Issuer DN:    %s\n", cert.IssuerDN)
		fmt.Printf("    Serial:       %s\n", cert.Serial)
		fmt.Printf("    Validity:     %s -> %s\n", cert.NotBeforeStr, cert.NotAfterStr)

		switch {
		case s.NotYetActive:
			fmt.Printf("    Status:       %s%sNOT YET ACTIVE%s (Activates in %s)\n",
				Red, Bold, Reset, cert.Cert.NotBefore.UTC().Sub(time.Now().UTC()).Round(time.Second))
		case s.Expired:
			fmt.Printf("    Status:       %s%sEXPIRED%s (Expired %s ago)\n",
				Red, Bold, Reset, time.Now().UTC().Sub(cert.Cert.NotAfter.UTC()).Round(time.Second))
		default:
			fmt.Printf("    Status:       %s%sACTIVE%s (%d days remaining)\n", Green, Bold, Reset, s.DaysLeft)
		}

		if cert.Skid != "" {
			fmt.Printf("    SKID:         %s\n", cert.Skid)
		}
		if cert.Akid != "" {
			fmt.Printf("    AKID:         %s\n", cert.Akid)
		}
		if len(cert.KeyUsages) > 0 {
			fmt.Printf("    Key Usage:    %s\n", strings.Join(cert.KeyUsages, ", "))
		}
		if len(cert.ExtKeyUsages) > 0 {
			fmt.Printf("    Ext Key Use:  %s\n", strings.Join(cert.ExtKeyUsages, ", "))
		}
		for _, issue := range cert.ComplianceIssues {
			fmt.Printf("    %s%sRFC Violation:%s %s\n", Red, Bold, Reset, issue)
		}
		if s.AkidMismatch {
			parent := r.Ordered[idx+1]
			fmt.Printf("    %s%sWarning: AKID does not match parent SKID!%s\n", Red, Bold, Reset)
			fmt.Printf("             This cert AKID: %s\n", cert.Akid)
			fmt.Printf("             Parent cert SKID: %s\n", parent.Skid)
		}
		fmt.Println()
	}

	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[Cryptographic Signature Chain Verification]%s\n", Bold, Reset)
	if r.SignatureErr == nil {
		fmt.Printf("  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Chain signature verification succeeded.")
	} else {
		fmt.Printf("  Result: %s%sFAIL%s\n", Red, Bold, Reset)
		fmt.Printf("  Detail: Signature verification failed:\n          %v\n", r.SignatureErr)
	}

	fmt.Println()
	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[Server-Presented Certificate Order]%s\n", Bold, Reset)
	fmt.Println("  Expected order (Leaf to Root/Anchor):")
	for idx, cert := range r.Ordered {
		roleName := getCertRoleName(idx, len(r.Ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		fmt.Printf("    %d. CN=%s%s%s (%s)\n", idx+1, Bold, cert.SubjectCN, Reset, roleName)
	}

	fmt.Println("\n  Physical order as sent by server:")
	for idx, e := range r.Order.Physical {
		var roleDisp string
		if e.LogicalIndex != -1 {
			roleDisp = fmt.Sprintf("(%s)", e.Role)
		} else {
			roleDisp = fmt.Sprintf("(%sUnrelated certificate%s)", Red, Reset)
		}
		fmt.Printf("    %d. CN=%s%s%s %s\n", idx+1, Bold, e.Cert.SubjectCN, Reset, roleDisp)
	}

	if r.Order.Correct {
		fmt.Printf("\n  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Server sent certificates in correct order (Leaf → Intermediates).")
	} else {
		fmt.Printf("\n  Result: %s%sFAIL%s\n", Red, Bold, Reset)
		fmt.Println("  Detail: Server sent certificates in incorrect order.")
		for _, reason := range r.Order.Reasons {
			fmt.Printf("          - %s\n", reason)
		}
	}

	fmt.Println()
	fmt.Println(sepEq)

	if !r.RootPresent {
		fmt.Printf("%sNote: Root CA absent from server chain (expected — validated against presented intermediates only).%s\n", Yellow, Reset)
	}
	if r.Passed {
		fmt.Printf("%s%sSUCCESS: Certificates are valid, properly ordered, and cryptographically sound.%s\n", Green, Bold, Reset)
	} else {
		fmt.Printf("%s%sFAILURE: TLS certificate check failed.%s\n", Red, Bold, Reset)
		fmt.Printf("Reasons: %s\n", strings.Join(r.FailReasons, ", "))
	}
}

// PrintInspectResult renders an InspectResult to stdout.
func PrintInspectResult(r *InspectResult) {
	if Quiet {
		return
	}
	fmt.Printf("%s%sCertificate Inspector%s\n", Bold, Cyan, Reset)
	fmt.Printf("File: %s\n", r.Path)
	fmt.Println(sepEq)
	fmt.Println()
	fmt.Printf("Found %d certificate(s) in the file.\n", len(r.Certs))
	fmt.Println(sepDash)
	fmt.Println()

	for _, cert := range r.Certs {
		color := Green
		switch {
		case cert.IsSelfSigned && cert.Cert.IsCA:
			color = Cyan
		case cert.Cert.IsCA:
			color = Yellow
		}

		role := "Leaf"
		switch {
		case cert.IsSelfSigned && cert.Cert.IsCA:
			role = "Root CA (Self-Signed)"
		case cert.Cert.IsCA:
			role = "CA"
		case cert.IsSelfSigned:
			role = "Leaf (Self-Signed, No CA)"
		}

		fmt.Printf("[%d] %s%s%s\n", cert.Index, color, Bold, Reset)
		fmt.Printf("    Role:         %s%s%s%s\n", color, Bold, role, Reset)
		fmt.Printf("    Subject CN:   %s%s%s\n", Bold, cert.SubjectCN, Reset)
		fmt.Printf("    Subject DN:   %s\n", cert.SubjectDN)
		fmt.Printf("    Issuer CN:    %s\n", cert.IssuerCN)
		fmt.Printf("    Issuer DN:    %s\n", cert.IssuerDN)
		fmt.Printf("    Serial:       %s\n", cert.Serial)
		fmt.Printf("    Validity:     %s -> %s\n", cert.NotBeforeStr, cert.NotAfterStr)

		switch {
		case time.Now().UTC().Before(cert.Cert.NotBefore.UTC()):
			fmt.Printf("    Status:       %s%sNOT YET ACTIVE%s\n", Red, Bold, Reset)
		case time.Now().UTC().After(cert.Cert.NotAfter.UTC()):
			fmt.Printf("    Status:       %s%sEXPIRED%s\n", Red, Bold, Reset)
		default:
			daysLeft := int(cert.Cert.NotAfter.UTC().Sub(time.Now().UTC()).Hours() / 24)
			fmt.Printf("    Status:       %s%sACTIVE%s (%d days remaining)\n", Green, Bold, Reset, daysLeft)
		}

		if cert.Skid != "" {
			fmt.Printf("    SKID:         %s\n", cert.Skid)
		}
		if cert.Akid != "" {
			fmt.Printf("    AKID:         %s\n", cert.Akid)
		}
		if len(cert.KeyUsages) > 0 {
			fmt.Printf("    Key Usage:    %s\n", strings.Join(cert.KeyUsages, ", "))
		}
		if len(cert.ExtKeyUsages) > 0 {
			fmt.Printf("    Ext Key Use:  %s\n", strings.Join(cert.ExtKeyUsages, ", "))
		}
		for _, issue := range cert.ComplianceIssues {
			fmt.Printf("    %s%sRFC Violation:%s %s\n", Red, Bold, Reset, issue)
		}
		fmt.Println()
	}

	fmt.Println(sepEq)
}

// PrintValidationResult renders a ValidationResult to stdout.
func PrintValidationResult(r *ValidationResult) {
	if Quiet {
		return
	}
	fmt.Printf("%s%sCertificate Chain Validation Utility%s\n", Bold, Cyan, Reset)
	fmt.Printf("File: %s\n", r.Path)
	fmt.Println(sepEq)
	fmt.Println()

	fmt.Printf("Found %d certificates in the file.\n", len(r.ParsedCerts))
	fmt.Println(sepDash)
	fmt.Println()

	printChainTree(r.Ordered)
	fmt.Println(sepDash)
	fmt.Println()

	for idx, s := range r.Statuses {
		cert := s.Cert
		color := Yellow
		if idx == 0 {
			color = Green
		} else if idx == len(r.Statuses)-1 && cert.IsSelfSigned && cert.Cert.IsCA {
			color = Cyan
		}
		fmt.Printf("[%d] %s%sCertificate Role: %s%s\n", idx+1, color, Bold, s.Role, Reset)
		fmt.Printf("    Subject CN:   %s%s%s\n", Bold, cert.SubjectCN, Reset)
		fmt.Printf("    Subject DN:   %s\n", cert.SubjectDN)
		fmt.Printf("    Issuer CN:    %s\n", cert.IssuerCN)
		fmt.Printf("    Issuer DN:    %s\n", cert.IssuerDN)
		fmt.Printf("    Serial:       %s\n", cert.Serial)
		fmt.Printf("    Validity:     %s -> %s\n", cert.NotBeforeStr, cert.NotAfterStr)

		switch {
		case s.NotYetActive:
			fmt.Printf("    Status:       %s%sNOT YET ACTIVE%s (Activates in %s)\n",
				Red, Bold, Reset, cert.Cert.NotBefore.UTC().Sub(time.Now().UTC()).Round(time.Second))
		case s.Expired:
			fmt.Printf("    Status:       %s%sEXPIRED%s (Expired %s ago)\n",
				Red, Bold, Reset, time.Now().UTC().Sub(cert.Cert.NotAfter.UTC()).Round(time.Second))
		default:
			fmt.Printf("    Status:       %s%sACTIVE%s (%d days remaining)\n", Green, Bold, Reset, s.DaysLeft)
		}

		if cert.Skid != "" {
			fmt.Printf("    SKID:         %s\n", cert.Skid)
		}
		if cert.Akid != "" {
			fmt.Printf("    AKID:         %s\n", cert.Akid)
		}
		if len(cert.KeyUsages) > 0 {
			fmt.Printf("    Key Usage:    %s\n", strings.Join(cert.KeyUsages, ", "))
		}
		if len(cert.ExtKeyUsages) > 0 {
			fmt.Printf("    Ext Key Use:  %s\n", strings.Join(cert.ExtKeyUsages, ", "))
		}
		for _, issue := range cert.ComplianceIssues {
			fmt.Printf("    %s%sRFC Violation:%s %s\n", Red, Bold, Reset, issue)
		}
		if s.AkidMismatch {
			parent := r.Ordered[idx+1]
			fmt.Printf("    %s%sWarning: AKID does not match parent SKID!%s\n", Red, Bold, Reset)
			fmt.Printf("             This cert AKID: %s\n", cert.Akid)
			fmt.Printf("             Parent cert SKID: %s\n", parent.Skid)
		}
		fmt.Println()
	}

	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[Cryptographic Signature Chain Verification]%s\n", Bold, Reset)
	if r.SignatureErr == nil {
		fmt.Printf("  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Chain signature verification succeeded.")
	} else {
		fmt.Printf("  Result: %s%sFAIL%s\n", Red, Bold, Reset)
		fmt.Printf("  Detail: Signature verification failed:\n          %v\n", r.SignatureErr)
	}

	fmt.Println()
	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[PEM File Order Verification]%s\n", Bold, Reset)
	fmt.Println("  Expected order (Leaf to Root):")
	for idx, cert := range r.Ordered {
		roleName := getCertRoleName(idx, len(r.Ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		fmt.Printf("    %d. CN=%s%s%s (%s)\n", idx+1, Bold, cert.SubjectCN, Reset, roleName)
	}

	fmt.Println("\n  Physical order in file:")
	for idx, e := range r.Order.Physical {
		var roleDisp string
		if e.LogicalIndex != -1 {
			roleDisp = fmt.Sprintf("(%s)", e.Role)
		} else {
			roleDisp = fmt.Sprintf("(%sUnused/Unrelated certificate%s)", Red, Reset)
		}
		fmt.Printf("    %d. CN=%s%s%s %s\n", idx+1, Bold, e.Cert.SubjectCN, Reset, roleDisp)
	}

	if r.Order.Correct {
		fmt.Printf("\n  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Physical certificate order in the file matches the logical chain order (Leaf -> Intermediates -> Root).")
	} else {
		fmt.Printf("\n  Result: %s%sFAIL%s\n", Red, Bold, Reset)
		fmt.Println("  Detail: Physical certificate order in the file does NOT match the logical chain order.")
		for _, reason := range r.Order.Reasons {
			fmt.Printf("          - %s\n", reason)
		}
	}

	fmt.Println()
	fmt.Println(sepEq)

	if r.Passed {
		fmt.Printf("%s%sSUCCESS: The certificate chain is complete, valid, properly ordered, and cryptographically sound.%s\n", Green, Bold, Reset)
	} else {
		fmt.Printf("%s%sFAILURE: Chain validation failed.%s\n", Red, Bold, Reset)
		fmt.Printf("Reasons: %s\n", strings.Join(r.FailReasons, ", "))
	}
}

// PrintComparisonResult renders a ComparisonResult to stdout.
func PrintComparisonResult(r *ComparisonResult) {
	if Quiet {
		return
	}
	fmt.Printf("%s%sCertificate Chain Comparison Utility%s\n", Bold, Cyan, Reset)
	fmt.Printf("File 1 (New): %s\n", r.FileNew)
	fmt.Printf("File 2 (Old): %s\n", r.FileOld)
	fmt.Println(sepEq)
	fmt.Println()

	fmt.Printf("File 1 (New) contains %d certs (logical chain depth: %d)\n", len(r.ParsedNew), len(r.OrderedNew))
	fmt.Printf("File 2 (Old) contains %d certs (logical chain depth: %d)\n", len(r.ParsedOld), len(r.OrderedOld))
	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[Chain 1 (New) Structure]%s\n", Bold, Reset)
	printChainTree(r.OrderedNew)
	fmt.Printf("%s[Chain 2 (Old) Structure]%s\n", Bold, Reset)
	printChainTree(r.OrderedOld)
	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[Detailed Node Comparison]%s\n", Bold, Reset)

	for _, p := range r.Positions {
		fmt.Printf("Position %d:\n", p.Idx+1)

		switch p.Status {
		case StatusIdentical:
			fmt.Printf("  Role:    %s (New) vs %s (Old)\n", p.RoleNew, p.RoleOld)
			fmt.Printf("  New:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, p.New.SubjectCN, Reset, p.New.Serial, p.New.NotAfterStr)
			fmt.Printf("  Old:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, p.Old.SubjectCN, Reset, p.Old.Serial, p.Old.NotAfterStr)
			fmt.Printf("  Status:  %s%sIDENTICAL%s (The exact same certificate)\n", Green, Bold, Reset)
		case StatusRenewed:
			fmt.Printf("  Role:    %s (New) vs %s (Old)\n", p.RoleNew, p.RoleOld)
			fmt.Printf("  New:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, p.New.SubjectCN, Reset, p.New.Serial, p.New.NotAfterStr)
			fmt.Printf("  Old:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, p.Old.SubjectCN, Reset, p.Old.Serial, p.Old.NotAfterStr)
			fmt.Printf("  Status:  %s%sRENEWED / CHANGED%s (Different certificate, same Subject CN)\n", Yellow, Bold, Reset)
		case StatusDifferent:
			fmt.Printf("  Role:    %s (New) vs %s (Old)\n", p.RoleNew, p.RoleOld)
			fmt.Printf("  New:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, p.New.SubjectCN, Reset, p.New.Serial, p.New.NotAfterStr)
			fmt.Printf("  Old:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, p.Old.SubjectCN, Reset, p.Old.Serial, p.Old.NotAfterStr)
			fmt.Printf("  Status:  %s%sDIFFERENT%s (Subject CN mismatched)\n", Red, Bold, Reset)
		case StatusAdded:
			fmt.Printf("  Role:    %s (New) vs [None] (Old)\n", p.RoleNew)
			fmt.Printf("  New:     CN=%s%s%s\n", Bold, p.New.SubjectCN, Reset)
			fmt.Printf("  Status:  %s%sADDED%s in New chain\n", Red, Bold, Reset)
		case StatusRemoved:
			fmt.Printf("  Role:    [None] (New) vs %s (Old)\n", p.RoleOld)
			fmt.Printf("  Old:     CN=%s%s%s\n", Bold, p.Old.SubjectCN, Reset)
			fmt.Printf("  Status:  %s%sREMOVED%s in New chain\n", Red, Bold, Reset)
		}
		fmt.Println()
	}

	fmt.Println(sepDash)
	fmt.Println()

	fmt.Printf("%s[Comparison Verdict]%s\n", Bold, Reset)

	switch r.Verdict {
	case "LEAF_RENEWED":
		fmt.Printf("  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: ONLY the leaf certificate has changed/renewed! The entire supporting chain (intermediates and root) remains 100% identical.")
		fmt.Printf("          - Leaf CN:           %s\n", r.OrderedNew[0].SubjectCN)
		fmt.Printf("          - Old Leaf Serial:   %s (Expires: %s)\n", r.OrderedOld[0].Serial, r.OrderedOld[0].NotAfterStr)
		fmt.Printf("          - New Leaf Serial:   %s (Expires: %s)\n", r.OrderedNew[0].Serial, r.OrderedNew[0].NotAfterStr)
	case "IDENTICAL":
		fmt.Printf("  Result: %s%sPASS (IDENTICAL CHAINS)%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Both certificate files contain the EXACT same certificate chain (including the leaf).")
	default:
		fmt.Printf("  Result: %s%sFAIL / WARNING%s\n", Red, Bold, Reset)
		fmt.Println("  Detail: The difference between the two files is NOT limited to a simple leaf certificate renewal.")
		fmt.Println("  Discrepancies found:")
		if r.LeafSerialMatch && !r.IntermediatesIdentical {
			fmt.Println("          - The leaf certificate is identical, but intermediates/root certificates have changed.")
		}
		if !r.LeafCNMatch && len(r.OrderedNew) > 0 && len(r.OrderedOld) > 0 {
			fmt.Printf("          - Leaf subject Common Name (CN) changed: '%s' (New) vs '%s' (Old).\n", r.OrderedNew[0].SubjectCN, r.OrderedOld[0].SubjectCN)
		}
		for _, p := range r.Positions {
			if p.Reason != "" {
				fmt.Printf("          - %s\n", p.Reason)
			}
		}
	}
}
