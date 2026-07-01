package xcv

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

var (
	NoColor bool
	NoPager bool
	Quiet   bool
)

var (
	sGreen  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	sYellow = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	sCyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("14"))
	sBold   = lipgloss.NewStyle().Bold(true)
	sPass   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	sFail   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))
	sWarn   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11"))
	sDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	sBorderIdentical = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("10")).Padding(0, 1)
	sBorderRenewed   = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("11")).Padding(0, 1)
	sBorderDiff      = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("9")).Padding(0, 1)
)

func sepEq(width int) string   { return strings.Repeat("═", width) }
func sepDash(width int) string { return strings.Repeat("─", width) }

func label(s string) string {
	return sBold.Render("[" + s + "]")
}

func certField(key, val string) string {
	return sDim.Render(key+":") + " " + val + "\n"
}

func renderCertBlock(c *CertDetails, s CertStatus, ordered []*CertDetails, idx int) string {
	var sb strings.Builder

	roleColor := sYellow
	switch {
	case idx == 0:
		roleColor = sGreen
	case c.IsSelfSigned && c.Cert.IsCA:
		roleColor = sCyan
	}

	fmt.Fprintf(&sb, "%s\n", roleColor.Bold(true).Render(fmt.Sprintf("[%d] %s", idx+1, s.Role)))
	sb.WriteString(certField("Subject CN", sBold.Render(c.SubjectCN)))
	sb.WriteString(certField("Subject DN", c.SubjectDN))
	sb.WriteString(certField("Issuer CN", c.IssuerCN))
	sb.WriteString(certField("Issuer DN", c.IssuerDN))
	sb.WriteString(certField("Serial", c.Serial))
	sb.WriteString(certField("Validity", c.NotBeforeStr+" → "+c.NotAfterStr))

	switch {
	case s.NotYetActive:
		activates := c.Cert.NotBefore.UTC().Sub(time.Now().UTC()).Round(time.Second)
		sb.WriteString(certField("Status", sFail.Render(fmt.Sprintf("NOT YET ACTIVE (activates in %s)", activates))))
	case s.Expired:
		ago := time.Now().UTC().Sub(c.Cert.NotAfter.UTC()).Round(time.Second)
		sb.WriteString(certField("Status", sFail.Render(fmt.Sprintf("EXPIRED (%s ago)", ago))))
	default:
		sb.WriteString(certField("Status", sPass.Render(fmt.Sprintf("ACTIVE (%d days remaining)", s.DaysLeft))))
	}

	if c.Skid != "" {
		sb.WriteString(certField("SKID", c.Skid))
	}
	if c.Akid != "" {
		sb.WriteString(certField("AKID", c.Akid))
	}
	if len(c.KeyUsages) > 0 {
		sb.WriteString(certField("Key Usage", strings.Join(c.KeyUsages, ", ")))
	}
	if len(c.ExtKeyUsages) > 0 {
		sb.WriteString(certField("Ext Key Use", strings.Join(c.ExtKeyUsages, ", ")))
	}
	for _, issue := range c.ComplianceIssues {
		fmt.Fprintf(&sb, "%s\n", sFail.Render("RFC Violation: "+issue))
	}
	if s.AkidMismatch && idx < len(ordered)-1 {
		parent := ordered[idx+1]
		fmt.Fprintf(&sb, "%s\n", sWarn.Render("Warning: AKID mismatch with parent SKID"))
		sb.WriteString(certField("  This AKID", c.Akid))
		sb.WriteString(certField("  Parent SKID", parent.Skid))
	}

	return sb.String()
}

func renderChainTree(ordered []*CertDetails) string {
	if len(ordered) == 0 {
		return "  (empty chain)\n"
	}
	var sb strings.Builder
	n := len(ordered)
	for i := range n {
		idx := n - 1 - i
		cert := ordered[idx]
		indent := strings.Repeat("  ", i)

		var roleLabel string
		switch i {
		case 0:
			switch {
			case cert.IsSelfSigned && cert.Cert.IsCA:
				roleLabel = sCyan.Bold(true).Render("[Root]")
			case cert.IsSelfSigned:
				roleLabel = sGreen.Bold(true).Render("[Leaf*]")
			default:
				roleLabel = sYellow.Bold(true).Render("[Anchor]")
			}
		case n - 1:
			roleLabel = sGreen.Bold(true).Render("[Leaf]")
		default:
			roleLabel = sYellow.Bold(true).Render(fmt.Sprintf("[Interm %d]", n-1-i))
		}

		connector := ""
		if i > 0 {
			connector = "└── "
		}
		fmt.Fprintf(&sb, "  %s %s%sCN=%s\n", roleLabel, indent, connector, sBold.Render(cert.SubjectCN))
	}
	return sb.String()
}

func renderSignatureVerification(err error) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", label("Cryptographic Signature Verification"))
	if err == nil {
		fmt.Fprintf(&sb, "  Result: %s\n", sPass.Render("PASS"))
		sb.WriteString("  Detail: Chain signatures verified successfully.\n")
	} else {
		fmt.Fprintf(&sb, "  Result: %s\n", sFail.Render("FAIL"))
		fmt.Fprintf(&sb, "  Detail: %v\n", err)
	}
	return sb.String()
}

func renderComparePanels(p PositionResult, colWidth int) string {
	var sb strings.Builder

	var badge string
	var panelStyle lipgloss.Style
	switch p.Status {
	case StatusIdentical:
		badge = sPass.Render("IDENTICAL")
		panelStyle = sBorderIdentical
	case StatusRenewed:
		badge = sWarn.Render("RENEWED")
		panelStyle = sBorderRenewed
	case StatusDifferent:
		badge = sFail.Render("DIFFERENT")
		panelStyle = sBorderDiff
	case StatusAdded:
		badge = sFail.Render("ADDED")
		panelStyle = sBorderDiff
	case StatusRemoved:
		badge = sFail.Render("REMOVED")
		panelStyle = sBorderDiff
	}

	fmt.Fprintf(&sb, "%s  %s\n", sBold.Render(fmt.Sprintf("Position %d", p.Idx+1)), badge)

	newContent := renderComparePanel(p.New, p.RoleNew)
	oldContent := renderComparePanel(p.Old, p.RoleOld)

	newPanel := panelStyle.Width(colWidth).Render(newContent)
	oldPanel := panelStyle.Width(colWidth).Render(oldContent)

	sb.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, oldPanel, "  ", newPanel))
	sb.WriteString("\n\n")
	return sb.String()
}

func renderComparePanel(cert *CertDetails, role string) string {
	if cert == nil {
		return sDim.Render("(not present)")
	}
	var sb strings.Builder
	sb.WriteString(certField("Role   ", role))
	sb.WriteString(certField("CN     ", sBold.Render(cert.SubjectCN)))
	sb.WriteString(certField("Serial ", cert.Serial))
	sb.WriteString(certField("Expires", cert.NotAfterStr))
	return strings.TrimRight(sb.String(), "\n")
}

func renderValidationResult(r *ValidationResult, width int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", sCyan.Bold(true).Render("Certificate Chain Validation"))
	fmt.Fprintf(&sb, "%s\n", sDim.Render("File: "+r.Path))
	fmt.Fprintf(&sb, "%s\n\n", sepEq(width))

	fmt.Fprintf(&sb, "Found %d certificate(s) in the file.\n", len(r.ParsedCerts))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	fmt.Fprintf(&sb, "%s\n", label("Chain Structure"))
	sb.WriteString(renderChainTree(r.Ordered))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	for idx, s := range r.Statuses {
		sb.WriteString(renderCertBlock(s.Cert, s, r.Ordered, idx))
		sb.WriteString("\n")
	}
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	sb.WriteString(renderSignatureVerification(r.SignatureErr))
	fmt.Fprintf(&sb, "\n%s\n\n", sepDash(width))

	fmt.Fprintf(&sb, "%s\n", label("PEM File Order"))
	sb.WriteString("  Expected (Leaf → Root):\n")
	for idx, cert := range r.Ordered {
		role := getCertRoleName(idx, len(r.Ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		fmt.Fprintf(&sb, "    %d. %s (%s)\n", idx+1, sBold.Render(cert.SubjectCN), role)
	}
	sb.WriteString("\n  Physical order in file:\n")
	for idx, e := range r.Order.Physical {
		var roleDisp string
		if e.LogicalIndex != -1 {
			roleDisp = "(" + e.Role + ")"
		} else {
			roleDisp = sFail.Render("(unrelated)")
		}
		fmt.Fprintf(&sb, "    %d. %s %s\n", idx+1, sBold.Render(e.Cert.SubjectCN), roleDisp)
	}
	if r.Order.Correct {
		fmt.Fprintf(&sb, "\n  %s — order is correct.\n", sPass.Render("PASS"))
	} else {
		fmt.Fprintf(&sb, "\n  %s — order is incorrect.\n", sFail.Render("FAIL"))
		for _, reason := range r.Order.Reasons {
			fmt.Fprintf(&sb, "  · %s\n", reason)
		}
	}

	fmt.Fprintf(&sb, "\n%s\n", sepEq(width))
	if r.Passed {
		fmt.Fprintf(&sb, "%s\n", sPass.Render("SUCCESS: chain is complete, valid, properly ordered, and cryptographically sound."))
	} else {
		fmt.Fprintf(&sb, "%s\n", sFail.Render("FAILURE: chain validation failed."))
		fmt.Fprintf(&sb, "Reasons: %s\n", strings.Join(r.FailReasons, "; "))
	}
	return sb.String()
}

func renderCheckResult(r *CheckResult, width int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", sCyan.Bold(true).Render("TLS Certificate Check"))
	fmt.Fprintf(&sb, "%s\n", sDim.Render(fmt.Sprintf("Host: %s:%d", r.Host, r.Port)))
	fmt.Fprintf(&sb, "%s\n\n", sepEq(width))

	fmt.Fprintf(&sb, "Server presented %d certificate(s).\n", len(r.Certs))
	if !r.RootPresent {
		fmt.Fprintf(&sb, "%s\n", sYellow.Render("Note: Root CA not included in server response (normal for TLS)."))
	}
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	fmt.Fprintf(&sb, "%s\n", label("Chain Structure"))
	sb.WriteString(renderChainTree(r.Ordered))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	for idx, s := range r.Statuses {
		sb.WriteString(renderCertBlock(s.Cert, s, r.Ordered, idx))
		sb.WriteString("\n")
	}
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	sb.WriteString(renderSignatureVerification(r.SignatureErr))
	fmt.Fprintf(&sb, "\n%s\n\n", sepDash(width))

	fmt.Fprintf(&sb, "%s\n", label("Server-Presented Order"))
	sb.WriteString("  Expected (Leaf → Root):\n")
	for idx, cert := range r.Ordered {
		role := getCertRoleName(idx, len(r.Ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		fmt.Fprintf(&sb, "    %d. %s (%s)\n", idx+1, sBold.Render(cert.SubjectCN), role)
	}
	sb.WriteString("\n  Physical order from server:\n")
	for idx, e := range r.Order.Physical {
		var roleDisp string
		if e.LogicalIndex != -1 {
			roleDisp = "(" + e.Role + ")"
		} else {
			roleDisp = sFail.Render("(unrelated)")
		}
		fmt.Fprintf(&sb, "    %d. %s %s\n", idx+1, sBold.Render(e.Cert.SubjectCN), roleDisp)
	}
	if r.Order.Correct {
		fmt.Fprintf(&sb, "\n  %s — order is correct.\n", sPass.Render("PASS"))
	} else {
		fmt.Fprintf(&sb, "\n  %s — order is incorrect.\n", sFail.Render("FAIL"))
		for _, reason := range r.Order.Reasons {
			fmt.Fprintf(&sb, "  · %s\n", reason)
		}
	}

	fmt.Fprintf(&sb, "\n%s\n", sepEq(width))
	if !r.RootPresent {
		fmt.Fprintf(&sb, "%s\n", sYellow.Render("Note: Root CA absent from server chain (validated against presented intermediates only)."))
	}
	if r.Passed {
		fmt.Fprintf(&sb, "%s\n", sPass.Render("SUCCESS: certificates are valid, properly ordered, and cryptographically sound."))
	} else {
		fmt.Fprintf(&sb, "%s\n", sFail.Render("FAILURE: TLS certificate check failed."))
		fmt.Fprintf(&sb, "Reasons: %s\n", strings.Join(r.FailReasons, "; "))
	}
	return sb.String()
}

func renderShowResult(r *ShowResult, width int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", sCyan.Bold(true).Render("Certificate Inspector"))
	fmt.Fprintf(&sb, "%s\n", sDim.Render("File: "+r.Path))
	fmt.Fprintf(&sb, "%s\n\n", sepEq(width))
	fmt.Fprintf(&sb, "Found %d certificate(s).\n", len(r.Certs))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	now := time.Now().UTC()
	for _, cert := range r.Certs {
		roleColor := sGreen
		role := "Leaf"
		switch {
		case cert.IsSelfSigned && cert.Cert.IsCA:
			roleColor = sCyan
			role = "Root CA (Self-Signed)"
		case cert.Cert.IsCA:
			roleColor = sYellow
			role = "CA"
		case cert.IsSelfSigned:
			role = "Leaf (Self-Signed, No CA)"
		}

		fmt.Fprintf(&sb, "%s\n", roleColor.Bold(true).Render(fmt.Sprintf("[%d] %s", cert.Index, role)))
		sb.WriteString(certField("Subject CN", sBold.Render(cert.SubjectCN)))
		sb.WriteString(certField("Subject DN", cert.SubjectDN))
		sb.WriteString(certField("Issuer CN", cert.IssuerCN))
		sb.WriteString(certField("Issuer DN", cert.IssuerDN))
		sb.WriteString(certField("Serial", cert.Serial))
		sb.WriteString(certField("Validity", cert.NotBeforeStr+" → "+cert.NotAfterStr))

		switch {
		case now.Before(cert.Cert.NotBefore.UTC()):
			activates := cert.Cert.NotBefore.UTC().Sub(now).Round(time.Second)
			sb.WriteString(certField("Status", sFail.Render(fmt.Sprintf("NOT YET ACTIVE (activates in %s)", activates))))
		case now.After(cert.Cert.NotAfter.UTC()):
			ago := now.Sub(cert.Cert.NotAfter.UTC()).Round(time.Second)
			sb.WriteString(certField("Status", sFail.Render(fmt.Sprintf("EXPIRED (%s ago)", ago))))
		default:
			days := int(cert.Cert.NotAfter.UTC().Sub(now).Hours() / 24)
			sb.WriteString(certField("Status", sPass.Render(fmt.Sprintf("ACTIVE (%d days remaining)", days))))
		}

		if cert.Skid != "" {
			sb.WriteString(certField("SKID", cert.Skid))
		}
		if cert.Akid != "" {
			sb.WriteString(certField("AKID", cert.Akid))
		}
		if len(cert.KeyUsages) > 0 {
			sb.WriteString(certField("Key Usage", strings.Join(cert.KeyUsages, ", ")))
		}
		if len(cert.ExtKeyUsages) > 0 {
			sb.WriteString(certField("Ext Key Use", strings.Join(cert.ExtKeyUsages, ", ")))
		}
		for _, issue := range cert.ComplianceIssues {
			fmt.Fprintf(&sb, "%s\n", sFail.Render("RFC Violation: "+issue))
		}
		sb.WriteString("\n")
	}

	fmt.Fprintf(&sb, "%s\n", sepEq(width))
	return sb.String()
}

func renderDiffResult(r *DiffResult, width int) string {
	colWidth := max((width-8)/2, 20)

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", sCyan.Bold(true).Render("Certificate Chain Comparison"))
	fmt.Fprintf(&sb, "%s\n", sDim.Render("Old: "+r.FileOld))
	fmt.Fprintf(&sb, "%s\n", sDim.Render("New: "+r.FileNew))
	fmt.Fprintf(&sb, "%s\n\n", sepEq(width))

	fmt.Fprintf(&sb, "Old file: %d cert(s), chain depth %d\n", len(r.ParsedOld), len(r.OrderedOld))
	fmt.Fprintf(&sb, "New file: %d cert(s), chain depth %d\n", len(r.ParsedNew), len(r.OrderedNew))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	oldTree := label("Old Chain") + "\n" + renderChainTree(r.OrderedOld)
	newTree := label("New Chain") + "\n" + renderChainTree(r.OrderedNew)

	treeStyle := lipgloss.NewStyle().Width((width - 4) / 2)
	sb.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Top,
		treeStyle.Render(oldTree),
		treeStyle.Render(newTree),
	))
	fmt.Fprintf(&sb, "\n%s\n\n", sepDash(width))

	fmt.Fprintf(&sb, "%s\n\n", label("Position Comparison"))
	for _, p := range r.Positions {
		sb.WriteString(renderComparePanels(p, colWidth))
	}

	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	var identical, changed int
	for _, p := range r.Positions {
		if p.Status == StatusIdentical {
			identical++
		} else {
			changed++
		}
	}
	fmt.Fprintf(&sb, "%s\n", label("Summary"))
	if changed == 0 {
		fmt.Fprintf(&sb, "  %s\n", sPass.Render(fmt.Sprintf("Chains are identical — all %d positions match.", identical)))
	} else {
		fmt.Fprintf(&sb, "  %d unchanged, %s\n", identical, sWarn.Render(fmt.Sprintf("%d differ.", changed)))
	}

	return sb.String()
}

func PrintValidationResult(r *ValidationResult) {
	display(func(w int) string { return renderValidationResult(r, w) })
}

func PrintCheckResult(r *CheckResult) {
	display(func(w int) string { return renderCheckResult(r, w) })
}

// PrintShowResult renders the result of a Show call to stdout (or the pager).
func PrintShowResult(r *ShowResult) {
	display(func(w int) string { return renderShowResult(r, w) })
}

// PrintDiffResult renders the result of a Diff call to stdout (or the pager).
func PrintDiffResult(r *DiffResult) {
	display(func(w int) string { return renderDiffResult(r, w) })
}
