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

	// Bold variants of the role colors, used for role labels and headers.
	sGreenBold  = sGreen.Bold(true)
	sYellowBold = sYellow.Bold(true)
	sCyanBold   = sCyan.Bold(true)

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

func renderPageHeader(sb *strings.Builder, title string, meta []string, width int) {
	fmt.Fprintf(sb, "%s\n", sCyanBold.Render(title))
	for _, m := range meta {
		fmt.Fprintf(sb, "%s\n", sDim.Render(m))
	}
	fmt.Fprintf(sb, "%s\n\n", sepEq(width))
}

// notYetActive and expired are mutually exclusive; daysLeft is used only when both are false.
func renderCertCommonFields(sb *strings.Builder, c *CertDetails, notYetActive, expired bool, daysLeft int) {
	sb.WriteString(certField("Subject CN", sBold.Render(c.SubjectCN)))
	sb.WriteString(certField("Subject DN", c.SubjectDN))
	sb.WriteString(certField("Issuer CN", c.IssuerCN))
	sb.WriteString(certField("Issuer DN", c.IssuerDN))
	sb.WriteString(certField("Serial", c.Serial))
	sb.WriteString(certField("Validity", c.NotBeforeStr+" → "+c.NotAfterStr))
	switch {
	case notYetActive:
		activates := time.Until(c.Cert.NotBefore).Round(time.Second)
		sb.WriteString(certField("Status", sFail.Render(fmt.Sprintf("NOT YET ACTIVE (activates in %s)", activates))))
	case expired:
		ago := time.Since(c.Cert.NotAfter).Round(time.Second)
		sb.WriteString(certField("Status", sFail.Render(fmt.Sprintf("EXPIRED (%s ago)", ago))))
	default:
		sb.WriteString(certField("Status", sPass.Render(fmt.Sprintf("ACTIVE (%d days remaining)", daysLeft))))
	}
	if c.SKID != "" {
		sb.WriteString(certField("SKID", c.SKID))
	}
	if c.AKID != "" {
		sb.WriteString(certField("AKID", c.AKID))
	}
	if len(c.KeyUsages) > 0 {
		sb.WriteString(certField("Key Usage", strings.Join(c.KeyUsages, ", ")))
	}
	if len(c.ExtKeyUsages) > 0 {
		sb.WriteString(certField("Ext Key Use", strings.Join(c.ExtKeyUsages, ", ")))
	}
	for _, issue := range c.ComplianceIssues {
		fmt.Fprintf(sb, "%s\n", sFail.Render("RFC Violation: "+issue))
	}
}

func renderChainStructureSection(sb *strings.Builder, ordered []*CertDetails, width int) {
	fmt.Fprintf(sb, "%s\n", label("Chain Structure"))
	sb.WriteString(renderChainTree(ordered))
	fmt.Fprintf(sb, "%s\n\n", sepDash(width))
}

func renderCertBlocksSection(sb *strings.Builder, statuses []CertStatus, width int) {
	for idx, s := range statuses {
		sb.WriteString(renderCertBlock(s.Cert, s, idx))
		sb.WriteString("\n")
	}
	fmt.Fprintf(sb, "%s\n\n", sepDash(width))
}

func renderSigSection(sb *strings.Builder, sigErr error, width int) {
	renderResultSection(sb, "Cryptographic Signature Verification", "Chain signatures verified successfully.", sigErr)
	// Historical quirk kept for output stability: this section has a blank
	// line before its separator, the hostname section does not.
	fmt.Fprintf(sb, "\n%s\n\n", sepDash(width))
}

func renderPassFail(sb *strings.Builder, passed bool, successMsg, failMsg string, reasons []string, width int, notes ...string) {
	fmt.Fprintf(sb, "\n%s\n", sepEq(width))
	for _, n := range notes {
		fmt.Fprintf(sb, "%s\n", n)
	}
	if passed {
		fmt.Fprintf(sb, "%s\n", sPass.Render(successMsg))
	} else {
		fmt.Fprintf(sb, "%s\n", sFail.Render(failMsg))
		if len(reasons) > 0 {
			fmt.Fprintf(sb, "Reasons: %s\n", strings.Join(reasons, "; "))
		}
	}
}

func renderOrderSection(sb *strings.Builder, sectionLabel, physicalLabel string, ordered []*CertDetails, physical []PhysicalEntry, correct bool, reasons []string) {
	fmt.Fprintf(sb, "%s\n", label(sectionLabel))
	sb.WriteString("  Expected (Leaf → Root):\n")
	for idx, cert := range ordered {
		role := getCertRoleName(idx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		fmt.Fprintf(sb, "    %d. %s (%s)\n", idx+1, sBold.Render(cert.SubjectCN), role)
	}
	fmt.Fprintf(sb, "\n  %s:\n", physicalLabel)
	for idx, e := range physical {
		var roleDisp string
		if e.LogicalIndex != -1 {
			roleDisp = "(" + e.Role + ")"
		} else {
			roleDisp = sFail.Render("(unrelated)")
		}
		fmt.Fprintf(sb, "    %d. %s %s\n", idx+1, sBold.Render(e.Cert.SubjectCN), roleDisp)
	}
	if correct {
		fmt.Fprintf(sb, "\n  %s — order is correct.\n", sPass.Render("PASS"))
	} else {
		fmt.Fprintf(sb, "\n  %s — order is incorrect.\n", sFail.Render("FAIL"))
		for _, reason := range reasons {
			fmt.Fprintf(sb, "  · %s\n", reason)
		}
	}
}

// certHeader renders the "[n] Role" heading above a certificate block.
func certHeader(style lipgloss.Style, index int, role string) string {
	return style.Render(fmt.Sprintf("[%d] %s", index, role))
}

func renderCertBlock(c *CertDetails, s CertStatus, idx int) string {
	var sb strings.Builder

	style := sYellowBold
	switch {
	case idx == 0:
		style = sGreenBold
	case c.IsSelfSigned && c.Cert.IsCA:
		style = sCyanBold
	}

	fmt.Fprintf(&sb, "%s\n", certHeader(style, idx+1, s.Role))
	renderCertCommonFields(&sb, c, s.NotYetActive, s.Expired, s.DaysLeft)

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
				roleLabel = sCyanBold.Render("[Root]")
			case cert.IsSelfSigned:
				roleLabel = sGreenBold.Render("[Leaf*]")
			default:
				roleLabel = sYellowBold.Render("[Anchor]")
			}
		case n - 1:
			roleLabel = sGreenBold.Render("[Leaf]")
		default:
			roleLabel = sYellowBold.Render(fmt.Sprintf("[Interm %d]", idx))
		}

		connector := ""
		if i > 0 {
			connector = "└── "
		}
		fmt.Fprintf(&sb, "  %s %s%sCN=%s\n", roleLabel, indent, connector, sBold.Render(cert.SubjectCN))
	}
	return sb.String()
}

// renderResultSection writes a labeled PASS/FAIL block: PASS with passDetail
// when err is nil, FAIL with the error otherwise.
func renderResultSection(sb *strings.Builder, title, passDetail string, err error) {
	fmt.Fprintf(sb, "%s\n", label(title))
	if err == nil {
		fmt.Fprintf(sb, "  Result: %s\n", sPass.Render("PASS"))
		fmt.Fprintf(sb, "  Detail: %s\n", passDetail)
	} else {
		fmt.Fprintf(sb, "  Result: %s\n", sFail.Render("FAIL"))
		fmt.Fprintf(sb, "  Detail: %v\n", err)
	}
}

func renderHostnameSection(sb *strings.Builder, host string, err error, width int) {
	renderResultSection(sb, "Hostname Verification", fmt.Sprintf("Leaf certificate is valid for %s.", host), err)
	fmt.Fprintf(sb, "%s\n\n", sepDash(width))
}

// compareStatusRender maps a diff position status to its badge text/style and
// panel border style.
var compareStatusRender = map[PositionStatus]struct {
	badge string
	style lipgloss.Style
	panel lipgloss.Style
}{
	StatusIdentical: {"IDENTICAL", sPass, sBorderIdentical},
	StatusRenewed:   {"RENEWED", sWarn, sBorderRenewed},
	StatusDifferent: {"DIFFERENT", sFail, sBorderDiff},
	StatusAdded:     {"ADDED", sFail, sBorderDiff},
	StatusRemoved:   {"REMOVED", sFail, sBorderDiff},
}

func renderComparePanels(p PositionResult, colWidth int) string {
	var sb strings.Builder

	cs := compareStatusRender[p.Status]
	fmt.Fprintf(&sb, "%s  %s\n", sBold.Render(fmt.Sprintf("Position %d", p.Idx+1)), cs.style.Render(cs.badge))

	panel := cs.panel.Width(colWidth)
	oldPanel := panel.Render(renderComparePanel(p.Old, p.RoleOld))
	newPanel := panel.Render(renderComparePanel(p.New, p.RoleNew))

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
	renderPageHeader(&sb, "Certificate Chain Validation", []string{"File: " + r.Path}, width)
	fmt.Fprintf(&sb, "Found %d certificate(s) in the file.\n", len(r.ParsedCerts))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))
	renderChainStructureSection(&sb, r.Ordered, width)
	renderCertBlocksSection(&sb, r.Statuses, width)
	renderSigSection(&sb, r.SignatureErr, width)
	renderOrderSection(&sb, "PEM File Order", "Physical order in file", r.Ordered, r.Order.Physical, r.Order.Correct, r.Order.Reasons)
	renderPassFail(&sb, r.Passed,
		"SUCCESS: chain is complete, valid, properly ordered, and cryptographically sound.",
		"FAILURE: chain validation failed.",
		r.FailReasons, width)
	return sb.String()
}

func renderCheckResult(r *CheckResult, width int) string {
	var sb strings.Builder
	renderPageHeader(&sb, "TLS Certificate Check", []string{fmt.Sprintf("Host: %s:%d", r.Host, r.Port)}, width)
	fmt.Fprintf(&sb, "Server presented %d certificate(s).\n", len(r.Certs))
	if !r.RootPresent {
		fmt.Fprintf(&sb, "%s\n", sYellow.Render("Note: Root CA not included in server response (normal for TLS)."))
	}
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))
	renderChainStructureSection(&sb, r.Ordered, width)
	renderCertBlocksSection(&sb, r.Statuses, width)
	renderSigSection(&sb, r.SignatureErr, width)
	renderHostnameSection(&sb, r.Host, r.HostnameErr, width)
	renderOrderSection(&sb, "Server-Presented Order", "Physical order from server", r.Ordered, r.Order.Physical, r.Order.Correct, r.Order.Reasons)

	var footerNotes []string
	if !r.RootPresent {
		footerNotes = append(footerNotes, sYellow.Render("Note: Root CA absent from server chain (validated against presented intermediates only)."))
	}
	renderPassFail(&sb, r.Passed,
		"SUCCESS: certificates are valid, properly ordered, and cryptographically sound.",
		"FAILURE: TLS certificate check failed.",
		r.FailReasons, width, footerNotes...)
	return sb.String()
}

func renderShowResult(r *ShowResult, width int) string {
	var sb strings.Builder
	renderPageHeader(&sb, "Certificate Inspector", []string{"File: " + r.Path}, width)
	fmt.Fprintf(&sb, "Found %d certificate(s).\n", len(r.Certs))
	fmt.Fprintf(&sb, "%s\n\n", sepDash(width))

	now := time.Now().UTC()
	for _, cert := range r.Certs {
		style := sGreenBold
		role := "Leaf"
		switch {
		case cert.IsSelfSigned && cert.Cert.IsCA:
			style = sCyanBold
			role = "Root (Self-Signed)"
		case cert.Cert.IsCA:
			style = sYellowBold
			role = "CA"
		case cert.IsSelfSigned:
			role = "Leaf (Self-Signed, No CA)"
		}

		notYetActive, expired, daysLeft := certTimeStatus(cert.Cert, now)

		fmt.Fprintf(&sb, "%s\n", certHeader(style, cert.Index, role))
		renderCertCommonFields(&sb, cert, notYetActive, expired, daysLeft)
		sb.WriteString("\n")
	}

	fmt.Fprintf(&sb, "%s\n", sepEq(width))
	return sb.String()
}

func renderDiffResult(r *DiffResult, width int) string {
	colWidth := max((width-8)/2, 20)

	var sb strings.Builder
	renderPageHeader(&sb, "Certificate Chain Comparison", []string{"Old: " + r.FileOld, "New: " + r.FileNew}, width)

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

func PrintShowResult(r *ShowResult) {
	display(func(w int) string { return renderShowResult(r, w) })
}

func PrintDiffResult(r *DiffResult) {
	display(func(w int) string { return renderDiffResult(r, w) })
}

func renderMatchResult(r *MatchResult, width int) string {
	var sb strings.Builder
	renderPageHeader(&sb, "Certificate Key Match", []string{"Cert: " + r.CertPath, "Key:  " + r.KeyPath}, width)

	sb.WriteString(certField("Subject CN", sBold.Render(r.CertSubject)))
	sb.WriteString(certField("Key Type", r.KeyType))

	if r.Matched {
		sb.WriteString(certField("Public Key", r.CertPubKey))
	} else {
		sb.WriteString(certField("Cert Key", r.CertPubKey))
		sb.WriteString(certField("File Key", r.KeyPubKey))
	}

	renderPassFail(&sb, r.Matched,
		"MATCH: certificate and key correspond.",
		"MISMATCH: certificate and key do not correspond.",
		nil, width)
	return sb.String()
}

func PrintMatchResult(r *MatchResult) {
	display(func(w int) string { return renderMatchResult(r, w) })
}
