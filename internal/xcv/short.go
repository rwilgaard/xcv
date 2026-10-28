package xcv

import (
	"fmt"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// shortFingerprintLen is enough hex to tell certificates apart by eye.
const shortFingerprintLen = 8

type shortRow struct {
	role         string
	style        lipgloss.Style
	cert         *CertDetails
	notYetActive bool
	expired      bool
	daysLeft     int
}

func statusRows(statuses []CertStatus) []shortRow {
	rows := make([]shortRow, len(statuses))
	for i, s := range statuses {
		rows[i] = shortRow{
			role:         s.Role,
			style:        roleStyle(roleOf(i, s.Cert)),
			cert:         s.Cert,
			notYetActive: s.NotYetActive,
			expired:      s.Expired,
			daysLeft:     s.DaysLeft,
		}
	}
	return rows
}

// renderShortRows writes one aligned line per certificate: role, validity,
// time status, fingerprint prefix and CN. The CN goes last and is never cut,
// so a long name can't push the other columns out of line.
func renderShortRows(sb *strings.Builder, rows []shortRow) {
	statuses := make([]string, len(rows))
	var roleW, statusW int
	for i, r := range rows {
		switch {
		case r.notYetActive:
			statuses[i] = "not yet active"
		case r.expired:
			statuses[i] = "expired"
		default:
			statuses[i] = fmt.Sprintf("%dd", r.daysLeft)
		}
		roleW = max(roleW, len([]rune(r.role)))
		statusW = max(statusW, len(statuses[i]))
	}
	for i, r := range rows {
		c := r.cert
		statusStyle := sPass
		if r.notYetActive || r.expired {
			statusStyle = sFail
		}
		fmt.Fprintf(sb, "  %s  %s → %s  %s  %s  %s\n",
			r.style.Render(fmt.Sprintf("%-*s", roleW, r.role)),
			c.Cert.NotBefore.UTC().Format(time.DateOnly),
			c.Cert.NotAfter.UTC().Format(time.DateOnly),
			statusStyle.Render(fmt.Sprintf("%*s", statusW, statuses[i])),
			sDim.Render(c.Fingerprint[:shortFingerprintLen]),
			sBold.Render(c.SubjectCN))
	}
}

func shortCheck(name string, ok bool) string {
	if ok {
		return name + " " + sPass.Render("✓")
	}
	return name + " " + sFail.Render("✗")
}

func shortCompleteness(c CompletenessCheck) string {
	if c.Status == ChainUnknown {
		return "completeness " + sWarn.Render("?")
	}
	return shortCheck("completeness", c.Status == ChainComplete)
}

func renderShortHeader(sb *strings.Builder, target string, passed bool) {
	verdict := sPass.Render("PASS")
	if !passed {
		verdict = sFail.Render("FAIL")
	}
	fmt.Fprintf(sb, "%s  %s\n", sCyanBold.Render(target), verdict)
}

func renderShortFooter(sb *strings.Builder, checks []string, passed bool, reasons []string) {
	fmt.Fprintf(sb, "\n  %s %s\n", sDim.Render("Checks: "), strings.Join(checks, "  "))
	if !passed && len(reasons) > 0 {
		fmt.Fprintf(sb, "  %s %s\n", sDim.Render("Reasons:"), strings.Join(reasons, "; "))
	}
}

func renderShortValidationResult(r *ValidationResult) string {
	var sb strings.Builder
	renderShortHeader(&sb, r.Path, r.Passed)
	renderShortRows(&sb, statusRows(r.Statuses))
	renderShortFooter(&sb, []string{
		shortCheck("signatures", r.SignatureErr == nil),
		shortCompleteness(r.Completeness),
		shortCheck("order", r.Order.Correct),
	}, r.Passed, r.FailReasons)
	return sb.String()
}

func renderShortCheckResult(r *CheckResult) string {
	var sb strings.Builder
	renderShortHeader(&sb, fmt.Sprintf("%s:%d", r.Host, r.Port), r.Passed)
	renderShortRows(&sb, statusRows(r.Statuses))
	renderShortFooter(&sb, []string{
		shortCheck("signatures", r.SignatureErr == nil),
		shortCheck("hostname", r.HostnameErr == nil),
		shortCompleteness(r.Completeness),
		shortCheck("order", r.Order.Correct),
	}, r.Passed, r.FailReasons)
	return sb.String()
}

func renderShortShowResult(r *ShowResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s  %s\n", sCyanBold.Render(r.Path), fmt.Sprintf("%d certificate(s)", len(r.Certs)))
	now := time.Now().UTC()
	rows := make([]shortRow, len(r.Certs))
	for i, c := range r.Certs {
		// show doesn't order the chain, so each cert is classified on its own.
		role := roleOf(0, c)
		notYetActive, expired, daysLeft := certTimeStatus(c.Cert, now)
		rows[i] = shortRow{
			role:         role.String(),
			style:        roleStyle(role),
			cert:         c,
			notYetActive: notYetActive,
			expired:      expired,
			daysLeft:     daysLeft,
		}
	}
	renderShortRows(&sb, rows)
	return sb.String()
}
