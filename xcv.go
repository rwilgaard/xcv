package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"
)

// ANSI Color codes for beautiful terminal output
const (
	Green  = "\033[92m"
	Red    = "\033[91m"
	Yellow = "\033[93m"
	Cyan   = "\033[96m"
	Bold   = "\033[1m"
	Reset  = "\033[0m"
)

type CertDetails struct {
	Index        int
	Cert         *x509.Certificate
	SubjectCN    string
	IssuerCN     string
	SubjectDN    string
	IssuerDN     string
	Serial       string
	NotBeforeStr string
	NotAfterStr  string
	Skid         string
	Akid         string
	IsSelfSigned bool
	RawPEM       string
}

func printErr(msg string) {
	fmt.Fprintf(os.Stderr, "%s%sError:%s %s\n", Red, Bold, Reset, msg)
}

func formatSerial(serial *big.Int) string {
	if serial == nil {
		return "Unknown"
	}
	return fmt.Sprintf("%X", serial)
}

func formatKeyId(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	return hex.EncodeToString(id)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

func newCertDetails(cert *x509.Certificate, rawPEM string, index int) *CertDetails {
	skid := formatKeyId(cert.SubjectKeyId)
	akid := formatKeyId(cert.AuthorityKeyId)

	return &CertDetails{
		Index:        index,
		Cert:         cert,
		SubjectCN:    cert.Subject.CommonName,
		IssuerCN:     cert.Issuer.CommonName,
		SubjectDN:    cert.Subject.String(),
		IssuerDN:     cert.Issuer.String(),
		Serial:       formatSerial(cert.SerialNumber),
		NotBeforeStr: cert.NotBefore.UTC().Format("Jan _2 15:04:05 2006 MST"),
		NotAfterStr:  cert.NotAfter.UTC().Format("Jan _2 15:04:05 2006 MST"),
		Skid:         skid,
		Akid:         akid,
		IsSelfSigned: isSelfSigned(cert),
		RawPEM:       rawPEM,
	}
}

func parseCertsFromFile(path string) ([]*x509.Certificate, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var certs []*x509.Certificate
	var pems []string

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			certs = append(certs, cert)

			// Encode PEM block to string
			var buf bytes.Buffer
			pem.Encode(&buf, block)
			pems = append(pems, buf.String())
		}
		data = rest
	}

	return certs, pems, nil
}

func findLeafDetails(certs []*CertDetails) *CertDetails {
	if len(certs) == 0 {
		return nil
	}
	for _, cert := range certs {
		isIssuer := false
		for _, other := range certs {
			if other == cert {
				continue
			}
			if other.Cert.CheckSignatureFrom(cert.Cert) == nil {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			return cert
		}
	}
	return certs[0]
}

func findParentDetails(cert *CertDetails, pool []*CertDetails) *CertDetails {
	for _, candidate := range pool {
		if candidate == cert {
			continue
		}
		if len(cert.Cert.AuthorityKeyId) > 0 && len(candidate.Cert.SubjectKeyId) > 0 {
			if !bytes.Equal(cert.Cert.AuthorityKeyId, candidate.Cert.SubjectKeyId) {
				continue
			}
		} else {
			if !bytes.Equal(cert.Cert.RawIssuer, candidate.Cert.RawSubject) {
				continue
			}
		}
		if cert.Cert.CheckSignatureFrom(candidate.Cert) == nil {
			return candidate
		}
	}
	return nil
}

func orderChainDetails(certs []*CertDetails) []*CertDetails {
	if len(certs) == 0 {
		return nil
	}
	leaf := findLeafDetails(certs)
	ordered := []*CertDetails{leaf}
	current := leaf

	for {
		parent := findParentDetails(current, certs)
		if parent == nil {
			break
		}
		contains := false
		for _, c := range ordered {
			if c == parent {
				contains = true
				break
			}
		}
		if contains {
			break
		}
		ordered = append(ordered, parent)
		if parent.IsSelfSigned {
			break
		}
		current = parent
	}
	return ordered
}

func printChainTree(ordered []*CertDetails) {
	fmt.Printf("%s[Chain Structure]%s\n", Bold, Reset)
	if len(ordered) == 0 {
		fmt.Println("  Empty chain")
		return
	}

	// Print from Root to Leaf
	n := len(ordered)
	for i := 0; i < n; i++ {
		idx := n - 1 - i
		cert := ordered[idx]
		indent := strings.Repeat("  ", i)

		var label string
		if i == 0 {
			if cert.IsSelfSigned {
				label = fmt.Sprintf("%s[Root]%s        ", Cyan, Reset)
			} else {
				label = fmt.Sprintf("%s[Anchor]%s      ", Yellow, Reset)
			}
		} else if i == n-1 {
			label = fmt.Sprintf("%s[Leaf]%s        ", Green, Reset)
		} else {
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

func verifyChain(ordered []*x509.Certificate) error {
	if len(ordered) == 0 {
		return fmt.Errorf("empty chain")
	}

	leaf := ordered[0]
	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()

	var hasRoot bool
	if len(ordered) > 1 {
		last := ordered[len(ordered)-1]
		if isSelfSigned(last) {
			roots.AddCert(last)
			hasRoot = true
			for i := 1; i < len(ordered)-1; i++ {
				intermediates.AddCert(ordered[i])
			}
		} else {
			for i := 1; i < len(ordered); i++ {
				intermediates.AddCert(ordered[i])
			}
		}
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}
	if hasRoot {
		opts.Roots = roots
	}

	_, err := leaf.Verify(opts)
	return err
}

func verifySignaturesDetails(ordered []*CertDetails) error {
	var rawCerts []*x509.Certificate
	for _, d := range ordered {
		rawCerts = append(rawCerts, d.Cert)
	}
	return verifyChain(rawCerts)
}

func getCertRoleName(index, total int, isSelfSigned bool) string {
	if index == 0 {
		return "Leaf"
	} else if index == total-1 {
		if isSelfSigned {
			return "Root (Self-Signed)"
		}
		return "Root/Anchor (Not Self-Signed)"
	} else {
		return fmt.Sprintf("Intermediate %d", index)
	}
}

func runSingleFileValidation(path string) {
	fmt.Printf("%s%sCertificate Chain Validation Utility%s\n", Bold, Cyan, Reset)
	fmt.Printf("File: %s\n", path)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	certs, pems, err := parseCertsFromFile(path)
	if err != nil {
		printErr(fmt.Sprintf("Failed to read/parse certificate file: %v", err))
		os.Exit(1)
	}
	if len(certs) == 0 {
		printErr("No certificate blocks found in file. Ensure certificates are in PEM format.")
		os.Exit(1)
	}

	fmt.Printf("Found %d certificates in the file.\n", len(certs))
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	var parsedCerts []*CertDetails
	for i, c := range certs {
		parsedCerts = append(parsedCerts, newCertDetails(c, pems[i], i+1))
	}

	ordered := orderChainDetails(parsedCerts)

	printChainTree(ordered)
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	now := time.Now().UTC()
	allDatesValid := true

	for idx, cert := range ordered {
		role := getCertRoleName(idx, len(ordered), cert.IsSelfSigned)
		color := Yellow
		if idx == 0 {
			color = Green
		} else if idx == len(ordered)-1 {
			if cert.IsSelfSigned {
				color = Cyan
			}
		}

		fmt.Printf("[%d] %s%sCertificate Role: %s%s\n", idx+1, color, Bold, role, Reset)
		fmt.Printf("    Subject CN:   %s%s%s\n", Bold, cert.SubjectCN, Reset)
		fmt.Printf("    Subject DN:   %s\n", cert.SubjectDN)
		fmt.Printf("    Issuer CN:    %s\n", cert.IssuerCN)
		fmt.Printf("    Issuer DN:    %s\n", cert.IssuerDN)
		fmt.Printf("    Serial:       %s\n", cert.Serial)

		notBefore := cert.Cert.NotBefore.UTC()
		notAfter := cert.Cert.NotAfter.UTC()

		fmt.Printf("    Validity:     %s -> %s\n", cert.NotBeforeStr, cert.NotAfterStr)
		if now.Before(notBefore) {
			fmt.Printf("    Status:       %s%sNOT YET ACTIVE%s (Activates in %s)\n", Red, Bold, Reset, notBefore.Sub(now).Round(time.Second))
			allDatesValid = false
		} else if now.After(notAfter) {
			fmt.Printf("    Status:       %s%sEXPIRED%s (Expired %s ago)\n", Red, Bold, Reset, now.Sub(notAfter).Round(time.Second))
			allDatesValid = false
		} else {
			daysLeft := int(notAfter.Sub(now).Hours() / 24)
			fmt.Printf("    Status:       %s%sACTIVE%s (%d days remaining)\n", Green, Bold, Reset, daysLeft)
		}

		if cert.Skid != "" {
			fmt.Printf("    SKID:         %s\n", cert.Skid)
		}
		if cert.Akid != "" {
			fmt.Printf("    AKID:         %s\n", cert.Akid)
		}

		if idx < len(ordered)-1 {
			parent := ordered[idx+1]
			if cert.Akid != "" && parent.Skid != "" && cert.Akid != parent.Skid {
				fmt.Printf("    %s%sWarning: AKID does not match parent SKID!%s\n", Red, Bold, Reset)
				fmt.Printf("             This cert AKID: %s\n", cert.Akid)
				fmt.Printf("             Parent cert SKID: %s\n", parent.Skid)
			}
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	// 6. Signature Validation
	fmt.Printf("%s[Cryptographic Signature Chain Verification]%s\n", Bold, Reset)
	sigErr := verifySignaturesDetails(ordered)
	sigSuccess := sigErr == nil
	if sigSuccess {
		fmt.Printf("  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Chain signature verification succeeded.")
	} else {
		fmt.Printf("  Result: %s%sFAIL%s\n", Red, Bold, Reset)
		fmt.Printf("  Detail: Signature verification failed:\n          %v\n", sigErr)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	// 6.5 PEM File Order Verification
	fmt.Printf("%s[PEM File Order Verification]%s\n", Bold, Reset)
	orderCorrect := true
	var orderReasons []string

	fmt.Println("  Expected order (Leaf to Root):")
	for idx, cert := range ordered {
		roleName := getCertRoleName(idx, len(ordered), cert.IsSelfSigned)
		fmt.Printf("    %d. CN=%s%s%s (%s)\n", idx+1, Bold, cert.SubjectCN, Reset, roleName)
	}

	fmt.Println("\n  Physical order in file:")
	for idx, cert := range parsedCerts {
		logicalMatch := -1
		for oIdx, c := range ordered {
			if c.Serial == cert.Serial && c.SubjectDN == cert.SubjectDN {
				logicalMatch = oIdx
				break
			}
		}

		var roleDisp string
		if logicalMatch != -1 {
			roleName := getCertRoleName(logicalMatch, len(ordered), cert.IsSelfSigned)
			roleDisp = fmt.Sprintf("(%s)", roleName)
		} else {
			roleDisp = fmt.Sprintf("(%sUnused/Unrelated certificate%s)", Red, Reset)
			orderCorrect = false
			orderReasons = append(orderReasons, fmt.Sprintf("Certificate at physical position %d (CN=%s) is not part of the active logical chain.", idx+1, cert.SubjectCN))
		}
		fmt.Printf("    %d. CN=%s%s%s %s\n", idx+1, Bold, cert.SubjectCN, Reset, roleDisp)
	}

	if len(parsedCerts) != len(ordered) {
		orderCorrect = false
		if len(parsedCerts) > len(ordered) {
			orderReasons = append(orderReasons, fmt.Sprintf("File contains extra/duplicate certificates (File has %d, but logical chain only needs %d).", len(parsedCerts), len(ordered)))
		} else {
			orderReasons = append(orderReasons, fmt.Sprintf("Logical chain requires %d certificates, but file only contains %d.", len(ordered), len(parsedCerts)))
		}
	} else {
		for idx, cert := range ordered {
			physicalCert := parsedCerts[idx]
			if cert.Serial != physicalCert.Serial || cert.SubjectDN != physicalCert.SubjectDN {
				orderCorrect = false
				expectedRole := getCertRoleName(idx, len(ordered), cert.IsSelfSigned)
				orderReasons = append(orderReasons, fmt.Sprintf("Positional mismatch at index %d. Expected CN=%s (%s), but found CN=%s.", idx+1, cert.SubjectCN, expectedRole, physicalCert.SubjectCN))
			}
		}
	}

	if orderCorrect {
		fmt.Printf("\n  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Physical certificate order in the file matches the logical chain order (Leaf -> Intermediates -> Root).")
	} else {
		fmt.Printf("\n  Result: %s%sFAIL%s\n", Red, Bold, Reset)
		fmt.Println("  Detail: Physical certificate order in the file does NOT match the logical chain order.")
		for _, reason := range orderReasons {
			fmt.Printf("          - %s\n", reason)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))

	isCompleteChain := len(ordered) > 0 && ordered[len(ordered)-1].IsSelfSigned

	if allDatesValid && sigSuccess && isCompleteChain && orderCorrect {
		fmt.Printf("%s%sSUCCESS: The certificate chain is complete, valid, properly ordered, and cryptographically sound.%s\n", Green, Bold, Reset)
		os.Exit(0)
	} else {
		var reasons []string
		if !allDatesValid {
			reasons = append(reasons, "one or more certificates are expired or not yet active")
		}
		if !sigSuccess {
			reasons = append(reasons, "cryptographic signature verification failed")
		}
		if !isCompleteChain {
			reasons = append(reasons, "the chain is incomplete (missing a self-signed root certificate)")
		}
		if !orderCorrect {
			reasons = append(reasons, "the physical order of certificates in the file is incorrect")
		}

		fmt.Printf("%s%sFAILURE: Chain validation failed.%s\n", Red, Bold, Reset)
		fmt.Printf("Reasons: %s\n", strings.Join(reasons, ", "))
		os.Exit(1)
	}
}

func runComparison(fileNew, fileOld string) {
	fmt.Printf("%s%sCertificate Chain Comparison Utility%s\n", Bold, Cyan, Reset)
	fmt.Printf("File 1 (New): %s\n", fileNew)
	fmt.Printf("File 2 (Old): %s\n", fileOld)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	certsNew, pemsNew, err := parseCertsFromFile(fileNew)
	if err != nil {
		printErr(fmt.Sprintf("Failed to read/parse File 1 (New): %v", err))
		os.Exit(1)
	}
	if len(certsNew) == 0 {
		printErr(fmt.Sprintf("No certificate blocks found in File 1 (New): %s", fileNew))
		os.Exit(1)
	}

	var parsedNew []*CertDetails
	for i, c := range certsNew {
		parsedNew = append(parsedNew, newCertDetails(c, pemsNew[i], i+1))
	}

	certsOld, pemsOld, err := parseCertsFromFile(fileOld)
	if err != nil {
		printErr(fmt.Sprintf("Failed to read/parse File 2 (Old): %v", err))
		os.Exit(1)
	}
	if len(certsOld) == 0 {
		printErr(fmt.Sprintf("No certificate blocks found in File 2 (Old): %s", fileOld))
		os.Exit(1)
	}

	var parsedOld []*CertDetails
	for i, c := range certsOld {
		parsedOld = append(parsedOld, newCertDetails(c, pemsOld[i], i+1))
	}

	orderedNew := orderChainDetails(parsedNew)
	orderedOld := orderChainDetails(parsedOld)

	fmt.Printf("File 1 (New) contains %d certs (logical chain depth: %d)\n", len(certsNew), len(orderedNew))
	fmt.Printf("File 2 (Old) contains %d certs (logical chain depth: %d)\n", len(certsOld), len(orderedOld))
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	fmt.Printf("%s[Chain 1 (New) Structure]%s\n", Bold, Reset)
	printChainTree(orderedNew)
	fmt.Printf("%s[Chain 2 (Old) Structure]%s\n", Bold, Reset)
	printChainTree(orderedOld)
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	fmt.Printf("%s[Detailed Node Comparison]%s\n", Bold, Reset)

	intermediatesIdentical := true
	var reasonsNotOnlyLeaf []string

	maxLen := len(orderedNew)
	if len(orderedOld) > maxLen {
		maxLen = len(orderedOld)
	}

	for idx := 0; idx < maxLen; idx++ {
		var roleNew, roleOld string
		var certNew, certOld *CertDetails

		if idx < len(orderedNew) {
			certNew = orderedNew[idx]
			roleNew = getCertRoleName(idx, len(orderedNew), certNew.IsSelfSigned)
		}
		if idx < len(orderedOld) {
			certOld = orderedOld[idx]
			roleOld = getCertRoleName(idx, len(orderedOld), certOld.IsSelfSigned)
		}

		fmt.Printf("Position %d:\n", idx+1)

		if certNew != nil && certOld != nil {
			cnMatch := certNew.SubjectCN == certOld.SubjectCN
			serialMatch := certNew.Serial == certOld.Serial

			fmt.Printf("  Role:    %s (New) vs %s (Old)\n", roleNew, roleOld)
			fmt.Printf("  New:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, certNew.SubjectCN, Reset, certNew.Serial, certNew.NotAfterStr)
			fmt.Printf("  Old:     CN=%s%s%s, Serial=%s, NotAfter=%s\n", Bold, certOld.SubjectCN, Reset, certOld.Serial, certOld.NotAfterStr)

			if serialMatch {
				fmt.Printf("  Status:  %s%sIDENTICAL%s (The exact same certificate)\n", Green, Bold, Reset)
			} else {
				if cnMatch {
					fmt.Printf("  Status:  %s%sRENEWED / CHANGED%s (Different certificate, same Subject CN)\n", Yellow, Bold, Reset)
					if idx != 0 {
						intermediatesIdentical = false
						reasonsNotOnlyLeaf = append(reasonsNotOnlyLeaf, fmt.Sprintf("Intermediate/Root certificate at Position %d (CN=%s) has changed (Serial mismatch).", idx+1, certNew.SubjectCN))
					}
				} else {
					fmt.Printf("  Status:  %s%sDIFFERENT%s (Subject CN mismatched)\n", Red, Bold, Reset)
					intermediatesIdentical = false
					reasonsNotOnlyLeaf = append(reasonsNotOnlyLeaf, fmt.Sprintf("Certificate subject changed at Position %d: '%s' vs '%s'.", idx+1, certNew.SubjectCN, certOld.SubjectCN))
				}
			}
		} else {
			intermediatesIdentical = false
			if certNew != nil {
				fmt.Printf("  Role:    %s (New) vs [None] (Old)\n", roleNew)
				fmt.Printf("  New:     CN=%s%s%s\n", Bold, certNew.SubjectCN, Reset)
				fmt.Printf("  Status:  %s%sADDED%s in New chain\n", Red, Bold, Reset)
				reasonsNotOnlyLeaf = append(reasonsNotOnlyLeaf, fmt.Sprintf("Chain structure mismatch: New chain has extra certificate at Position %d (CN=%s).", idx+1, certNew.SubjectCN))
			} else {
				fmt.Printf("  Role:    [None] (New) vs %s (Old)\n", roleOld)
				fmt.Printf("  Old:     CN=%s%s%s\n", Bold, certOld.SubjectCN, Reset)
				fmt.Printf("  Status:  %s%sREMOVED%s in New chain\n", Red, Bold, Reset)
				reasonsNotOnlyLeaf = append(reasonsNotOnlyLeaf, fmt.Sprintf("Chain structure mismatch: Old chain had certificate at Position %d (CN=%s) which is missing in New.", idx+1, certOld.SubjectCN))
			}
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	fmt.Printf("%s[Comparison Verdict]%s\n", Bold, Reset)

	var leafSerialMatch, leafCNMatch bool
	if len(orderedNew) > 0 && len(orderedOld) > 0 {
		leafSerialMatch = orderedNew[0].Serial == orderedOld[0].Serial
		leafCNMatch = orderedNew[0].SubjectCN == orderedOld[0].SubjectCN
	}

	isOnlyLeafRenewed := len(orderedNew) == len(orderedOld) &&
		len(orderedNew) > 0 &&
		!leafSerialMatch &&
		leafCNMatch &&
		intermediatesIdentical

	if isOnlyLeafRenewed {
		fmt.Printf("  Result: %s%sPASS%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: ONLY the leaf certificate has changed/renewed! The entire supporting chain (intermediates and root) remains 100% identical.")
		fmt.Printf("          - Leaf CN:           %s\n", orderedNew[0].SubjectCN)
		fmt.Printf("          - Old Leaf Serial:   %s (Expires: %s)\n", orderedOld[0].Serial, orderedOld[0].NotAfterStr)
		fmt.Printf("          - New Leaf Serial:   %s (Expires: %s)\n", orderedNew[0].Serial, orderedNew[0].NotAfterStr)
		os.Exit(0)
	} else if len(orderedNew) == len(orderedOld) && intermediatesIdentical && leafSerialMatch {
		fmt.Printf("  Result: %s%sPASS (IDENTICAL CHAINS)%s\n", Green, Bold, Reset)
		fmt.Println("  Detail: Both certificate files contain the EXACT same certificate chain (including the leaf).")
		os.Exit(0)
	} else {
		fmt.Printf("  Result: %s%sFAIL / WARNING%s\n", Red, Bold, Reset)
		fmt.Println("  Detail: The difference between the two files is NOT limited to a simple leaf certificate renewal.")
		fmt.Println("  Discrepancies found:")
		if leafSerialMatch && !intermediatesIdentical {
			fmt.Println("          - The leaf certificate is identical, but intermediates/root certificates have changed.")
		}
		if !leafCNMatch && len(orderedNew) > 0 && len(orderedOld) > 0 {
			fmt.Printf("          - Leaf subject Common Name (CN) changed: '%s' (New) vs '%s' (Old).\n", orderedNew[0].SubjectCN, orderedOld[0].SubjectCN)
		}
		for _, reason := range reasonsNotOnlyLeaf {
			fmt.Printf("          - %s\n", reason)
		}
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage:\n")
		fmt.Printf("  Single Validation: %s <file>\n", os.Args[0])
		fmt.Printf("  Chain Comparison:  %s <new_file> <old_file>\n", os.Args[0])
		os.Exit(1)
	}

	if len(os.Args) >= 3 {
		runComparison(os.Args[1], os.Args[2])
	} else {
		runSingleFileValidation(os.Args[1])
	}
}
