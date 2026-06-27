package main

import (
	"fmt"
	"time"
)

// Validate parses the PEM file at path, reconstructs the certificate chain,
// and returns a fully-populated ValidationResult. Returns error only on I/O
// or parse failure.
func Validate(path string) (*ValidationResult, error) {
	certs, pems, err := parseCertsFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in file; ensure certificates are in PEM format")
	}

	parsedCerts := buildCertDetails(certs, pems)
	ordered := orderChainDetails(parsedCerts)

	statuses := computeCertStatuses(ordered)
	allDatesValid := true
	for _, s := range statuses {
		if s.NotYetActive || s.Expired {
			allDatesValid = false
			break
		}
	}

	sigErr := verifySignaturesDetails(ordered)
	orderCheck := computeOrderCheck(parsedCerts, ordered)
	last := ordered[len(ordered)-1]
	isCompleteChain := len(ordered) > 0 && last.IsSelfSigned && last.Cert.IsCA

	passed := allDatesValid && sigErr == nil && isCompleteChain && orderCheck.Correct
	var failReasons []string
	if !allDatesValid {
		failReasons = append(failReasons, "one or more certificates are expired or not yet active")
	}
	if sigErr != nil {
		failReasons = append(failReasons, "cryptographic signature verification failed")
	}
	if !isCompleteChain {
		failReasons = append(failReasons, "the chain is incomplete (missing a self-signed root certificate)")
	}
	if !orderCheck.Correct {
		failReasons = append(failReasons, "the physical order of certificates in the file is incorrect")
	}

	return &ValidationResult{
		Path:            path,
		ParsedCerts:     parsedCerts,
		Ordered:         ordered,
		Statuses:        statuses,
		SignatureErr:    sigErr,
		Order:           orderCheck,
		IsCompleteChain: isCompleteChain,
		Passed:          passed,
		FailReasons:     failReasons,
	}, nil
}

// Check connects to host:port over TLS, retrieves the presented certificate
// chain, and validates expiry, signatures, and server-sent order. Root absence
// is treated as informational — servers normally omit the root.
func Check(host string, port int) (*CheckResult, error) {
	rawCerts, pems, err := fetchCertsFromTLS(host, port)
	if err != nil {
		return nil, err
	}

	parsed := buildCertDetails(rawCerts, pems)
	ordered := orderChainDetails(parsed)

	statuses := computeCertStatuses(ordered)
	allDatesValid := true
	for _, s := range statuses {
		if s.NotYetActive || s.Expired {
			allDatesValid = false
			break
		}
	}

	sigErr := verifySignaturesDetails(ordered)
	orderCheck := computeOrderCheck(parsed, ordered)

	rootPresent := len(ordered) > 0 && ordered[len(ordered)-1].IsSelfSigned && ordered[len(ordered)-1].Cert.IsCA

	passed := allDatesValid && sigErr == nil && orderCheck.Correct
	var failReasons []string
	if !allDatesValid {
		failReasons = append(failReasons, "one or more certificates are expired or not yet active")
	}
	if sigErr != nil {
		failReasons = append(failReasons, "cryptographic signature verification failed")
	}
	if !orderCheck.Correct {
		failReasons = append(failReasons, "certificates were presented in incorrect order by the server")
	}

	return &CheckResult{
		Host:        host,
		Port:        port,
		Certs:       parsed,
		Ordered:     ordered,
		Statuses:    statuses,
		SignatureErr: sigErr,
		Order:       orderCheck,
		RootPresent: rootPresent,
		Passed:      passed,
		FailReasons: failReasons,
	}, nil
}

// Inspect parses the PEM file at path and returns raw cert details with no
// chain validation — no ordering, no signature checks, no completeness check.
func Inspect(path string) (*InspectResult, error) {
	certs, pems, err := parseCertsFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in file; ensure certificates are in PEM format")
	}
	return &InspectResult{
		Path:  path,
		Certs: buildCertDetails(certs, pems),
	}, nil
}

func computeCertStatuses(ordered []*CertDetails) []CertStatus {
	now := time.Now().UTC()
	statuses := make([]CertStatus, len(ordered))

	for idx, cert := range ordered {
		notBefore := cert.Cert.NotBefore.UTC()
		notAfter := cert.Cert.NotAfter.UTC()

		s := CertStatus{
			Cert: cert,
			Role: getCertRoleName(idx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA),
		}

		switch {
		case now.Before(notBefore):
			s.NotYetActive = true
		case now.After(notAfter):
			s.Expired = true
		default:
			s.Active = true
			s.DaysLeft = int(notAfter.Sub(now).Hours() / 24)
		}

		if idx < len(ordered)-1 {
			parent := ordered[idx+1]
			if cert.Akid != "" && parent.Skid != "" && cert.Akid != parent.Skid {
				s.AkidMismatch = true
			}
		}

		statuses[idx] = s
	}

	return statuses
}

func computeOrderCheck(parsedCerts, ordered []*CertDetails) OrderCheckResult {
	orderedIdx := make(map[string]int, len(ordered))
	for oIdx, c := range ordered {
		orderedIdx[c.Serial+"|"+c.SubjectDN] = oIdx
	}

	physical := make([]PhysicalEntry, len(parsedCerts))
	result := OrderCheckResult{Correct: true}

	for idx, cert := range parsedCerts {
		logicalIdx, ok := orderedIdx[cert.Serial+"|"+cert.SubjectDN]
		entry := PhysicalEntry{Cert: cert, LogicalIndex: -1}
		if ok {
			entry.LogicalIndex = logicalIdx
			entry.Role = getCertRoleName(logicalIdx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		} else {
			result.Correct = false
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"Certificate at physical position %d (CN=%s) is not part of the active logical chain.", idx+1, cert.SubjectCN))
		}
		physical[idx] = entry
	}
	result.Physical = physical

	if len(parsedCerts) != len(ordered) {
		result.Correct = false
		if len(parsedCerts) > len(ordered) {
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"File contains extra/duplicate certificates (File has %d, but logical chain only needs %d).", len(parsedCerts), len(ordered)))
		} else {
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"Logical chain requires %d certificates, but file only contains %d.", len(ordered), len(parsedCerts)))
		}
	} else {
		for idx, cert := range ordered {
			physical := parsedCerts[idx]
			if cert.Serial != physical.Serial || cert.SubjectDN != physical.SubjectDN {
				result.Correct = false
				expectedRole := getCertRoleName(idx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA)
				result.Reasons = append(result.Reasons, fmt.Sprintf(
					"Positional mismatch at index %d. Expected CN=%s (%s), but found CN=%s.",
					idx+1, cert.SubjectCN, expectedRole, physical.SubjectCN))
			}
		}
	}

	return result
}

// Compare parses two PEM files and returns a ComparisonResult describing
// how the certificate chains differ.
func Compare(fileNew, fileOld string) (*ComparisonResult, error) {
	certsNew, pemsNew, err := parseCertsFromFile(fileNew)
	if err != nil {
		return nil, fmt.Errorf("failed to read/parse %s: %w", fileNew, err)
	}
	if len(certsNew) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in %s", fileNew)
	}

	certsOld, pemsOld, err := parseCertsFromFile(fileOld)
	if err != nil {
		return nil, fmt.Errorf("failed to read/parse %s: %w", fileOld, err)
	}
	if len(certsOld) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in %s", fileOld)
	}

	parsedNew := buildCertDetails(certsNew, pemsNew)
	parsedOld := buildCertDetails(certsOld, pemsOld)
	orderedNew := orderChainDetails(parsedNew)
	orderedOld := orderChainDetails(parsedOld)

	positions, intermediatesIdentical := computePositions(orderedNew, orderedOld)

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

	verdict := "FAIL"
	passed := false
	if isOnlyLeafRenewed {
		verdict = "LEAF_RENEWED"
		passed = true
	} else if len(orderedNew) == len(orderedOld) && intermediatesIdentical && leafSerialMatch {
		verdict = "IDENTICAL"
		passed = true
	}

	return &ComparisonResult{
		FileNew:                fileNew,
		FileOld:                fileOld,
		ParsedNew:              parsedNew,
		ParsedOld:              parsedOld,
		OrderedNew:             orderedNew,
		OrderedOld:             orderedOld,
		Positions:              positions,
		IntermediatesIdentical: intermediatesIdentical,
		LeafSerialMatch:        leafSerialMatch,
		LeafCNMatch:            leafCNMatch,
		Passed:                 passed,
		Verdict:                verdict,
	}, nil
}

func computePositions(orderedNew, orderedOld []*CertDetails) ([]PositionResult, bool) {
	maxLen := max(len(orderedNew), len(orderedOld))
	positions := make([]PositionResult, maxLen)
	intermediatesIdentical := true

	for idx := range maxLen {
		var certNew, certOld *CertDetails
		var roleNew, roleOld string

		if idx < len(orderedNew) {
			certNew = orderedNew[idx]
			roleNew = getCertRoleName(idx, len(orderedNew), certNew.IsSelfSigned, certNew.Cert.IsCA)
		}
		if idx < len(orderedOld) {
			certOld = orderedOld[idx]
			roleOld = getCertRoleName(idx, len(orderedOld), certOld.IsSelfSigned, certOld.Cert.IsCA)
		}

		p := PositionResult{Idx: idx, New: certNew, Old: certOld, RoleNew: roleNew, RoleOld: roleOld}

		switch {
		case certNew != nil && certOld != nil:
			if certNew.Serial == certOld.Serial {
				p.Status = StatusIdentical
			} else if certNew.SubjectCN == certOld.SubjectCN {
				p.Status = StatusRenewed
				if idx != 0 {
					intermediatesIdentical = false
					p.Reason = fmt.Sprintf("Intermediate/Root certificate at Position %d (CN=%s) has changed (Serial mismatch).", idx+1, certNew.SubjectCN)
				}
			} else {
				p.Status = StatusDifferent
				intermediatesIdentical = false
				p.Reason = fmt.Sprintf("Certificate subject changed at Position %d: '%s' vs '%s'.", idx+1, certNew.SubjectCN, certOld.SubjectCN)
			}
		case certNew != nil:
			p.Status = StatusAdded
			intermediatesIdentical = false
			p.Reason = fmt.Sprintf("Chain structure mismatch: New chain has extra certificate at Position %d (CN=%s).", idx+1, certNew.SubjectCN)
		default:
			p.Status = StatusRemoved
			intermediatesIdentical = false
			p.Reason = fmt.Sprintf("Chain structure mismatch: Old chain had certificate at Position %d (CN=%s) which is missing in New.", idx+1, certOld.SubjectCN)
		}

		positions[idx] = p
	}

	return positions, intermediatesIdentical
}
