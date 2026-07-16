package xcv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// loadChain reads a PEM file and returns its certificates as CertDetails.
func loadChain(path string) ([]*CertDetails, error) {
	certs, pems, err := parseCertsFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in %s; ensure certificates are in PEM format", displayName(path))
	}
	return buildCertDetails(certs, pems), nil
}

// displayName returns the label shown in output headers for an input path.
func displayName(path string) string {
	if path == "-" {
		return "(stdin)"
	}
	return path
}

// chainAnalysis bundles the checks shared by Validate and Check.
type chainAnalysis struct {
	Statuses     []CertStatus
	SignatureErr error
	Order        OrderCheckResult
	DatesOK      bool
	RootPresent  bool
}

func analyzeChain(parsed, ordered []*CertDetails) chainAnalysis {
	a := chainAnalysis{
		Statuses:     computeCertStatuses(ordered),
		SignatureErr: verifySignaturesDetails(ordered),
		Order:        computeOrderCheck(parsed, ordered),
		RootPresent:  hasSelfSignedRoot(ordered),
	}
	a.DatesOK = datesAllValid(a.Statuses)
	return a
}

func hasSelfSignedRoot(ordered []*CertDetails) bool {
	if len(ordered) == 0 {
		return false
	}
	last := ordered[len(ordered)-1]
	return last.IsSelfSigned && last.Cert.IsCA
}

func Validate(path string) (*ValidationResult, error) {
	parsedCerts, err := loadChain(path)
	if err != nil {
		return nil, err
	}
	ordered := orderChainDetails(parsedCerts)
	a := analyzeChain(parsedCerts, ordered)

	passed := a.DatesOK && a.SignatureErr == nil && a.RootPresent && a.Order.Correct
	var failReasons []string
	if !a.DatesOK {
		failReasons = append(failReasons, "one or more certificates are expired or not yet active")
	}
	if a.SignatureErr != nil {
		failReasons = append(failReasons, "cryptographic signature verification failed")
	}
	if !a.RootPresent {
		failReasons = append(failReasons, "the chain is incomplete (missing a self-signed root certificate)")
	}
	if !a.Order.Correct {
		failReasons = append(failReasons, "the physical order of certificates in the file is incorrect")
	}

	return &ValidationResult{
		Path:            displayName(path),
		ParsedCerts:     parsedCerts,
		Ordered:         ordered,
		Statuses:        a.Statuses,
		SignatureErr:    a.SignatureErr,
		Order:           a.Order,
		IsCompleteChain: a.RootPresent,
		Passed:          passed,
		FailReasons:     failReasons,
	}, nil
}

func Check(ctx context.Context, host string, port int) (*CheckResult, error) {
	rawCerts, pems, err := fetchCertsFromTLS(ctx, host, port)
	if err != nil {
		return nil, err
	}

	parsed := buildCertDetails(rawCerts, pems)
	ordered := orderChainDetails(parsed)
	a := analyzeChain(parsed, ordered)

	var hostnameErr error
	if len(ordered) > 0 {
		hostnameErr = ordered[0].Cert.VerifyHostname(host)
	}

	passed := a.DatesOK && a.SignatureErr == nil && a.Order.Correct && hostnameErr == nil
	var failReasons []string
	if !a.DatesOK {
		failReasons = append(failReasons, "one or more certificates are expired or not yet active")
	}
	if a.SignatureErr != nil {
		failReasons = append(failReasons, "cryptographic signature verification failed")
	}
	if hostnameErr != nil {
		failReasons = append(failReasons, fmt.Sprintf("certificate is not valid for %s", host))
	}
	if !a.Order.Correct {
		failReasons = append(failReasons, "certificates were presented in incorrect order by the server")
	}

	return &CheckResult{
		Host:         host,
		Port:         port,
		Certs:        parsed,
		Ordered:      ordered,
		Statuses:     a.Statuses,
		SignatureErr: a.SignatureErr,
		HostnameErr:  hostnameErr,
		Order:        a.Order,
		RootPresent:  a.RootPresent,
		Passed:       passed,
		FailReasons:  failReasons,
	}, nil
}

// Show parses a PEM file and returns certificate details without chain validation.
func Show(path string) (*ShowResult, error) {
	certs, err := loadChain(path)
	if err != nil {
		return nil, err
	}
	return &ShowResult{Path: displayName(path), Certs: certs}, nil
}

// Match determines whether a private key corresponds to the public key embedded
// in a certificate. path1 and path2 may be given in either order — the function
// detects which file contains the certificate and which contains the private key
// by inspecting PEM block types.
func Match(path1, path2 string) (*MatchResult, error) {
	data1, err := readInput(path1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", displayName(path1), err)
	}
	data2, err := readInput(path2)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", displayName(path2), err)
	}

	has1Cert, has1Key := classifyPEM(data1)
	has2Cert, has2Key := classifyPEM(data2)

	var certPath, keyPath string
	var certData, keyData []byte

	switch {
	case has1Cert && has2Key && !has2Cert:
		certPath, keyPath = path1, path2
		certData, keyData = data1, data2
	case has2Cert && has1Key && !has1Cert:
		certPath, keyPath = path2, path1
		certData, keyData = data2, data1
	case !has1Cert && !has2Cert:
		return nil, fmt.Errorf("neither file contains a certificate — expected one cert file and one key file")
	case !has1Key && !has2Key:
		return nil, fmt.Errorf("neither file contains a private key; provide one certificate file and one key file")
	default:
		return nil, fmt.Errorf("ambiguous input: could not determine which file is the certificate and which is the key")
	}

	certs, pems, err := parseCertsFromBytes(certData)
	if err != nil {
		return nil, fmt.Errorf("parse certificate file %s: %w", displayName(certPath), err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", displayName(certPath))
	}
	leaf := orderChainDetails(buildCertDetails(certs, pems))[0]

	certFP, err := pubKeyFingerprint(leaf.Cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("fingerprint cert public key: %w", err)
	}

	keyPub, keyType, err := extractPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", displayName(keyPath), err)
	}
	keyFP, err := pubKeyFingerprint(keyPub)
	if err != nil {
		return nil, fmt.Errorf("fingerprint key public key: %w", err)
	}

	return &MatchResult{
		CertPath:    displayName(certPath),
		KeyPath:     displayName(keyPath),
		CertSubject: leaf.SubjectCN,
		KeyType:     keyType,
		CertPubKey:  certFP,
		KeyPubKey:   keyFP,
		Matched:     certFP == keyFP,
	}, nil
}

func ParseHostPort(input string, defaultPort int) (string, int, error) {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	if i := strings.Index(input, "/"); i != -1 {
		input = input[:i]
	}
	h, p, err := net.SplitHostPort(input)
	if err != nil {
		return input, defaultPort, nil
	}
	portNum, err := strconv.Atoi(p)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, portNum, nil
}

// certTimeStatus classifies a certificate's validity window relative to now.
// daysLeft is meaningful only when the certificate is currently active.
func certTimeStatus(cert *x509.Certificate, now time.Time) (notYetActive, expired bool, daysLeft int) {
	switch {
	case now.Before(cert.NotBefore):
		notYetActive = true
	case now.After(cert.NotAfter):
		expired = true
	default:
		daysLeft = int(cert.NotAfter.Sub(now).Hours() / 24)
	}
	return notYetActive, expired, daysLeft
}

func computeCertStatuses(ordered []*CertDetails) []CertStatus {
	now := time.Now().UTC()
	statuses := make([]CertStatus, len(ordered))

	for idx, cert := range ordered {
		s := CertStatus{
			Cert: cert,
			Role: getCertRoleName(idx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA),
		}
		s.NotYetActive, s.Expired, s.DaysLeft = certTimeStatus(cert.Cert, now)
		s.Active = !s.NotYetActive && !s.Expired
		statuses[idx] = s
	}

	return statuses
}

func computeOrderCheck(parsedCerts, ordered []*CertDetails) OrderCheckResult {
	orderedIdx := make(map[string]int, len(ordered))
	for oIdx, c := range ordered {
		orderedIdx[c.Fingerprint] = oIdx
	}

	physical := make([]PhysicalEntry, len(parsedCerts))
	result := OrderCheckResult{Correct: true}

	for idx, cert := range parsedCerts {
		logicalIdx, ok := orderedIdx[cert.Fingerprint]
		entry := PhysicalEntry{Cert: cert, LogicalIndex: -1}
		if ok {
			entry.LogicalIndex = logicalIdx
			entry.Role = getCertRoleName(logicalIdx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA)
		} else {
			result.Correct = false
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"Certificate at physical position %d (CN=%s) is not part of the active logical chain.", idx+1, cert.SubjectCN,
			))
		}
		physical[idx] = entry
	}
	result.Physical = physical

	if len(parsedCerts) != len(ordered) {
		result.Correct = false
		if len(parsedCerts) > len(ordered) {
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"File contains extra/duplicate certificates (File has %d, but logical chain only needs %d).", len(parsedCerts), len(ordered),
			))
		} else {
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"Logical chain requires %d certificates, but file only contains %d.", len(ordered), len(parsedCerts),
			))
		}
	} else {
		for idx, cert := range ordered {
			phys := parsedCerts[idx]
			if cert.Fingerprint != phys.Fingerprint {
				result.Correct = false
				expectedRole := getCertRoleName(idx, len(ordered), cert.IsSelfSigned, cert.Cert.IsCA)
				result.Reasons = append(result.Reasons, fmt.Sprintf(
					"Positional mismatch at index %d. Expected CN=%s (%s), but found CN=%s.",
					idx+1, cert.SubjectCN, expectedRole, phys.SubjectCN,
				))
			}
		}
	}

	return result
}

// Diff compares two PEM certificate chain files and returns their position-by-position comparison.
func Diff(fileOld, fileNew string) (*DiffResult, error) {
	parsedOld, err := loadChain(fileOld)
	if err != nil {
		return nil, err
	}
	parsedNew, err := loadChain(fileNew)
	if err != nil {
		return nil, err
	}

	orderedNew := orderChainDetails(parsedNew)
	orderedOld := orderChainDetails(parsedOld)

	return &DiffResult{
		FileNew:    displayName(fileNew),
		FileOld:    displayName(fileOld),
		ParsedNew:  parsedNew,
		ParsedOld:  parsedOld,
		OrderedNew: orderedNew,
		OrderedOld: orderedOld,
		Positions:  computePositions(orderedNew, orderedOld),
	}, nil
}

func computePositions(orderedNew, orderedOld []*CertDetails) []PositionResult {
	maxLen := max(len(orderedNew), len(orderedOld))
	positions := make([]PositionResult, maxLen)

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
			switch {
			case certNew.Fingerprint == certOld.Fingerprint:
				p.Status = StatusIdentical
			case sameSubjectIdentity(certNew, certOld):
				p.Status = StatusRenewed
			default:
				p.Status = StatusDifferent
			}
		case certNew != nil:
			p.Status = StatusAdded
		default:
			p.Status = StatusRemoved
		}

		positions[idx] = p
	}

	return positions
}

// sameSubjectIdentity reports whether two certificates name the same subject.
// SAN-only certificates (empty subject DN) are compared by their DNS names.
func sameSubjectIdentity(a, b *CertDetails) bool {
	if a.SubjectDN != "" || b.SubjectDN != "" {
		return a.SubjectDN == b.SubjectDN
	}
	return slices.Equal(sortedDNSNames(a), sortedDNSNames(b))
}

func sortedDNSNames(c *CertDetails) []string {
	names := slices.Clone(c.Cert.DNSNames)
	slices.Sort(names)
	return names
}

func classifyPEM(data []byte) (hasCert, hasKey bool) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return
		}
		switch block.Type {
		case "CERTIFICATE":
			hasCert = true
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			hasKey = true
		}
		if hasCert && hasKey {
			return
		}
		data = rest
	}
}

func extractPublicKeyFromPEM(data []byte) (crypto.PublicKey, string, error) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") || block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, "", fmt.Errorf("encrypted private keys are not supported; decrypt first (openssl pkey -in key.pem)")
		}
		switch block.Type {
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, "", fmt.Errorf("parse PKCS#8 key: %w", err)
			}
			return privateKeyPublic(key)
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, "", fmt.Errorf("parse RSA PKCS#1 key: %w", err)
			}
			return key.Public(), "RSA", nil
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, "", fmt.Errorf("parse EC key: %w", err)
			}
			return key.Public(), "ECDSA", nil
		}
	}
	return nil, "", fmt.Errorf("no supported private key block found (expected PRIVATE KEY, RSA PRIVATE KEY, or EC PRIVATE KEY)")
}

func privateKeyPublic(key any) (crypto.PublicKey, string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.Public(), "RSA", nil
	case *ecdsa.PrivateKey:
		return k.Public(), "ECDSA", nil
	case ed25519.PrivateKey:
		return k.Public(), "Ed25519", nil
	default:
		return nil, "", fmt.Errorf("unsupported PKCS#8 key type: %T", key)
	}
}

func pubKeyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func datesAllValid(statuses []CertStatus) bool {
	for _, s := range statuses {
		if s.NotYetActive || s.Expired {
			return false
		}
	}
	return true
}
