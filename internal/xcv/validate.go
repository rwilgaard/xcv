package xcv

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

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
	datesOK := datesAllValid(statuses)

	sigErr := verifySignaturesDetails(ordered)
	orderCheck := computeOrderCheck(parsedCerts, ordered)
	last := ordered[len(ordered)-1]
	isCompleteChain := len(ordered) > 0 && last.IsSelfSigned && last.Cert.IsCA

	passed := datesOK && sigErr == nil && isCompleteChain && orderCheck.Correct
	var failReasons []string
	if !datesOK {
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

func Check(host string, port int) (*CheckResult, error) {
	rawCerts, pems, err := fetchCertsFromTLS(host, port)
	if err != nil {
		return nil, err
	}

	parsed := buildCertDetails(rawCerts, pems)
	ordered := orderChainDetails(parsed)

	statuses := computeCertStatuses(ordered)
	datesOK := datesAllValid(statuses)

	sigErr := verifySignaturesDetails(ordered)
	orderCheck := computeOrderCheck(parsed, ordered)

	rootPresent := len(ordered) > 0 && ordered[len(ordered)-1].IsSelfSigned && ordered[len(ordered)-1].Cert.IsCA

	passed := datesOK && sigErr == nil && orderCheck.Correct
	var failReasons []string
	if !datesOK {
		failReasons = append(failReasons, "one or more certificates are expired or not yet active")
	}
	if sigErr != nil {
		failReasons = append(failReasons, "cryptographic signature verification failed")
	}
	if !orderCheck.Correct {
		failReasons = append(failReasons, "certificates were presented in incorrect order by the server")
	}

	return &CheckResult{
		Host:         host,
		Port:         port,
		Certs:        parsed,
		Ordered:      ordered,
		Statuses:     statuses,
		SignatureErr: sigErr,
		Order:        orderCheck,
		RootPresent:  rootPresent,
		Passed:       passed,
		FailReasons:  failReasons,
	}, nil
}

// Show parses a PEM file and returns certificate details without chain validation.
func Show(path string) (*ShowResult, error) {
	certs, pems, err := parseCertsFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate blocks found in file; ensure certificates are in PEM format")
	}
	return &ShowResult{
		Path:  path,
		Certs: buildCertDetails(certs, pems),
	}, nil
}

// Match determines whether a private key corresponds to the public key embedded
// in a certificate. path1 and path2 may be given in either order — the function
// detects which file contains the certificate and which contains the private key
// by inspecting PEM block types.
func Match(path1, path2 string) (*MatchResult, error) {
	data1, err := os.ReadFile(path1)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path1, err)
	}
	data2, err := os.ReadFile(path2)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path2, err)
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
		return nil, fmt.Errorf("parse certificate file %s: %w", certPath, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", certPath)
	}
	leaf := orderChainDetails(buildCertDetails(certs, pems))[0]

	certFP, err := pubKeyFingerprint(leaf.Cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("fingerprint cert public key: %w", err)
	}

	keyPub, keyType, err := extractPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", keyPath, err)
	}
	keyFP, err := pubKeyFingerprint(keyPub)
	if err != nil {
		return nil, fmt.Errorf("fingerprint key public key: %w", err)
	}

	return &MatchResult{
		CertPath:    certPath,
		KeyPath:     keyPath,
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
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q", p)
	}
	return h, portNum, nil
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
			if cert.Serial != phys.Serial || cert.SubjectDN != phys.SubjectDN {
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
func Diff(fileNew, fileOld string) (*DiffResult, error) {
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

	return &DiffResult{
		FileNew:    fileNew,
		FileOld:    fileOld,
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
			if certNew.Serial == certOld.Serial {
				p.Status = StatusIdentical
			} else if certNew.SubjectCN == certOld.SubjectCN {
				p.Status = StatusRenewed
			} else {
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

func classifyPEM(data []byte) (hasCert, hasKey bool) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return
		}
		switch block.Type {
		case "CERTIFICATE":
			hasCert = true
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
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
	return fmt.Sprintf("%x", sum), nil
}

func datesAllValid(statuses []CertStatus) bool {
	for _, s := range statuses {
		if s.NotYetActive || s.Expired {
			return false
		}
	}
	return true
}
