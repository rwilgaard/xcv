package xcv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"time"
)

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

const (
	certTimeFormat = "Jan _2 15:04:05 2006 MST"
	tlsDialTimeout = 10 * time.Second
)

func formatSerial(serial *big.Int) string {
	if serial == nil {
		return "Unknown"
	}
	return fmt.Sprintf("%X", serial)
}

func formatKeyID(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	return hex.EncodeToString(id)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}

func complianceIssues(cert *x509.Certificate) []string {
	var issues []string

	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		issues = append(issues, "non-positive serial number (RFC 5280 §4.1.2.2)")
	} else if n := len(cert.SerialNumber.Bytes()); n > 20 {
		issues = append(issues, fmt.Sprintf("serial number too long: %d bytes, max 20 (RFC 5280 §4.1.2.2)", n))
	}

	if cert.Version != 3 && len(cert.Extensions) > 0 {
		issues = append(issues, fmt.Sprintf("version %d with extensions present (RFC 5280 requires v3)", cert.Version))
	}

	if !cert.NotAfter.IsZero() && !cert.NotBefore.IsZero() && cert.NotAfter.Before(cert.NotBefore) {
		issues = append(issues, "NotAfter is before NotBefore (RFC 5280 §4.1.2.5)")
	}

	if cert.IsCA && !cert.BasicConstraintsValid {
		issues = append(issues, "CA certificate missing BasicConstraints extension (RFC 5280 §4.2.1.9)")
	}

	if cert.IsCA && cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		issues = append(issues, "CA certificate without Certificate Sign key usage (RFC 5280 §4.2.1.3)")
	}

	if cert.KeyUsage != 0 {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oidKeyUsage) && !ext.Critical {
				issues = append(issues, "KeyUsage extension is not marked critical (RFC 5280 §4.2.1.3)")
				break
			}
		}
	}

	return issues
}

var keyUsageBits = []struct {
	bit  x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "Digital Signature"},
	{x509.KeyUsageContentCommitment, "Content Commitment"},
	{x509.KeyUsageKeyEncipherment, "Key Encipherment"},
	{x509.KeyUsageDataEncipherment, "Data Encipherment"},
	{x509.KeyUsageKeyAgreement, "Key Agreement"},
	{x509.KeyUsageCertSign, "Cert Sign"},
	{x509.KeyUsageCRLSign, "CRL Sign"},
	{x509.KeyUsageEncipherOnly, "Encipher Only"},
	{x509.KeyUsageDecipherOnly, "Decipher Only"},
}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "Server Authentication",
	x509.ExtKeyUsageClientAuth:                 "Client Authentication",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft Server Gated Crypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape Server Gated Crypto",
}

func keyUsageStrings(ku x509.KeyUsage) []string {
	var usages []string
	for _, b := range keyUsageBits {
		if ku&b.bit != 0 {
			usages = append(usages, b.name)
		}
	}
	return usages
}

func extKeyUsageStrings(ekus []x509.ExtKeyUsage) []string {
	var result []string
	for _, eku := range ekus {
		if name, ok := extKeyUsageNames[eku]; ok {
			result = append(result, name)
		} else {
			result = append(result, fmt.Sprintf("Unknown(%d)", eku))
		}
	}
	return result
}

func newCertDetails(cert *x509.Certificate, rawPEM string, index int) *CertDetails {
	sum := sha256.Sum256(cert.Raw)
	return &CertDetails{
		Index:            index,
		Cert:             cert,
		SubjectCN:        cert.Subject.CommonName,
		IssuerCN:         cert.Issuer.CommonName,
		SubjectDN:        cert.Subject.String(),
		IssuerDN:         cert.Issuer.String(),
		Serial:           formatSerial(cert.SerialNumber),
		NotBeforeStr:     cert.NotBefore.UTC().Format(certTimeFormat),
		NotAfterStr:      cert.NotAfter.UTC().Format(certTimeFormat),
		SKID:             formatKeyID(cert.SubjectKeyId),
		AKID:             formatKeyID(cert.AuthorityKeyId),
		KeyUsages:        keyUsageStrings(cert.KeyUsage),
		ExtKeyUsages:     extKeyUsageStrings(cert.ExtKeyUsage),
		ComplianceIssues: complianceIssues(cert),
		IsSelfSigned:     isSelfSigned(cert),
		RawPEM:           rawPEM,
		Fingerprint:      hex.EncodeToString(sum[:]),
	}
}

func fetchCertsFromTLS(ctx context.Context, host string, port int) ([]*x509.Certificate, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, tlsDialTimeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: tlsDialTimeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional: we analyse the cert, not trust it
			ServerName:         host,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS connection to %s failed: %w", addr, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	raw := conn.(*tls.Conn).ConnectionState().PeerCertificates
	pems := make([]string, len(raw))
	for i, c := range raw {
		pems[i] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return raw, pems, nil
}

func parseCertsFromBytes(data []byte) ([]*x509.Certificate, []string, error) {
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
				return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
			pems = append(pems, string(pem.EncodeToMemory(block)))
		}
		data = rest
	}
	return certs, pems, nil
}

// readInput reads the file at path, or stdin when path is "-".
func readInput(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return data, nil
	}
	return os.ReadFile(path)
}

func parseCertsFromFile(path string) ([]*x509.Certificate, []string, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, nil, err
	}
	return parseCertsFromBytes(data)
}

func buildCertDetails(certs []*x509.Certificate, pems []string) []*CertDetails {
	details := make([]*CertDetails, len(certs))
	for i, c := range certs {
		details[i] = newCertDetails(c, pems[i], i+1)
	}
	return details
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
		if slices.Contains(ordered, parent) {
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

// verifyChain walks the ordered chain (leaf first) and verifies each certificate's
// signature against its parent using pure-Go crypto. This avoids the macOS
// Security.framework platform verifier, which rejects some widely-trusted CAs
// for opaque "not standards compliant" reasons unrelated to the actual signature.
func verifyChain(ordered []*x509.Certificate) error {
	if len(ordered) == 0 {
		return fmt.Errorf("empty chain")
	}
	for i := 0; i < len(ordered)-1; i++ {
		child, parent := ordered[i], ordered[i+1]
		if err := child.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("x509: %q not signed by parent %q: %w",
				child.Subject.CommonName, parent.Subject.CommonName, err)
		}
	}
	return nil
}

func verifySignaturesDetails(ordered []*CertDetails) error {
	rawCerts := make([]*x509.Certificate, len(ordered))
	for i, d := range ordered {
		rawCerts[i] = d.Cert
	}
	return verifyChain(rawCerts)
}

func getCertRoleName(index, total int, isSelfSigned, isCA bool) string {
	if index == total-1 {
		switch {
		case isSelfSigned && isCA:
			return "Root (Self-Signed)"
		case isSelfSigned:
			return "Leaf (Self-Signed, No CA)"
		default:
			return "Root/Anchor (Not Self-Signed)"
		}
	}
	if index == 0 {
		return "Leaf"
	}
	return fmt.Sprintf("Intermediate %d", index)
}
