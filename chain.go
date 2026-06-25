package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"slices"
	"time"
)

const certTimeFormat = "Jan _2 15:04:05 2006 MST"

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
	return &CertDetails{
		Index:        index,
		Cert:         cert,
		SubjectCN:    cert.Subject.CommonName,
		IssuerCN:     cert.Issuer.CommonName,
		SubjectDN:    cert.Subject.String(),
		IssuerDN:     cert.Issuer.String(),
		Serial:       formatSerial(cert.SerialNumber),
		NotBeforeStr: cert.NotBefore.UTC().Format(certTimeFormat),
		NotAfterStr:  cert.NotAfter.UTC().Format(certTimeFormat),
		Skid:         formatKeyId(cert.SubjectKeyId),
		Akid:         formatKeyId(cert.AuthorityKeyId),
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

			var buf bytes.Buffer
			if err := pem.Encode(&buf, block); err != nil {
				return nil, nil, fmt.Errorf("failed to encode PEM block: %w", err)
			}
			pems = append(pems, buf.String())
		}
		data = rest
	}

	return certs, pems, nil
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
	rawCerts := make([]*x509.Certificate, len(ordered))
	for i, d := range ordered {
		rawCerts[i] = d.Cert
	}
	return verifyChain(rawCerts)
}

func getCertRoleName(index, total int, isSelfSigned bool) string {
	switch index {
	case 0:
		return "Leaf"
	case total - 1:
		if isSelfSigned {
			return "Root (Self-Signed)"
		}
		return "Root/Anchor (Not Self-Signed)"
	default:
		return fmt.Sprintf("Intermediate %d", index)
	}
}
