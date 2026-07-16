package xcv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testSerialSeq is a monotonically increasing counter used to guarantee unique
// serial numbers across all in-process certificate generations.
var testSerialSeq atomic.Int64

func nextSerial() *big.Int {
	return big.NewInt(testSerialSeq.Add(1))
}

// signCert signs tmpl with a fresh key, using parent/parentKey as issuer
// (self-signed if parent is nil), and returns the parsed cert and its key.
func signCert(t *testing.T, tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate %s: %v", tmpl.Subject.CommonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", tmpl.Subject.CommonName, err)
	}
	return cert, key
}

// makeCert creates a certificate signed by parent (or self-signed if parent is nil).
func makeCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         isCA,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if isCA {
		tmpl.BasicConstraintsValid = true
	}
	return signCert(t, tmpl, parent, parentKey)
}

// writePEM writes a slice of certs as a PEM bundle to a temp file, returning its path.
func writePEM(t *testing.T, certs []*x509.Certificate) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close temp file: %v", cerr)
		}
	}()
	for _, c := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatalf("encode pem: %v", err)
		}
	}
	return f.Name()
}

// writeKeyPEM writes an ECDSA private key as PKCS#8 PEM to a temp file.
func writeKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "*.key.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("close temp file: %v", cerr)
		}
	}()
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	return f.Name()
}

func TestValidate(t *testing.T) {
	root, rootKey := makeCert(t, "Test Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Test Leaf", false, root, rootKey)

	tests := []struct {
		name       string
		certs      []*x509.Certificate
		wantPassed bool
	}{
		{
			name:       "valid chain leaf then root",
			certs:      []*x509.Certificate{leaf, root},
			wantPassed: true,
		},
		{
			name:       "valid chain root then leaf (wrong order)",
			certs:      []*x509.Certificate{root, leaf},
			wantPassed: false, // physical order check fails
		},
		{
			name:       "self-signed only",
			certs:      []*x509.Certificate{root},
			wantPassed: true, // self-signed root: no chain to walk, cert is structurally valid
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writePEM(t, tc.certs)
			r, err := Validate(path)
			if err != nil {
				t.Fatalf("Validate returned error: %v", err)
			}
			if r.Passed != tc.wantPassed {
				t.Errorf("Passed = %v, want %v; FailReasons = %v", r.Passed, tc.wantPassed, r.FailReasons)
			}
		})
	}
}

func TestValidate_NoSuchFile(t *testing.T) {
	_, err := Validate(filepath.Join(t.TempDir(), "nonexistent.pem"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestValidate_EmptyFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	_, err = Validate(f.Name())
	if err == nil {
		t.Fatal("expected error for empty PEM file, got nil")
	}
}

func TestStripANSI(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)
	path := writePEM(t, []*x509.Certificate{leaf, root})
	r, err := Validate(path)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Confirm the renderer actually emits ANSI — makes the strip check meaningful.
	withColor := renderValidationResult(r, 80)
	if !strings.Contains(withColor, "\033[") {
		t.Fatal("expected ANSI escape codes in colored render, but found none")
	}
	if stripped := stripANSI(withColor); strings.Contains(stripped, "\033[") {
		t.Error("stripANSI left escape codes behind")
	}
}

func TestVerifyChain_InvalidSignature(t *testing.T) {
	root1, _ := makeCert(t, "Root 1", true, nil, nil)
	root2, root2Key := makeCert(t, "Root 2", true, nil, nil)
	// leaf signed by root2 but chain presents root1 as parent
	leaf, _ := makeCert(t, "Leaf", false, root2, root2Key)
	err := verifyChain([]*x509.Certificate{leaf, root1})
	if err == nil {
		t.Fatal("expected signature error, got nil")
	}
}

func TestValidate_ExpiredCert(t *testing.T) {
	cert, _ := signCert(t, &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "Expired Root"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, nil)
	path := writePEM(t, []*x509.Certificate{cert})
	r, err := Validate(path)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Passed {
		t.Error("expected Passed=false for expired cert, got true")
	}
	if len(r.Statuses) == 0 || !r.Statuses[0].Expired {
		t.Error("expected Expired=true in status")
	}
}

func TestValidate_ExtraUnrelatedCert(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)
	unrelated, _ := makeCert(t, "Unrelated", true, nil, nil)
	// file has leaf + root + unrelated — order check should fail
	path := writePEM(t, []*x509.Certificate{leaf, root, unrelated})
	r, err := Validate(path)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if r.Passed {
		t.Error("expected Passed=false for extra cert, got true")
	}
}

// TestRenderers smoke-tests every renderer against a valid root+leaf fixture:
// no panics, and each produces its expected page. renderValidationResult is
// covered by TestStripANSI.
func TestRenderers(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, leafKey := makeCert(t, "example.com", false, root, rootKey)
	chainPEM := writePEM(t, []*x509.Certificate{leaf, root})

	show, err := Show(chainPEM)
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	diff, err := Diff(chainPEM, chainPEM)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	match, err := Match(writePEM(t, []*x509.Certificate{leaf}), writeKeyPEM(t, leafKey))
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	details := buildCertDetails([]*x509.Certificate{leaf, root}, []string{"", ""})
	check := &CheckResult{
		Host:        "example.com",
		Port:        443,
		Certs:       details,
		Ordered:     details,
		Statuses:    computeCertStatuses(details),
		Order:       OrderCheckResult{Correct: true},
		RootPresent: true,
		Passed:      true,
	}

	tests := []struct {
		name   string
		render func(width int) string
		want   string
	}{
		{"show", func(w int) string { return renderShowResult(show, w) }, "Certificate Inspector"},
		{"diff", func(w int) string { return renderDiffResult(diff, w) }, "Certificate Chain Comparison"},
		{"check", func(w int) string { return renderCheckResult(check, w) }, "TLS Certificate Check"},
		{"match", func(w int) string { return renderMatchResult(match, w) }, "Certificate Key Match"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if out := stripANSI(tc.render(80)); !strings.Contains(out, tc.want) {
				t.Errorf("output missing %q", tc.want)
			}
		})
	}
}

func TestDiff(t *testing.T) {
	root, rootKey := makeCert(t, "Test Root CA", true, nil, nil)
	leaf1, _ := makeCert(t, "Test Leaf", false, root, rootKey)
	leaf2, _ := makeCert(t, "Test Leaf", false, root, rootKey)    // renewed: same CN, different serial
	leaf3, _ := makeCert(t, "Test Leaf V2", false, root, rootKey) // different CN

	tests := []struct {
		name           string
		newCerts       []*x509.Certificate
		oldCerts       []*x509.Certificate
		wantLeafStatus PositionStatus
		wantRootStatus PositionStatus
	}{
		{
			name:           "leaf renewed",
			newCerts:       []*x509.Certificate{leaf2, root},
			oldCerts:       []*x509.Certificate{leaf1, root},
			wantLeafStatus: StatusRenewed,
			wantRootStatus: StatusIdentical,
		},
		{
			name:           "identical chains",
			newCerts:       []*x509.Certificate{leaf1, root},
			oldCerts:       []*x509.Certificate{leaf1, root},
			wantLeafStatus: StatusIdentical,
			wantRootStatus: StatusIdentical,
		},
		{
			name:           "different leaf CN",
			newCerts:       []*x509.Certificate{leaf1, root},
			oldCerts:       []*x509.Certificate{leaf3, root},
			wantLeafStatus: StatusDifferent,
			wantRootStatus: StatusIdentical,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fileNew := writePEM(t, tc.newCerts)
			fileOld := writePEM(t, tc.oldCerts)
			r, err := Diff(fileOld, fileNew)
			if err != nil {
				t.Fatalf("Diff returned error: %v", err)
			}
			if len(r.Positions) < 2 {
				t.Fatalf("expected at least 2 positions, got %d", len(r.Positions))
			}
			if r.Positions[0].Status != tc.wantLeafStatus {
				t.Errorf("leaf status = %v, want %v", r.Positions[0].Status, tc.wantLeafStatus)
			}
			if r.Positions[1].Status != tc.wantRootStatus {
				t.Errorf("root status = %v, want %v", r.Positions[1].Status, tc.wantRootStatus)
			}
		})
	}
}

func TestShow(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)

	tests := []struct {
		name      string
		certs     []*x509.Certificate
		wantCount int
	}{
		{"single root", []*x509.Certificate{root}, 1},
		{"leaf and root", []*x509.Certificate{leaf, root}, 2},
		{"root then leaf (wrong order in file)", []*x509.Certificate{root, leaf}, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writePEM(t, tc.certs)
			r, err := Show(path)
			if err != nil {
				t.Fatalf("Show returned error: %v", err)
			}
			if len(r.Certs) != tc.wantCount {
				t.Errorf("len(Certs) = %d, want %d", len(r.Certs), tc.wantCount)
			}
			if r.Path != path {
				t.Errorf("Path = %q, want %q", r.Path, path)
			}
		})
	}
}

// Not parallel: swaps os.Stdin.
func TestShowFromStdin(t *testing.T) {
	root, _ := makeCert(t, "Stdin Root", true, nil, nil)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	go func() {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})
		_ = w.Close()
	}()

	res, err := Show("-")
	if err != nil {
		t.Fatalf("Show(-): %v", err)
	}
	if res.Path != "(stdin)" {
		t.Errorf("Path = %q, want %q", res.Path, "(stdin)")
	}
	if len(res.Certs) != 1 {
		t.Errorf("got %d certs, want 1", len(res.Certs))
	}
}

// Not parallel: swaps os.Stdin.
func TestMatchFromStdin(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, leafKey := makeCert(t, "example.com", false, root, rootKey)

	certPEM := writePEM(t, []*x509.Certificate{leaf})

	der, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	go func() {
		_ = pem.Encode(w, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
		_ = w.Close()
	}()

	res, err := Match("-", certPEM)
	if err != nil {
		t.Fatalf("Match(-,cert): %v", err)
	}
	if !res.Matched {
		t.Errorf("Matched = false, want true; CertPubKey=%s KeyPubKey=%s", res.CertPubKey, res.KeyPubKey)
	}
	if res.KeyPath != "(stdin)" {
		t.Errorf("KeyPath = %q, want %q", res.KeyPath, "(stdin)")
	}
	if res.CertPath != certPEM {
		t.Errorf("CertPath = %q, want %q", res.CertPath, certPEM)
	}
}

func TestMatch(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, leafKey := makeCert(t, "example.com", false, root, rootKey)
	_, otherKey := makeCert(t, "other.com", false, root, rootKey)

	leafPEM := writePEM(t, []*x509.Certificate{leaf})
	leafKeyPEM := writeKeyPEM(t, leafKey)
	otherKeyPEM := writeKeyPEM(t, otherKey)
	chainPEM := writePEM(t, []*x509.Certificate{leaf, root})

	tests := []struct {
		name        string
		path1       string
		path2       string
		wantMatched bool
		wantErr     bool
	}{
		{
			name:        "cert then key - match",
			path1:       leafPEM,
			path2:       leafKeyPEM,
			wantMatched: true,
		},
		{
			name:        "key then cert - match (order independent)",
			path1:       leafKeyPEM,
			path2:       leafPEM,
			wantMatched: true,
		},
		{
			name:        "cert then wrong key - mismatch",
			path1:       leafPEM,
			path2:       otherKeyPEM,
			wantMatched: false,
		},
		{
			name:        "chain file then key - uses leaf cert",
			path1:       chainPEM,
			path2:       leafKeyPEM,
			wantMatched: true,
		},
		{
			name:    "two cert files - error",
			path1:   leafPEM,
			path2:   chainPEM,
			wantErr: true,
		},
		{
			name:    "two key files - error",
			path1:   leafKeyPEM,
			path2:   otherKeyPEM,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Match(tc.path1, tc.path2)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Match returned error: %v", err)
			}
			if r.Matched != tc.wantMatched {
				t.Errorf("Matched = %v, want %v; CertPubKey=%s KeyPubKey=%s",
					r.Matched, tc.wantMatched, r.CertPubKey, r.KeyPubKey)
			}
		})
	}
}

func TestGetCertRoleName(t *testing.T) {
	tests := []struct {
		name         string
		index, total int
		isSelfSigned bool
		isCA         bool
		want         string
	}{
		{"single self-signed CA", 0, 1, true, true, "Root (Self-Signed)"},
		{"single self-signed non-CA", 0, 1, true, false, "Leaf (Self-Signed, No CA)"},
		{"single anchor (not self-signed)", 0, 1, false, false, "Root/Anchor (Not Self-Signed)"},
		{"leaf in chain", 0, 3, false, false, "Leaf"},
		{"intermediate", 1, 3, false, true, "Intermediate 1"},
		{"root in full chain", 2, 3, true, true, "Root (Self-Signed)"},
		{"anchor in full chain", 2, 3, false, true, "Root/Anchor (Not Self-Signed)"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getCertRoleName(tc.index, tc.total, tc.isSelfSigned, tc.isCA)
			if got != tc.want {
				t.Errorf("getCertRoleName(%d,%d,%v,%v) = %q, want %q",
					tc.index, tc.total, tc.isSelfSigned, tc.isCA, got, tc.want)
			}
		})
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input       string
		defaultPort int
		wantHost    string
		wantPort    int
		wantErr     bool
	}{
		{"example.com", 443, "example.com", 443, false},
		{"example.com:8443", 443, "example.com", 8443, false},
		{"https://example.com", 443, "example.com", 443, false},
		{"https://example.com:8443", 443, "example.com", 8443, false},
		{"https://example.com/some/path", 443, "example.com", 443, false},
		{"http://example.com", 80, "example.com", 80, false},
		{"example.com:abc", 443, "", 0, true},
		{"example.com:0", 443, "", 0, true},
		{"example.com:99999", 443, "", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			host, port, err := ParseHostPort(tc.input, tc.defaultPort)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Errorf("port = %d, want %d", port, tc.wantPort)
			}
		})
	}
}

// makeSANCert creates a self-signed cert with an empty subject and the given DNS names.
func makeSANCert(t *testing.T, dnsNames []string) *x509.Certificate {
	t.Helper()
	cert, _ := signCert(t, &x509.Certificate{
		SerialNumber: nextSerial(),
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}, nil, nil)
	return cert
}

func TestComputePositions_SANOnly(t *testing.T) {
	a := makeSANCert(t, []string{"example.com"})
	b := makeSANCert(t, []string{"example.com"})
	c := makeSANCert(t, []string{"other.com"})

	details := func(cert *x509.Certificate) []*CertDetails {
		return buildCertDetails([]*x509.Certificate{cert}, []string{""})
	}

	renewed := computePositions(details(b), details(a))
	if renewed[0].Status != StatusRenewed {
		t.Errorf("same SANs, different serial: status = %v, want StatusRenewed", renewed[0].Status)
	}

	different := computePositions(details(c), details(a))
	if different[0].Status != StatusDifferent {
		t.Errorf("different SANs: status = %v, want StatusDifferent", different[0].Status)
	}
}

func TestMatch_EncryptedKey(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "example.com", false, root, rootKey)
	certPEM := writePEM(t, []*x509.Certificate{leaf})

	f, err := os.CreateTemp(t.TempDir(), "*.key.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	block := &pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("not-a-real-key")}
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = Match(certPEM, f.Name())
	if err == nil {
		t.Fatal("expected error for encrypted key, got nil")
	}
	if !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("error should mention encryption, got: %v", err)
	}
}

func TestComplianceIssues(t *testing.T) {
	negSerial := big.NewInt(-1)
	zeroSerial := big.NewInt(0)
	longSerial := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 21))

	tests := []struct {
		name       string
		cert       *x509.Certificate
		wantIssues []string
	}{
		{
			name:       "negative serial",
			cert:       &x509.Certificate{SerialNumber: negSerial},
			wantIssues: []string{"non-positive serial number (RFC 5280 §4.1.2.2)"},
		},
		{
			name:       "zero serial",
			cert:       &x509.Certificate{SerialNumber: zeroSerial},
			wantIssues: []string{"non-positive serial number (RFC 5280 §4.1.2.2)"},
		},
		{
			name:       "serial too long",
			cert:       &x509.Certificate{SerialNumber: longSerial},
			wantIssues: []string{"serial number too long: 21 bytes, max 20 (RFC 5280 §4.1.2.2)"},
		},
		{
			name: "NotAfter before NotBefore",
			cert: &x509.Certificate{
				SerialNumber: big.NewInt(1),
				NotBefore:    time.Now().Add(time.Hour),
				NotAfter:     time.Now(),
			},
			wantIssues: []string{"NotAfter is before NotBefore (RFC 5280 §4.1.2.5)"},
		},
		{
			name: "CA without BasicConstraints",
			cert: &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				IsCA:                  true,
				BasicConstraintsValid: false,
			},
			wantIssues: []string{"CA certificate missing BasicConstraints extension (RFC 5280 §4.2.1.9)"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := complianceIssues(tc.cert)
			for _, want := range tc.wantIssues {
				if !slices.Contains(got, want) {
					t.Errorf("missing issue %q in %v", want, got)
				}
			}
		})
	}
}

func TestReadInput(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "in.pem")
		if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := readInput(path)
		if err != nil {
			t.Fatalf("readInput(file): %v", err)
		}
		if string(data) != "hello" {
			t.Errorf("got %q, want %q", data, "hello")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := readInput(filepath.Join(t.TempDir(), "nope.pem")); err == nil {
			t.Error("expected error for missing file")
		}
	})

	// Not parallel: swaps os.Stdin.
	t.Run("stdin", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = old })

		go func() {
			_, _ = w.WriteString("piped")
			_ = w.Close()
		}()

		data, err := readInput("-")
		if err != nil {
			t.Fatalf("readInput(-): %v", err)
		}
		if string(data) != "piped" {
			t.Errorf("got %q, want %q", data, "piped")
		}
	})
}
