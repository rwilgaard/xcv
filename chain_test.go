package main

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

// makeCert creates a certificate signed by parent (or self-signed if parent is nil).
func makeCert(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
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
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create certificate %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %s: %v", cn, err)
	}
	return cert, key
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

func TestQuietSuppressesOutput(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)
	path := writePEM(t, []*x509.Certificate{leaf, root})

	r, err := Validate(path)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Capture stdout
	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw

	quiet = true
	PrintValidationResult(r)
	quiet = false

	if err := pw.Close(); err != nil {
		t.Errorf("close write pipe: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(pr); err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("quiet=true: expected no output, got %d bytes", buf.Len())
	}
}

func TestNoColorStripsANSI(t *testing.T) {
	// Simulate what main does when --no-color is set
	savedGreen, savedRed, savedYellow, savedCyan, savedBold, savedReset :=
		Green, Red, Yellow, Cyan, Bold, Reset
	Green, Red, Yellow, Cyan, Bold, Reset = "", "", "", "", "", ""
	defer func() {
		Green, Red, Yellow, Cyan, Bold, Reset =
			savedGreen, savedRed, savedYellow, savedCyan, savedBold, savedReset
	}()

	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)
	path := writePEM(t, []*x509.Certificate{leaf, root})
	r, err := Validate(path)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw
	PrintValidationResult(r)
	if err := pw.Close(); err != nil {
		t.Errorf("close write pipe: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(pr); err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	output := buf.String()
	if strings.Contains(output, "\033[") {
		t.Errorf("no-color: output still contains ANSI escape codes")
	}
}

func TestExtKeyUsageStrings_Unknown(t *testing.T) {
	result := extKeyUsageStrings([]x509.ExtKeyUsage{x509.ExtKeyUsage(999)})
	if len(result) != 1 || result[0] != "Unknown(999)" {
		t.Errorf("got %v, want [Unknown(999)]", result)
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: "Expired Root"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
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

func TestPrintInspectResult(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)
	path := writePEM(t, []*x509.Certificate{leaf, root})
	r, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw
	PrintInspectResult(r)
	if err := pw.Close(); err != nil {
		t.Errorf("close write pipe: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(pr); err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	output := buf.String()
	for _, want := range []string{"Certificate Inspector", "Root CA", "Leaf"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestPrintInspectResult_Quiet(t *testing.T) {
	root, _ := makeCert(t, "Root CA", true, nil, nil)
	path := writePEM(t, []*x509.Certificate{root})
	r, err := Inspect(path)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw
	quiet = true
	PrintInspectResult(r)
	quiet = false
	if err := pw.Close(); err != nil {
		t.Errorf("close write pipe: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(pr); err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("quiet=true: expected no output, got %d bytes", buf.Len())
	}
}

func TestPrintComparisonResult(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf1, _ := makeCert(t, "Leaf", false, root, rootKey)
	leaf2, _ := makeCert(t, "Leaf", false, root, rootKey)

	fileNew := writePEM(t, []*x509.Certificate{leaf2, root})
	fileOld := writePEM(t, []*x509.Certificate{leaf1, root})
	r, err := Compare(fileNew, fileOld)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw
	PrintComparisonResult(r)
	if err := pw.Close(); err != nil {
		t.Errorf("close write pipe: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(pr); err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	output := buf.String()
	for _, want := range []string{"Certificate Chain Comparison", "leaf certificate has changed", "PASS"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestPrintCheckResult(t *testing.T) {
	root, rootKey := makeCert(t, "Root CA", true, nil, nil)
	leaf, _ := makeCert(t, "Leaf", false, root, rootKey)

	// Build CheckResult directly — no network required.
	pems := []string{"", ""}
	for i, c := range []*x509.Certificate{leaf, root} {
		var buf bytes.Buffer
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			t.Fatalf("pem encode: %v", err)
		}
		pems[i] = buf.String()
	}
	parsed := buildCertDetails([]*x509.Certificate{leaf, root}, pems)
	ordered := orderChainDetails(parsed)
	r := &CheckResult{
		Host:        "example.com",
		Port:        443,
		Certs:       parsed,
		Ordered:     ordered,
		Statuses:    computeCertStatuses(ordered),
		SignatureErr: verifySignaturesDetails(ordered),
		Order:       computeOrderCheck(parsed, ordered),
		RootPresent: true,
		Passed:      true,
	}

	old := os.Stdout
	pr, pw, _ := os.Pipe()
	os.Stdout = pw
	PrintCheckResult(r)
	if err := pw.Close(); err != nil {
		t.Errorf("close write pipe: %v", err)
	}
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(pr); err != nil {
		t.Fatalf("read from pipe: %v", err)
	}
	output := buf.String()
	for _, want := range []string{"TLS Certificate Check", "example.com:443", "SUCCESS"} {
		if !strings.Contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestCompare(t *testing.T) {
	root, rootKey := makeCert(t, "Test Root CA", true, nil, nil)
	leaf1, _ := makeCert(t, "Test Leaf", false, root, rootKey)
	leaf2, _ := makeCert(t, "Test Leaf", false, root, rootKey)   // renewed: same CN, different serial
	leaf3, _ := makeCert(t, "Test Leaf V2", false, root, rootKey) // different CN → StatusDifferent → FAIL

	tests := []struct {
		name        string
		newCerts    []*x509.Certificate
		oldCerts    []*x509.Certificate
		wantPassed  bool
		wantVerdict string
	}{
		{
			name:        "leaf renewed",
			newCerts:    []*x509.Certificate{leaf2, root},
			oldCerts:    []*x509.Certificate{leaf1, root},
			wantPassed:  true,
			wantVerdict: "LEAF_RENEWED",
		},
		{
			name:        "identical chains",
			newCerts:    []*x509.Certificate{leaf1, root},
			oldCerts:    []*x509.Certificate{leaf1, root},
			wantPassed:  true,
			wantVerdict: "IDENTICAL",
		},
		{
			name:        "different leaf CN",
			newCerts:    []*x509.Certificate{leaf1, root},
			oldCerts:    []*x509.Certificate{leaf3, root},
			wantPassed:  false,
			wantVerdict: "FAIL",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fileNew := writePEM(t, tc.newCerts)
			fileOld := writePEM(t, tc.oldCerts)
			r, err := Compare(fileNew, fileOld)
			if err != nil {
				t.Fatalf("Compare returned error: %v", err)
			}
			if r.Passed != tc.wantPassed {
				t.Errorf("Passed = %v, want %v", r.Passed, tc.wantPassed)
			}
			if r.Verdict != tc.wantVerdict {
				t.Errorf("Verdict = %q, want %q", r.Verdict, tc.wantVerdict)
			}
		})
	}
}

func TestInspect(t *testing.T) {
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
			r, err := Inspect(path)
			if err != nil {
				t.Fatalf("Inspect returned error: %v", err)
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

func TestInspect_EmptyFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	_, err = Inspect(f.Name())
	if err == nil {
		t.Fatal("expected error for empty file, got nil")
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
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			host, port, err := parseHostPort(tc.input, tc.defaultPort)
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

func TestComplianceIssues(t *testing.T) {
	negSerial := big.NewInt(-1)
	zeroSerial := big.NewInt(0)
	longSerial := new(big.Int).SetBytes(bytes.Repeat([]byte{0xff}, 21))

	tests := []struct {
		name        string
		cert        *x509.Certificate
		wantIssues  []string
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
				found := false
				for _, g := range got {
					if strings.Contains(g, want) || g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing issue %q in %v", want, got)
				}
			}
		})
	}
}

