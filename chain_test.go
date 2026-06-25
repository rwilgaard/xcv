package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
			wantPassed: false, // signature verify fails without a trusted root anchor
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
			name:        "different root",
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
