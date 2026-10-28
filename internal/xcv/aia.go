package xcv

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	aiaTimeout  = 5 * time.Second
	aiaMaxBytes = 64 << 10 // issuer certs are a few KB; cap what an untrusted URL can send
)

var aiaClient = &http.Client{Timeout: aiaTimeout}

// checkCompleteness reports whether a leaf-only chain is missing its
// intermediate. The leaf's issuer is fetched over AIA: a self-signed issuer
// means only the root was left out. Longer chains aren't fetched, since a
// non-self-signed issuer there may just be a cross-signed root.
func checkCompleteness(ctx context.Context, ordered []*CertDetails, offline bool) CompletenessCheck {
	leaf := ordered[0]
	if len(ordered) > 1 || leaf.IsSelfSigned {
		return CompletenessCheck{Status: ChainComplete}
	}
	if offline {
		return CompletenessCheck{Status: ChainUnknown, Reason: "offline"}
	}
	if len(leaf.Cert.IssuingCertificateURL) == 0 {
		return CompletenessCheck{Status: ChainUnknown, Reason: "no AIA URL"}
	}

	ctx, cancel := context.WithTimeout(ctx, aiaTimeout)
	defer cancel()

	var errs []error
	for _, u := range leaf.Cert.IssuingCertificateURL {
		issuer, err := fetchIssuer(ctx, u)
		if err == nil {
			if sigErr := leaf.Cert.CheckSignatureFrom(issuer); sigErr != nil {
				err = fmt.Errorf("fetched %q did not sign the leaf: %w", certName(issuer), sigErr)
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", u, err))
			continue
		}
		if isSelfSigned(issuer) {
			return CompletenessCheck{Status: ChainComplete, Root: certName(issuer)}
		}
		return CompletenessCheck{Status: ChainIncomplete, Missing: certName(issuer), URL: u}
	}
	return CompletenessCheck{Status: ChainUnknown, Reason: "issuer fetch failed: " + errors.Join(errs...).Error()}
}

// fetchIssuer downloads a DER or PEM certificate from an AIA caIssuers URL.
func fetchIssuer(ctx context.Context, rawURL string) (*x509.Certificate, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := aiaClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, aiaMaxBytes))
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(body); block != nil && block.Type == "CERTIFICATE" {
		body = block.Bytes
	}
	cert, err := x509.ParseCertificate(body)
	if err != nil {
		// PKCS#7 (.p7c) bundles land here too.
		return nil, fmt.Errorf("not a DER or PEM certificate: %w", err)
	}
	return cert, nil
}

// certName is the CN, or the full subject DN when the CN is empty.
func certName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}
