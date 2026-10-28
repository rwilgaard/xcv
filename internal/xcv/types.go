package xcv

import "crypto/x509"

type CertDetails struct {
	Index            int
	Cert             *x509.Certificate
	SubjectCN        string
	IssuerCN         string
	SubjectDN        string
	IssuerDN         string
	Serial           string
	NotBeforeStr     string
	NotAfterStr      string
	SKID             string
	AKID             string
	KeyUsages        []string
	ExtKeyUsages     []string
	ComplianceIssues []string
	IsSelfSigned     bool
	RawPEM           string
	Fingerprint      string // hex SHA-256 of the DER-encoded certificate
}

type CertStatus struct {
	Cert         *CertDetails
	Role         string
	Active       bool
	NotYetActive bool
	Expired      bool
	DaysLeft     int
}

type PhysicalEntry struct {
	Cert         *CertDetails
	LogicalIndex int    // -1 = not part of active chain
	Role         string // "" if LogicalIndex == -1
}

type OrderCheckResult struct {
	Correct  bool
	Reasons  []string
	Physical []PhysicalEntry
}

type ValidationResult struct {
	Path         string
	ParsedCerts  []*CertDetails
	Ordered      []*CertDetails
	Statuses     []CertStatus
	SignatureErr error
	Order        OrderCheckResult
	Completeness CompletenessCheck
	RootPresent  bool
	Passed       bool
	// FailReasons lists human-readable reasons when Passed == false.
	FailReasons []string
}

type PositionStatus int

const (
	StatusIdentical PositionStatus = iota
	StatusRenewed
	StatusDifferent
	StatusAdded
	StatusRemoved
)

type PositionResult struct {
	Idx     int
	New     *CertDetails // nil when Status == StatusRemoved
	Old     *CertDetails // nil when Status == StatusAdded
	RoleNew string
	RoleOld string
	Status  PositionStatus
}

type CheckResult struct {
	Host         string
	Port         int
	Certs        []*CertDetails
	Ordered      []*CertDetails
	Statuses     []CertStatus
	SignatureErr error
	HostnameErr  error
	Order        OrderCheckResult
	Completeness CompletenessCheck
	RootPresent  bool
	Passed       bool
	FailReasons  []string
}

// ShowResult holds the certificates parsed from a PEM file for display.
type ShowResult struct {
	Path  string
	Certs []*CertDetails
}

// DiffResult holds the outcome of comparing two PEM certificate chain files.
type DiffResult struct {
	FileNew    string
	FileOld    string
	ParsedNew  []*CertDetails
	ParsedOld  []*CertDetails
	OrderedNew []*CertDetails
	OrderedOld []*CertDetails
	Positions  []PositionResult
}

// MatchResult holds the outcome of comparing a certificate's public key
// against a private key's public key.
type MatchResult struct {
	CertPath    string
	KeyPath     string
	CertSubject string
	KeyType     string
	CertPubKey  string // hex SHA-256 of PKIX-marshaled cert public key
	KeyPubKey   string // hex SHA-256 of PKIX-marshaled key's public key
	Matched     bool
}

// ReorderResult holds a PEM file's chain in Leaf → Intermediates → Root order.
type ReorderResult struct {
	Path    string
	Ordered []*CertDetails
	// Dropped lists certificates in the file that are not part of the chain,
	// including duplicates.
	Dropped []*CertDetails
}

type CompletenessStatus int

const (
	ChainComplete CompletenessStatus = iota
	ChainIncomplete
	ChainUnknown
)

// CompletenessCheck is the outcome of checking whether a leaf-only chain is
// missing its intermediate.
type CompletenessCheck struct {
	Status  CompletenessStatus
	Root    string // fetched root of a leaf-only chain; "" when nothing was fetched
	Missing string // the missing intermediate, when Status == ChainIncomplete
	URL     string // where Missing was fetched from
	Reason  string // why, when Status == ChainUnknown
}
