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
	Skid             string
	Akid             string
	KeyUsages        []string
	ExtKeyUsages     []string
	ComplianceIssues []string
	IsSelfSigned     bool
	RawPEM           string
}

type CertStatus struct {
	Cert         *CertDetails
	Role         string
	Active       bool
	NotYetActive bool
	Expired      bool
	DaysLeft     int
	AkidMismatch bool
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
	Path            string
	ParsedCerts     []*CertDetails
	Ordered         []*CertDetails
	Statuses        []CertStatus
	SignatureErr    error
	Order           OrderCheckResult
	IsCompleteChain bool
	Passed          bool
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
	Order        OrderCheckResult
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
