package main

import "crypto/x509"

// CertDetails holds parsed fields from a single x509.Certificate.
type CertDetails struct {
	Index        int
	Cert         *x509.Certificate
	SubjectCN    string
	IssuerCN     string
	SubjectDN    string
	IssuerDN     string
	Serial       string
	NotBeforeStr string
	NotAfterStr  string
	Skid         string
	Akid         string
	KeyUsages        []string
	ExtKeyUsages     []string
	ComplianceIssues []string
	IsSelfSigned     bool
	RawPEM       string
}

// CertStatus holds the computed validity state for one cert in the chain.
type CertStatus struct {
	Cert         *CertDetails
	Role         string
	Active       bool
	NotYetActive bool
	Expired      bool
	DaysLeft     int
	AkidMismatch bool
}

// PhysicalEntry is one cert as it physically appears in the PEM file,
// annotated with its logical position in the ordered chain.
type PhysicalEntry struct {
	Cert         *CertDetails
	LogicalIndex int    // -1 = not part of active chain
	Role         string // "" if LogicalIndex == -1
}

// OrderCheckResult holds the outcome of PEM physical-order verification.
type OrderCheckResult struct {
	Correct  bool
	Reasons  []string
	Physical []PhysicalEntry
}

// ValidationResult holds the complete outcome of single-file chain validation.
type ValidationResult struct {
	Path            string
	ParsedCerts     []*CertDetails
	Ordered         []*CertDetails
	Statuses        []CertStatus
	SignatureErr    error
	Order           OrderCheckResult
	IsCompleteChain bool
	// Passed is true when all checks pass.
	Passed bool
	// FailReasons lists human-readable reasons when Passed == false.
	FailReasons []string
}

// PositionStatus classifies how two certs at the same chain position relate.
type PositionStatus int

const (
	StatusIdentical PositionStatus = iota
	StatusRenewed
	StatusDifferent
	StatusAdded
	StatusRemoved
)

// PositionResult holds the comparison outcome at one chain position.
type PositionResult struct {
	Idx     int
	New     *CertDetails // nil when Status == StatusRemoved
	Old     *CertDetails // nil when Status == StatusAdded
	RoleNew string
	RoleOld string
	Status  PositionStatus
	Reason  string // non-empty for Renewed/Different/Added/Removed
}

// InspectResult holds parsed cert details for one or more certs with no chain validation.
type InspectResult struct {
	Path  string
	Certs []*CertDetails
}

// ComparisonResult holds the complete outcome of a two-file chain comparison.
type ComparisonResult struct {
	FileNew                string
	FileOld                string
	ParsedNew              []*CertDetails
	ParsedOld              []*CertDetails
	OrderedNew             []*CertDetails
	OrderedOld             []*CertDetails
	Positions              []PositionResult
	IntermediatesIdentical bool
	LeafSerialMatch        bool
	LeafCNMatch            bool
	// Passed is true when the comparison succeeds (leaf-only renewal or identical).
	Passed bool
	// Verdict is one of: "LEAF_RENEWED", "IDENTICAL", "FAIL"
	Verdict string
}
