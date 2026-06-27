// Package utils — types.go
// Shared data structures used across scanner, proxy, and reporting packages.
package utils

// FindingInfo represents a single confirmed vulnerability finding.
type FindingInfo struct {
	// Parameter is the HTTP param / header name that was injected.
	Parameter string `json:"parameter"`
	// Payload is the exact injection string that triggered the finding.
	Payload string `json:"payload"`
	// Vector is the name of the detection technique (e.g. "Boolean-Based Blind SQLi").
	Vector string `json:"vector"`
	// Method is the HTTP method / injection point (GET, POST, POST/JSON, GET/Header).
	Method string `json:"method"`
	// Evidence is a human-readable description of why this is flagged.
	Evidence string `json:"evidence"`
	// Severity is Critical / High / Medium / Low.
	Severity string `json:"severity"`
	// URL is the full request URL at which the finding was observed.
	URL string `json:"url"`
}
