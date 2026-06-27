// Package scanner — diff.go
// Implements the Ratio-Based Page Comparison engine (replaces raw byte-size diff).
// Uses a string-similarity ratio on normalised response bodies to detect
// structurally significant changes while ignoring dynamic noise (timestamps,
// CSRF tokens, session IDs, nonces, etc.).
package scanner

import (
	"regexp"
	"strings"
	"unicode"
)

// ─────────────────────────── Dynamic-Noise Filters ───────────────────────────

// noisePatterns are compiled once and applied to strip volatile page elements
// before any similarity computation, preventing false positives.
var noisePatterns = []*regexp.Regexp{
	// Unix / ISO 8601 timestamps
	regexp.MustCompile(`\b\d{10,13}\b`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?`),
	// CSRF / nonce tokens (32–128 hex chars or base64-like)
	regexp.MustCompile(`(?i)(?:csrf[_-]?token|_token|nonce|authenticity_token)[^"'=]*["'=\s]+[A-Za-z0-9+/=_-]{16,}`),
	regexp.MustCompile(`\b[A-Fa-f0-9]{32,128}\b`),
	// UUID / GUID
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	// Session cookies / JWT fragments in HTML attributes
	regexp.MustCompile(`(?i)(session|token|auth)[^"]*"[^"]{20,}"`),
	// Inline script nonces (CSP)
	regexp.MustCompile(`(?i)nonce="[^"]+"`),
	// Cache-busting query strings on resources
	regexp.MustCompile(`\?(?:v|ver|t|ts|_)=[0-9A-Za-z._-]+`),
	// Inline comments with dates
	regexp.MustCompile(`<!--[^-]*\d{4}[^-]*-->`),
	// Numbers that are likely counters / view-counts
	regexp.MustCompile(`(?i)(?:views?|visits?|count|hits?)[^\d]*\d+`),
}

// normalise strips noise patterns, collapses whitespace, and lower-cases the
// body so the similarity ratio measures structural content only.
func normalise(body string) string {
	s := body
	for _, re := range noisePatterns {
		s = re.ReplaceAllString(s, "")
	}
	// Collapse all whitespace runs to a single space
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	return strings.ToLower(s)
}

// ─────────────────────────── Similarity Ratio ────────────────────────────────

// SimilarityRatio returns a value in [0.0, 1.0] where 1.0 means identical.
//
// Algorithm: token-level Jaccard similarity on the normalised bodies.
// Jaccard is preferred over edit-distance here because it is O(n) and
// handles reordered blocks (e.g., shuffled ad sections) without penalty.
func SimilarityRatio(a, b string) float64 {
	na := normalise(a)
	nb := normalise(b)

	if na == nb {
		return 1.0
	}
	if na == "" && nb == "" {
		return 1.0
	}

	setA := tokenSet(na)
	setB := tokenSet(nb)

	intersection := 0
	for tok := range setA {
		if setB[tok] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

func tokenSet(s string) map[string]bool {
	set := make(map[string]bool)
	for _, tok := range strings.Fields(s) {
		if len(tok) > 2 { // ignore tiny tokens ("a", "1", etc.)
			set[tok] = true
		}
	}
	return set
}

// ─────────────────────────── Boolean Differential Core ───────────────────────

// DiffThreshold is the minimum ratio drop required to consider two responses
// structurally different.  Values above this → "same page" (no finding).
// Values at or below → structural divergence detected.
const DiffThreshold = 0.85

// DiffResult captures the outcome of a True/False differential comparison.
type DiffResult struct {
	// TrueRatio: similarity between TRUE-payload response and baseline
	TrueRatio float64
	// FalseRatio: similarity between FALSE-payload response and baseline
	FalseRatio float64
	// Divergent: true when TRUE response is similar to baseline but FALSE is not
	Divergent bool
	// Evidence: human-readable explanation
	Evidence string
}

// DifferentialAnalysis performs a boolean-differential comparison:
//
//	baseline – clean request with original parameter value
//	trueBody  – response to a TRUE  conditional payload
//	falseBody – response to a FALSE conditional payload
//
// A finding is flagged only when:
//  1. trueRatio  ≥ DiffThreshold  (TRUE payload ≈ baseline → query likely executed)
//  2. falseRatio <  DiffThreshold  (FALSE payload ≠ baseline → query changes output)
func DifferentialAnalysis(baseline, trueBody, falseBody string) DiffResult {
	tr := SimilarityRatio(baseline, trueBody)
	fr := SimilarityRatio(baseline, falseBody)

	divergent := tr >= DiffThreshold && fr < DiffThreshold

	evidence := ""
	if divergent {
		evidence = formatEvidence(tr, fr)
	}

	return DiffResult{
		TrueRatio:  tr,
		FalseRatio: fr,
		Divergent:  divergent,
		Evidence:   evidence,
	}
}

func formatEvidence(tr, fr float64) string {
	return strings.TrimSpace(
		strings.Join([]string{
			"Ratio-based differential confirmed SQLi:",
			"  TRUE  payload similarity to baseline : " + pct(tr),
			"  FALSE payload similarity to baseline : " + pct(fr),
			"  Structural divergence detected (threshold " + pct(DiffThreshold) + ")",
		}, "\n"),
	)
}

func pct(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		strings.Replace(strings.TrimRight(
			strings.TrimRight(
				// fmt.Sprintf("%.1f%%", f*100),  — avoid importing fmt here
				formatFloat(f*100)+"%%", "0"), "."), ".", "", 1), "0"), ".")
}

func formatFloat(f float64) string {
	// Simple fixed-1 decimal formatter without importing fmt
	i := int64(f * 10)
	whole := i / 10
	frac := i % 10
	if frac < 0 {
		frac = -frac
	}
	return intToStr(whole) + "." + intToStr(frac)
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
