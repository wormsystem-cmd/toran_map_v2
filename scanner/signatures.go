// Package scanner — signatures.go
// Multi-Tiered Data Validation Engine: RegEx fingerprints matched against
// Response Body, HTTP Headers, and Status Codes.
package scanner

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// ─────────────────────────── Signature Types ─────────────────────────────────

// MatchTier identifies where in the HTTP response a signature was found.
type MatchTier string

const (
	TierBody    MatchTier = "Body"
	TierHeader  MatchTier = "Header"
	TierStatus  MatchTier = "StatusCode"
)

// DBSignature holds compiled RegEx patterns for a specific database engine.
type DBSignature struct {
	DB      string
	Tier    MatchTier
	Pattern *regexp.Regexp
	// HeaderName is set only for TierHeader matches (e.g. "X-Powered-By")
	HeaderName string
}

// MatchResult is returned when a signature fires.
type MatchResult struct {
	DB       string
	Tier     MatchTier
	Evidence string
}

// ─────────────────────────── Signature Bank ──────────────────────────────────

var bodySignatures = []DBSignature{
	// MySQL
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)you have an error in your sql syntax`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)warning:\s+mysql`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)mysql_fetch|mysql_num_rows|valid mysql result`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)supplied argument is not a valid mysql`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)column count doesn't match value count`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)unknown column\s+'[^']+'\s+in\s+'`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)table '[^']+' doesn't exist`)},
	{DB: "MySQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)com\.mysql\.jdbc`)},
	// MSSQL
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)unclosed quotation mark after the character string`)},
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)incorrect syntax near`)},
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)microsoft ole db provider for sql server`)},
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)odbc sql server driver`)},
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)sqlserver|microsoft jet database`)},
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)conversion failed when converting`)},
	{DB: "MSSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)invalid column name`)},
	// Oracle
	{DB: "Oracle", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)\bORA-\d{4,5}\b`)},
	{DB: "Oracle", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)oracle error|oracle.*driver`)},
	{DB: "Oracle", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)warning.*oci_|quoted string not properly terminated`)},
	{DB: "Oracle", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)\bPL\/SQL\b`)},
	// PostgreSQL
	{DB: "PostgreSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)psql error|postgresql`)},
	{DB: "PostgreSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)pg_query|pg_exec|pg::syntaxerror`)},
	{DB: "PostgreSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)unterminated quoted string at or near`)},
	{DB: "PostgreSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)syntax error at or near`)},
	{DB: "PostgreSQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)invalid input syntax for`)},
	// SQLite
	{DB: "SQLite", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)sqlite error|sqlite3::`)},
	{DB: "SQLite", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)unable to open database file`)},
	{DB: "SQLite", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)unrecognized token:|no such table:`)},
	// Generic
	{DB: "Generic SQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)sql syntax|sqlexception|sqlstate`)},
	{DB: "Generic SQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)\bjdbc\b|\bodbc\b`)},
	{DB: "Generic SQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)org\.postgresql|java\.sql`)},
	{DB: "Generic SQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)\bdb2\b|sybase|database error|db error`)},
	{DB: "Generic SQL", Tier: TierBody, Pattern: regexp.MustCompile(`(?i)query failed|sql command not properly ended`)},
}

var headerSignatures = []DBSignature{
	// Powered-by hints
	{DB: "PHP/MySQL", Tier: TierHeader, Pattern: regexp.MustCompile(`(?i)php`), HeaderName: "X-Powered-By"},
	{DB: "ASP.NET/MSSQL", Tier: TierHeader, Pattern: regexp.MustCompile(`(?i)asp\.net`), HeaderName: "X-Powered-By"},
	{DB: "Java/Oracle", Tier: TierHeader, Pattern: regexp.MustCompile(`(?i)servlet|jsp`), HeaderName: "X-Powered-By"},
	// Server headers that narrow the DB guess
	{DB: "MySQL (IIS)", Tier: TierHeader, Pattern: regexp.MustCompile(`(?i)microsoft-iis`), HeaderName: "Server"},
	// Error pages leaking DB type via cookies
	{DB: "Generic SQL", Tier: TierHeader, Pattern: regexp.MustCompile(`(?i)sql|db|database`), HeaderName: "Set-Cookie"},
}

// statusSignatures maps HTTP status codes to a DB/category hint.
var statusSignatures = map[int]string{
	500: "Internal Server Error (likely SQL error triggered)",
	503: "Service Unavailable (possible DB overload / injection stall)",
}

// ─────────────────────────── Matcher ─────────────────────────────────────────

// MatchSignatures runs all three tiers against a response and returns any hits.
func MatchSignatures(body string, resp *http.Response) []MatchResult {
	var results []MatchResult

	// Tier 1: Body
	lower := strings.ToLower(body)
	for _, sig := range bodySignatures {
		loc := sig.Pattern.FindStringIndex(lower)
		if loc == nil {
			continue
		}
		start := loc[0] - 80
		if start < 0 {
			start = 0
		}
		end := loc[1] + 80
		if end > len(body) {
			end = len(body)
		}
		excerpt := sanitise(body[start:end])
		results = append(results, MatchResult{
			DB:       sig.DB,
			Tier:     TierBody,
			Evidence: fmt.Sprintf("[Body/%s] %q", sig.DB, excerpt),
		})
		break // one body hit is enough; stop scanning more body sigs
	}

	// Tier 2: Headers
	if resp != nil {
		for _, sig := range headerSignatures {
			val := resp.Header.Get(sig.HeaderName)
			if val != "" && sig.Pattern.MatchString(val) {
				results = append(results, MatchResult{
					DB:       sig.DB,
					Tier:     TierHeader,
					Evidence: fmt.Sprintf("[Header/%s: %s=%q]", sig.DB, sig.HeaderName, val),
				})
			}
		}
	}

	// Tier 3: Status Code
	if resp != nil {
		if hint, ok := statusSignatures[resp.StatusCode]; ok {
			results = append(results, MatchResult{
				DB:       "Unknown",
				Tier:     TierStatus,
				Evidence: fmt.Sprintf("[StatusCode %d] %s", resp.StatusCode, hint),
			})
		}
	}

	return results
}

// sanitise removes non-printable characters from an excerpt.
func sanitise(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) || r == '\n' {
			return r
		}
		return -1
	}, strings.TrimSpace(s))
}
