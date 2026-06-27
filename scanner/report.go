// Package scanner — report.go
// Generates structured console + JSON + Markdown reports from scan findings.
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wormsystem/toran_map/utils"
)

// ─────────────────────────── Report Structure ─────────────────────────────────

// ScanReport is the top-level report object.
type ScanReport struct {
	Meta     ReportMeta          `json:"meta"`
	Summary  ReportSummary       `json:"summary"`
	Findings []utils.FindingInfo `json:"findings"`
}

// ReportMeta holds metadata about the scan session.
type ReportMeta struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Duration   string    `json:"duration"`
	StealthMode bool     `json:"stealth_mode"`
}

// ReportSummary holds aggregate counts by severity.
type ReportSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ─────────────────────────── Builder ─────────────────────────────────────────

// BuildReport assembles a ScanReport from raw findings.
func BuildReport(target string, stealth bool, findings []utils.FindingInfo, started, finished time.Time) ScanReport {
	summary := ReportSummary{Total: len(findings)}
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
	}

	return ScanReport{
		Meta: ReportMeta{
			Tool:        "Toran_MAP",
			Version:     "2.0.0-enterprise",
			Target:      target,
			StartedAt:   started,
			FinishedAt:  finished,
			Duration:    finished.Sub(started).Round(time.Millisecond).String(),
			StealthMode: stealth,
		},
		Summary:  summary,
		Findings: findings,
	}
}

// ─────────────────────────── Console Output ──────────────────────────────────

// PrintConsoleReport renders the report to stdout in a readable format.
func PrintConsoleReport(r ScanReport) {
	utils.PrintSection("SCAN REPORT")

	fmt.Printf("  %-15s %s\n", "Tool:", r.Meta.Tool+" v"+r.Meta.Version)
	fmt.Printf("  %-15s %s\n", "Target:", r.Meta.Target)
	fmt.Printf("  %-15s %s\n", "Duration:", r.Meta.Duration)
	fmt.Printf("  %-15s %v\n", "Stealth:", r.Meta.StealthMode)
	fmt.Println()

	fmt.Printf("  %-10s %d\n", "Total:", r.Summary.Total)
	if r.Summary.Critical > 0 {
		fmt.Printf("  \033[35m%-10s %d\033[0m\n", "Critical:", r.Summary.Critical)
	}
	if r.Summary.High > 0 {
		fmt.Printf("  \033[31m%-10s %d\033[0m\n", "High:", r.Summary.High)
	}
	if r.Summary.Medium > 0 {
		fmt.Printf("  \033[33m%-10s %d\033[0m\n", "Medium:", r.Summary.Medium)
	}
	if r.Summary.Low > 0 {
		fmt.Printf("  \033[32m%-10s %d\033[0m\n", "Low:", r.Summary.Low)
	}

	if len(r.Findings) == 0 {
		fmt.Println("\n  \033[32m[✓] No SQL Injection vulnerabilities detected.\033[0m")
		return
	}

	utils.PrintSection("FINDINGS DETAIL")
	for i, f := range r.Findings {
		col := severityColor(f.Severity)
		fmt.Printf("\n  \033[1m[#%02d]\033[0m %s%s\033[0m\n", i+1, col, f.Vector)
		fmt.Printf("  %-12s %s\n", "Severity:", col+f.Severity+"\033[0m")
		fmt.Printf("  %-12s %s\n", "Method:", f.Method)
		fmt.Printf("  %-12s %s\n", "Parameter:", f.Parameter)
		fmt.Printf("  %-12s %s\n", "URL:", f.URL)
		fmt.Printf("  %-12s %s\n", "Payload:", truncate(f.Payload, 80))
		fmt.Printf("  %-12s %s\n", "Evidence:", truncate(f.Evidence, 120))
	}
}

func severityColor(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "\033[35m"
	case "high":
		return "\033[31m"
	case "medium":
		return "\033[33m"
	case "low":
		return "\033[32m"
	default:
		return "\033[36m"
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "…"
}

// ─────────────────────────── JSON Export ─────────────────────────────────────

// WriteJSONReport serialises the report to a JSON file.
func WriteJSONReport(r ScanReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create JSON report: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// ─────────────────────────── Markdown Export ─────────────────────────────────

// WriteMarkdownReport writes a Markdown-formatted report file.
func WriteMarkdownReport(r ScanReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create Markdown report: %w", err)
	}
	defer f.Close()

	w := func(s string) { fmt.Fprintln(f, s) }

	w("# Toran_MAP — SQL Injection Assessment Report")
	w("")
	w("## Metadata")
	w("")
	w(fmt.Sprintf("| Field | Value |"))
	w(fmt.Sprintf("|---|---|"))
	w(fmt.Sprintf("| Tool | %s %s |", r.Meta.Tool, r.Meta.Version))
	w(fmt.Sprintf("| Target | `%s` |", r.Meta.Target))
	w(fmt.Sprintf("| Started | %s |", r.Meta.StartedAt.Format(time.RFC3339)))
	w(fmt.Sprintf("| Finished | %s |", r.Meta.FinishedAt.Format(time.RFC3339)))
	w(fmt.Sprintf("| Duration | %s |", r.Meta.Duration))
	w(fmt.Sprintf("| Stealth Mode | %v |", r.Meta.StealthMode))
	w("")
	w("## Summary")
	w("")
	w(fmt.Sprintf("| Severity | Count |"))
	w("|---|---|")
	w(fmt.Sprintf("| 🟣 Critical | %d |", r.Summary.Critical))
	w(fmt.Sprintf("| 🔴 High     | %d |", r.Summary.High))
	w(fmt.Sprintf("| 🟡 Medium   | %d |", r.Summary.Medium))
	w(fmt.Sprintf("| 🟢 Low      | %d |", r.Summary.Low))
	w(fmt.Sprintf("| **Total**  | **%d** |", r.Summary.Total))
	w("")

	if len(r.Findings) == 0 {
		w("## Result")
		w("")
		w("> ✅ No SQL Injection vulnerabilities were detected.")
		return nil
	}

	w("## Findings")
	w("")

	for i, fi := range r.Findings {
		w(fmt.Sprintf("### Finding #%02d — %s", i+1, fi.Vector))
		w("")
		w(fmt.Sprintf("| Field | Value |"))
		w("|---|---|")
		w(fmt.Sprintf("| Severity  | **%s** |", fi.Severity))
		w(fmt.Sprintf("| Method    | `%s` |", fi.Method))
		w(fmt.Sprintf("| Parameter | `%s` |", fi.Parameter))
		w(fmt.Sprintf("| URL       | `%s` |", fi.URL))
		w(fmt.Sprintf("| Payload   | `%s` |", mdEscape(fi.Payload)))
		w(fmt.Sprintf("| Evidence  | %s |", mdEscape(fi.Evidence)))
		w("")
	}
	return nil
}

func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "`", "'")
	if len(s) > 200 {
		s = s[:197] + "…"
	}
	return s
}
