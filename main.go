// Toran_MAP v2.0.0 — Enterprise-Grade Network Assessment Engine
// Entry point: CLI flag parsing → scanner.Run → report generation.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wormsystem/toran_map/proxy"
	"github.com/wormsystem/toran_map/scanner"
	"github.com/wormsystem/toran_map/utils"
)

// ─────────────────────────── CLI Flags ───────────────────────────────────────

type cliFlags struct {
	target       string
	stealth      bool
	timeout      int
	concurrency  int
	outJSON      string
	outMarkdown  string
	sshProxies   string // comma-separated "user:pass@host:port" connection strings
}

func parseFlags() cliFlags {
	var f cliFlags
	flag.StringVar(&f.target, "u", "", "Target URL  (required)  e.g. https://example.com/page.php?id=1")
	flag.BoolVar(&f.stealth, "stealth", false, "Enable stealth mode (extended payload bank, slower throttle)")
	flag.IntVar(&f.timeout, "timeout", 30, "HTTP request timeout in seconds")
	flag.IntVar(&f.concurrency, "c", 8, "Maximum concurrent goroutines")
	flag.StringVar(&f.outJSON, "o", "", "Write JSON report to this file  e.g. report.json")
	flag.StringVar(&f.outMarkdown, "md", "", "Write Markdown report to this file  e.g. report.md")
	flag.StringVar(&f.sshProxies, "proxy", "",
		`Comma-separated SSH tunnel connection strings:
  Format:  "user:pass@host:port[,user2:pass2@host2:port2,...]"
  Example: "root:s3cr3t@10.0.0.1:22,admin:pwd@10.0.0.2:22"
  Supports 1–10 entries. Enables Round-Robin load balancing.`)

	flag.Usage = usage
	flag.Parse()
	return f
}

func usage() {
	fmt.Fprintf(os.Stderr, `
Toran_MAP v2.0.0 — Enterprise SQL Injection Assessment Engine

USAGE:
  toran_map -u <URL> [options]

OPTIONS:
`)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
EXAMPLES:
  # Basic scan
  toran_map -u "https://target.com/page.php?id=1"

  # Stealth mode with JSON + Markdown reports
  toran_map -u "https://target.com/search?q=test" --stealth -o report.json -md report.md

  # Via single SSH tunnel
  toran_map -u "https://target.com/page.php?id=1" -proxy "root:pass@1.2.3.4:22"

  # Round-Robin over 3 SSH lines
  toran_map -u "https://target.com/page.php?id=1" \
    -proxy "user1:p1@host1:22,user2:p2@host2:22,user3:p3@host3:22" \
    --stealth -o out.json

`)
}

// ─────────────────────────── SSH Proxy Parser ────────────────────────────────

func parseSSHProxies(raw string) ([]proxy.SSHConfig, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	configs := make([]proxy.SSHConfig, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		cfg, err := proxy.ParseConnectionString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH proxy string %q: %w", p, err)
		}
		configs = append(configs, cfg)
	}
	if len(configs) > 10 {
		return nil, fmt.Errorf("maximum 10 SSH proxies supported, got %d", len(configs))
	}
	return configs, nil
}

// ─────────────────────────── Main ────────────────────────────────────────────

func main() {
	f := parseFlags()

	if f.target == "" {
		utils.PrintBanner()
		fmt.Fprintln(os.Stderr, "  ERROR: -u <URL> is required.\n")
		flag.Usage()
		os.Exit(1)
	}

	sshCfgs, err := parseSSHProxies(f.sshProxies)
	if err != nil {
		fmt.Fprintln(os.Stderr, "  ERROR:", err)
		os.Exit(1)
	}

	cfg := scanner.ScanConfig{
		TargetURL:   f.target,
		StealthMode: f.stealth,
		Timeout:     time.Duration(f.timeout) * time.Second,
		Concurrency: f.concurrency,
		SSHProxies:  sshCfgs,
	}

	started := time.Now()
	findings, err := scanner.Run(cfg)
	finished := time.Now()

	if err != nil {
		utils.PrintWarning(fmt.Sprintf("Scan error: %v", err))
		os.Exit(2)
	}

	// ── Build & print report
	report := scanner.BuildReport(f.target, f.stealth, findings, started, finished)
	scanner.PrintConsoleReport(report)

	// ── Optional JSON export
	if f.outJSON != "" {
		if err := scanner.WriteJSONReport(report, f.outJSON); err != nil {
			utils.PrintWarning(fmt.Sprintf("JSON report error: %v", err))
		} else {
			utils.PrintSuccess(fmt.Sprintf("JSON report saved → %s", f.outJSON))
		}
	}

	// ── Optional Markdown export
	if f.outMarkdown != "" {
		if err := scanner.WriteMarkdownReport(report, f.outMarkdown); err != nil {
			utils.PrintWarning(fmt.Sprintf("Markdown report error: %v", err))
		} else {
			utils.PrintSuccess(fmt.Sprintf("Markdown report saved → %s", f.outMarkdown))
		}
	}

	// Exit code mirrors finding count for CI/CD pipelines
	if len(findings) > 0 {
		os.Exit(1)
	}
}
