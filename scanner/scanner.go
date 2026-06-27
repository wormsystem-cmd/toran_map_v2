// Package scanner — scanner.go
// Top-level orchestrator: parameter discovery, scan coordination, result aggregation.
package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/wormsystem/toran_map/proxy"
	"github.com/wormsystem/toran_map/utils"
)

// ─────────────────────────── ScanConfig ──────────────────────────────────────

// ScanConfig holds all runtime options for a scan session.
type ScanConfig struct {
	TargetURL    string
	StealthMode  bool
	Timeout      time.Duration
	Concurrency  int
	SSHProxies   []proxy.SSHConfig  // optional SSH pool entries (1–10)
	ProxyStrings []string           // alternative: connection strings
}

// ─────────────────────────── Parameter Discovery ─────────────────────────────

var formInputRe = regexp.MustCompile(`(?i)<input[^>]+name=["']?([A-Za-z0-9_\-\.]+)["']?`)
var anchorRe    = regexp.MustCompile(`(?i)href=["']([^"'#]+)["']`)

// discoverParameters fetches the page and extracts:
//  1. Query-string parameters from the URL itself
//  2. <input name="…"> fields from the HTML body
//  3. href links that carry query parameters
func discoverParameters(ctx context.Context, d *Dispatcher, rawURL string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req)

	var resp *http.Response
	var body string

	if d.pool != nil && d.pool.HasDialers() {
		resp, err = d.pool.Do(req)
	} else {
		resp, err = d.direct.Do(req)
	}
	if err != nil {
		return nil, fmt.Errorf("discovery fetch failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	body = string(raw)

	params := make(map[string]string)

	// 1. URL query params
	parsed, _ := url.Parse(rawURL)
	for k, v := range parsed.Query() {
		if len(v) > 0 {
			params[k] = v[0]
		}
	}

	// 2. HTML form inputs
	for _, m := range formInputRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			name := m[1]
			if _, exists := params[name]; !exists {
				params[name] = "1"
			}
		}
	}

	// 3. Anchor hrefs with query strings
	for _, m := range anchorRe.FindAllStringSubmatch(body, -1) {
		if len(m) > 1 {
			href := m[1]
			if u, err := url.Parse(href); err == nil {
				for k, v := range u.Query() {
					if _, exists := params[k]; !exists && len(v) > 0 {
						params[k] = v[0]
					}
				}
			}
		}
	}

	return params, nil
}

// ─────────────────────────── Target Normaliser ───────────────────────────────

// normaliseTarget ensures the URL has a scheme and attempts to inject a
// minimal parameter set when none are found.
func normaliseTarget(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL %q has no host", rawURL)
	}
	return u.String(), nil
}

// ─────────────────────────── Engine Bootstrap ────────────────────────────────

// Run is the single entry-point for an entire scan session.
func Run(cfg ScanConfig) ([]utils.FindingInfo, error) {
	// ── 1. Normalise target
	target, err := normaliseTarget(cfg.TargetURL)
	if err != nil {
		return nil, err
	}

	utils.PrintBanner()
	utils.PrintInfo(fmt.Sprintf("Target : %s", target))

	// ── 2. Build proxy pool (optional)
	var pool *proxy.Pool
	switch {
	case len(cfg.SSHProxies) > 0:
		pool, err = proxy.NewPool(cfg.SSHProxies, cfg.Timeout)
		if err != nil {
			utils.PrintWarning(fmt.Sprintf("SSH pool init warning: %v — falling back to direct", err))
			pool = nil
		} else {
			utils.PrintInfo(fmt.Sprintf("SSH pool active: %d line(s)", len(cfg.SSHProxies)))
		}
	case len(cfg.ProxyStrings) > 0:
		pool, err = proxy.NewPoolFromStrings(cfg.ProxyStrings, cfg.Timeout)
		if err != nil {
			utils.PrintWarning(fmt.Sprintf("SSH pool (strings) init warning: %v — falling back to direct", err))
			pool = nil
		} else {
			utils.PrintInfo(fmt.Sprintf("SSH pool active: %d line(s)", len(cfg.ProxyStrings)))
		}
	default:
		utils.PrintInfo("No SSH proxies configured — using direct connection")
	}
	if pool != nil {
		defer pool.Close()
	}

	// ── 3. Build dispatcher
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	d := NewDispatcher(pool, timeout)

	// ── 4. Context with generous deadline
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Hour)
	defer cancel()

	// ── 5. Parameter discovery
	utils.PrintInfo("Discovering parameters…")
	discovered, err := discoverParameters(ctx, d, target)
	if err != nil {
		utils.PrintWarning(fmt.Sprintf("Parameter discovery error: %v", err))
	}

	if len(discovered) == 0 {
		utils.PrintWarning("No parameters found — adding fallback param 'id=1'")
		discovered = map[string]string{"id": "1"}
	}

	// Rebuild target URL with discovered params (merge with existing)
	parsed, _ := url.Parse(target)
	q := parsed.Query()
	for k, v := range discovered {
		if q.Get(k) == "" {
			q.Set(k, v)
		}
	}
	parsed.RawQuery = q.Encode()
	target = parsed.String()

	paramList := make([]string, 0, len(discovered))
	for k := range discovered {
		paramList = append(paramList, k)
	}
	utils.PrintInfo(fmt.Sprintf("Parameters: [%s]", strings.Join(paramList, ", ")))
	if cfg.StealthMode {
		utils.PrintInfo("Stealth mode: ON — extended payload bank active")
	}

	// ── 6. Run SQLi engine
	utils.PrintSection("SQL Injection Assessment")
	start := time.Now()
	findings, err := ScanSQLi(ctx, target, cfg.StealthMode, d)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)

	// ── 7. Summary
	utils.PrintSection("Scan Complete")
	utils.PrintInfo(fmt.Sprintf("Duration : %s", elapsed.Round(time.Millisecond)))
	utils.PrintInfo(fmt.Sprintf("Findings : %d", len(findings)))

	return findings, nil
}
