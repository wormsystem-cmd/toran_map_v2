# Toran_MAP v2.0.0 — Enterprise-Grade Network Assessment Engine

> A high-stability SQL Injection assessment engine written in Go, featuring
> Dynamic Multi-SSH Load Balancing, Ratio-Based Differential Analysis,
> Multi-Tier Signature Matching, Full HTTP Pipeline Reflection, and
> Adaptive Traffic Throttling.

---

## Architecture Overview

```
toran_map/
├── main.go                  # CLI entry point, flag parsing, report dispatch
├── go.mod
│
├── proxy/
│   └── proxy.go             # Dynamic Multi-SSH Load Balancer + Adaptive Throttle
│
├── scanner/
│   ├── scanner.go           # Top-level orchestrator, parameter discovery, Run()
│   ├── sqli.go              # 15 injection vectors (Error, Boolean, Time, UNION, …)
│   ├── diff.go              # Ratio-Based Differential Engine (replaces byte-size)
│   ├── signatures.go        # Multi-Tier Signature Bank (Body + Headers + Status)
│   ├── http.go              # Full HTTP Pipeline Reflection + header randomiser
│   └── report.go            # Console / JSON / Markdown report generator
│
└── utils/
    ├── logger.go            # Colourised thread-safe terminal logger
    └── types.go             # Shared FindingInfo struct
```

---

## Feature Matrix

| # | Feature | Description |
|---|---|---|
| 1 | **Dynamic Multi-SSH Load Balancer** | 1–10 SSH/SOCKS5 accounts, Round-Robin distribution, automatic fault isolation, self-healing recovery loop |
| 2 | **Ratio-Based Differential Engine** | Jaccard token-set similarity; noise filters strip timestamps, CSRF tokens, UUIDs, session IDs before comparison |
| 3 | **Multi-Tier Signature Bank** | 40+ RegEx patterns matched against Response Body, HTTP Headers (`X-Powered-By`, `Server`, `Set-Cookie`), and Status Codes |
| 4 | **Full HTTP Pipeline Reflection** | GET query params, POST Form-Data, POST JSON payloads, Header injection (Cookie, User-Agent, Referer, X-Forwarded-For) |
| 5 | **Adaptive Traffic Throttling** | Jittered latency-based sleep (avg_latency × [1–3] + 50–300 ms random jitter); fully randomised header ordering; rotating User-Agent pool (10 agents) |
| 6 | **15 Injection Vectors** | Error-Based, Boolean Differential, Time-Based, UNION, Double-Quote, Comment Termination, Stacked Queries, WAF Bypass, Numeric Context, Polyglot, OOB Marker, Second-Order, POST Form, POST JSON, Header Injection |
| 7 | **Stealth Mode** | Activates extended payload bank (50+ extra payloads), OOB and Second-Order vectors, slower throttle multiplier |
| 8 | **Structured Reporting** | Console (colourised), JSON, and Markdown formats; CI/CD-friendly exit codes |

---

## Installation

```bash
git clone https://github.com/wormsystem/toran_map_v2
cd toran_map
go mod tidy
go build -o toran_map .
```

**Requirement:** Go 1.21+  |  `golang.org/x/crypto`

---

## Usage

```
toran_map -u <URL> [options]

OPTIONS:
  -u        Target URL (required)
  --stealth Enable stealth mode (extended payloads, slower throttle)
  -timeout  HTTP timeout in seconds              [default: 30]
  -c        Concurrent goroutines               [default: 8]
  -o        JSON report output file
  -md       Markdown report output file
  -proxy    Comma-separated SSH connection strings (1–10)
```

### Examples

```bash
# Basic scan
./toran_map -u "https://target.com/page.php?id=1"

# Stealth + reports
./toran_map -u "https://target.com/search?q=test" --stealth \
  -o report.json -md report.md

# Via single SSH tunnel
./toran_map -u "https://target.com/page.php?id=1" \
  -proxy "root:pass@1.2.3.4:22"

# Round-Robin across 3 SSH lines
./toran_map -u "https://target.com/page.php?id=1" \
  -proxy "user1:p1@host1:22,user2:p2@host2:22,user3:p3@host3:22" \
  --stealth -o out.json -md out.md
```

---

## SSH Proxy Configuration

The proxy pool is **fully optional**. When not supplied, the tool connects directly.

### Via connection strings (CLI)
```
user:password@host:port
```

### Via `SSHConfig` struct (embedded use)
```go
pool, err := proxy.NewPool([]proxy.SSHConfig{
    {Username: "root", Password: "s3cr3t", Host: "10.0.0.1", Port: 22},
    {Username: "admin", Password: "pwd",   Host: "10.0.0.2", Port: 22},
}, 30*time.Second)
```

**Fault isolation logic:**
- A dialer is isolated after **3 consecutive failures**
- A background goroutine attempts reconnection every **45 seconds**
- Requests are seamlessly rerouted to healthy dialers during isolation

---

## Differential Engine

The Boolean-Based Blind vector uses a **Ratio-Based Differential Core** instead of raw byte-size comparison:

```
Similarity = |intersection(tokenSet(A), tokenSet(B))| / |union(tokenSet(A), tokenSet(B))|
```

**Noise filters** (applied before comparison):
- Unix / ISO 8601 timestamps
- CSRF tokens, nonces, and session IDs (32–128 hex chars)
- UUIDs / GUIDs
- Cache-busting query strings
- Inline script nonces (CSP)
- Counter / view-count numbers

A finding is flagged **only when:**
1. TRUE payload similarity ≥ 0.85 (query ran, page looks normal)
2. FALSE payload similarity < 0.85 (query altered the page structure)

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Scan completed — no vulnerabilities found |
| `1`  | Vulnerabilities detected (CI/CD gate) |
| `2`  | Fatal scan error |

---

## Legal Disclaimer

> **This tool is intended solely for authorised security assessments.**
> Use only on systems you own or have explicit written permission to test.
> Unauthorised scanning is illegal and unethical.
