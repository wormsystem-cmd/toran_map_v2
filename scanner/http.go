// Package scanner — http.go
// Full HTTP Pipeline Reflection: GET params, POST Form/JSON, Headers (Cookies,
// User-Agent, Referer).
// Adaptive Traffic Throttling with randomised header order + rotating User-Agent.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wormsystem/toran_map/proxy"
)

// ─────────────────────────── User-Agent Pool ─────────────────────────────────

var userAgentPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"curl/8.7.1",
}

func randomUA() string {
	return userAgentPool[rand.Intn(len(userAgentPool))] //nolint:gosec
}

// ─────────────────────────── Header Randomiser ───────────────────────────────

type headerEntry struct{ key, val string }

// buildRandomisedHeaders constructs a header map with shuffled optional headers
// so each request has a unique ordering fingerprint.
func buildRandomisedHeaders(ua string) http.Header {
	optional := []headerEntry{
		{"Accept-Language", "en-US,en;q=0.9"},
		{"Accept-Encoding", "gzip, deflate, br"},
		{"Cache-Control", "no-cache"},
		{"Pragma", "no-cache"},
		{"DNT", "1"},
		{"Upgrade-Insecure-Requests", "1"},
		{"Sec-Fetch-Dest", "document"},
		{"Sec-Fetch-Mode", "navigate"},
		{"Sec-Fetch-Site", "none"},
		{"Sec-Fetch-User", "?1"},
		{"TE", "trailers"},
	}

	// Fisher-Yates shuffle
	rand.Shuffle(len(optional), func(i, j int) { //nolint:gosec
		optional[i], optional[j] = optional[j], optional[i]
	})

	// Pick a random subset (3 to 7 headers)
	n := 3 + rand.Intn(5) //nolint:gosec
	if n > len(optional) {
		n = len(optional)
	}

	h := make(http.Header)
	h.Set("User-Agent", ua)
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	for _, e := range optional[:n] {
		h.Set(e.key, e.val)
	}
	return h
}

// ─────────────────────────── HTTP Dispatcher ─────────────────────────────────

// Dispatcher sends HTTP requests through either the SSH pool (if configured)
// or a direct transport, and records latency for the adaptive throttle.
type Dispatcher struct {
	pool     *proxy.Pool
	direct   *http.Client
	throttle *proxy.AdaptiveThrottle
}

// NewDispatcher creates a Dispatcher.  pool may be nil for direct mode.
func NewDispatcher(pool *proxy.Pool, timeout time.Duration) *Dispatcher {
	return &Dispatcher{
		pool:     pool,
		direct:   proxy.DirectTransport(timeout),
		throttle: proxy.NewAdaptiveThrottle(),
	}
}

// Do sends a request, records its latency, and returns body + response.
// Callers should call d.Throttle.Sleep() between requests when appropriate.
func (d *Dispatcher) Do(req *http.Request) (string, *http.Response, error) {
	start := time.Now()
	var (
		resp *http.Response
		err  error
	)

	if d.pool != nil && d.pool.HasDialers() {
		resp, err = d.pool.Do(req)
	} else {
		resp, err = d.direct.Do(req)
	}

	d.throttle.Record(time.Since(start))

	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return "", resp, err
	}
	return string(bodyBytes), resp, nil
}

// Sleep delegates to the adaptive throttle.
func (d *Dispatcher) Sleep() {
	d.throttle.Sleep()
}

// ─────────────────────────── Request Builders ────────────────────────────────

// GETRequest builds a GET request with a single parameter replaced by payload.
func GETRequest(ctx context.Context, base *url.URL, param, payload string) (*http.Request, string) {
	q := base.Query()
	q.Set(param, payload)
	u := *base
	u.RawQuery = q.Encode()
	rawURL := u.String()

	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	applyHeaders(req)
	return req, rawURL
}

// GETRequestRaw builds a GET request without re-encoding the payload
// (needed for WAF-bypass vectors where raw percent-encoding matters).
func GETRequestRaw(ctx context.Context, base *url.URL, param, rawPayload string) (*http.Request, string) {
	otherQ := base.Query()
	otherQ.Del(param)
	rawURL := base.Scheme + "://" + base.Host + base.Path + "?" + param + "=" + rawPayload
	if enc := otherQ.Encode(); enc != "" {
		rawURL += "&" + enc
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	applyHeaders(req)
	return req, rawURL
}

// POSTFormRequest builds a POST request with application/x-www-form-urlencoded body.
func POSTFormRequest(ctx context.Context, target string, params map[string]string) (*http.Request, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applyHeaders(req)
	return req, nil
}

// POSTJSONRequest builds a POST request with a JSON payload.
func POSTJSONRequest(ctx context.Context, target string, payload map[string]interface{}) (*http.Request, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	applyHeaders(req)
	return req, nil
}

// HeaderInjectionRequest tests injection via a specific HTTP header value.
func HeaderInjectionRequest(ctx context.Context, targetURL, headerName, payload string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	applyHeaders(req)
	req.Header.Set(headerName, payload)
	return req, nil
}

// applyHeaders sets randomised, shuffled headers on a request.
func applyHeaders(req *http.Request) {
	ua := randomUA()
	for k, vals := range buildRandomisedHeaders(ua) {
		for _, v := range vals {
			req.Header.Set(k, v)
		}
	}
}

// ─────────────────────────── Baseline Fetch ──────────────────────────────────

// FetchBaseline retrieves the unmodified response for a URL to use as a
// comparison reference in differential analysis.
func FetchBaseline(ctx context.Context, d *Dispatcher, rawURL string) (body string, resp *http.Response, err error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	applyHeaders(req)
	body, resp, err = d.Do(req)
	return
}

// ─────────────────────────── Generic GET Send ────────────────────────────────

// SendGET is a convenience wrapper that builds and fires a GET request.
func SendGET(ctx context.Context, d *Dispatcher, base *url.URL, param, payload string) (string, *http.Response, string, error) {
	req, rawURL := GETRequest(ctx, base, param, payload)
	body, resp, err := d.Do(req)
	return body, resp, rawURL, err
}

// SendGETRaw is the raw-encoding variant of SendGET.
func SendGETRaw(ctx context.Context, d *Dispatcher, base *url.URL, param, rawPayload string) (string, *http.Response, string, error) {
	req, rawURL := GETRequestRaw(ctx, base, param, rawPayload)
	body, resp, err := d.Do(req)
	return body, resp, rawURL, err
}

// TimedSendGET returns the elapsed time in addition to the standard outputs.
func TimedSendGET(ctx context.Context, d *Dispatcher, base *url.URL, param, payload string) (string, *http.Response, string, time.Duration, error) {
	req, rawURL := GETRequest(ctx, base, param, payload)
	start := time.Now()
	body, resp, err := d.Do(req)
	return body, resp, rawURL, time.Since(start), err
}

// FormatDuration converts a duration to a human-readable string for evidence logs.
func FormatDuration(d time.Duration) string {
	return fmt.Sprintf("%.3fs", d.Seconds())
}
