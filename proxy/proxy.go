// Package proxy implements a Dynamic Multi-SSH/SOCKS5 Network Load Balancer
// with Round-Robin distribution, automatic fault isolation, and self-healing.
package proxy

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// ─────────────────────────── Configuration Types ─────────────────────────────

// SSHConfig holds the credentials and address for a single SSH/SOCKS5 tunnel.
// Users can populate a slice of these (1 to 10 entries) to enable load balancing.
type SSHConfig struct {
	Username string
	Password string
	Host     string
	Port     int
}

// ParseConnectionString parses a connection string in the format:
//
//	"username:password@host:port"
//
// Returns an SSHConfig or an error.
func ParseConnectionString(s string) (SSHConfig, error) {
	// Expected: user:pass@host:port
	atIdx := strings.LastIndex(s, "@")
	if atIdx < 0 {
		return SSHConfig{}, fmt.Errorf("missing '@' in connection string: %q", s)
	}
	creds := s[:atIdx]
	hostPort := s[atIdx+1:]

	colonIdx := strings.Index(creds, ":")
	if colonIdx < 0 {
		return SSHConfig{}, fmt.Errorf("missing ':' between username and password in %q", creds)
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return SSHConfig{}, fmt.Errorf("invalid host:port %q: %w", hostPort, err)
	}

	var port int
	fmt.Sscanf(portStr, "%d", &port)
	if port == 0 {
		port = 22
	}

	return SSHConfig{
		Username: creds[:colonIdx],
		Password: creds[colonIdx+1:],
		Host:     host,
		Port:     port,
	}, nil
}

// ─────────────────────────── Dialer State ────────────────────────────────────

type dialerState int32

const (
	stateActive   dialerState = 0
	stateIsolated dialerState = 1
)

// sshDialer wraps a single SSH connection and its derived HTTP transport.
type sshDialer struct {
	cfg       SSHConfig
	client    *ssh.Client
	transport *http.Transport
	state     atomic.Int32 // dialerState
	failures  atomic.Int32
	mu        sync.Mutex
}

// isActive returns true if this dialer is not in the isolation queue.
func (d *sshDialer) isActive() bool {
	return dialerState(d.state.Load()) == stateActive
}

// isolate moves the dialer to the isolation queue.
func (d *sshDialer) isolate() {
	d.state.Store(int32(stateIsolated))
}

// restore brings a dialer back to active state and resets failure counter.
func (d *sshDialer) restore() {
	d.failures.Store(0)
	d.state.Store(int32(stateActive))
}

// dial (re)connects the SSH tunnel and rebuilds the HTTP transport.
func (d *sshDialer) dial() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.client != nil {
		d.client.Close()
	}

	sshCfg := &ssh.ClientConfig{
		User: d.cfg.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(d.cfg.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         15 * time.Second,
	}

	addr := fmt.Sprintf("%s:%d", d.cfg.Host, d.cfg.Port)
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return fmt.Errorf("SSH dial %s: %w", addr, err)
	}
	d.client = client

	d.transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return client.Dial(network, addr)
		},
		MaxIdleConnsPerHost:   20,
		DisableKeepAlives:     false,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return nil
}

// httpClient returns an *http.Client routed through this SSH tunnel.
func (d *sshDialer) httpClient(timeout time.Duration) *http.Client {
	d.mu.Lock()
	t := d.transport
	d.mu.Unlock()
	return &http.Client{
		Transport: t,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// ─────────────────────────── Pool / Router ───────────────────────────────────

const (
	maxFailuresBeforeIsolation = 3
	recoveryCheckInterval      = 45 * time.Second
)

// Pool manages a collection of SSH dialers and implements Round-Robin
// load balancing with automatic fault isolation and recovery.
type Pool struct {
	dialers []*sshDialer
	cursor  atomic.Int64
	mu      sync.RWMutex
	timeout time.Duration
}

// NewPool constructs a Pool from a slice of SSHConfig entries.
// Connections are established eagerly; entries that fail initial dial are
// placed in isolation but kept for later recovery attempts.
func NewPool(configs []SSHConfig, timeout time.Duration) (*Pool, error) {
	if len(configs) == 0 {
		return nil, fmt.Errorf("proxy pool requires at least one SSHConfig")
	}
	if len(configs) > 10 {
		return nil, fmt.Errorf("proxy pool supports at most 10 SSHConfig entries")
	}

	p := &Pool{timeout: timeout}

	for _, cfg := range configs {
		d := &sshDialer{cfg: cfg}
		if err := d.dial(); err != nil {
			// Mark isolated but still keep in pool for recovery
			d.isolate()
		}
		p.dialers = append(p.dialers, d)
	}

	// Start background recovery goroutine
	go p.recoveryLoop()

	return p, nil
}

// NewPoolFromStrings builds a Pool from connection strings.
//
//	"username:password@host:port"
func NewPoolFromStrings(connStrings []string, timeout time.Duration) (*Pool, error) {
	var configs []SSHConfig
	for _, s := range connStrings {
		cfg, err := ParseConnectionString(s)
		if err != nil {
			return nil, err
		}
		configs = append(configs, cfg)
	}
	return NewPool(configs, timeout)
}

// next returns the next active dialer via Round-Robin.
// Returns nil if no active dialers are available.
func (p *Pool) next() *sshDialer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	n := int64(len(p.dialers))
	if n == 0 {
		return nil
	}

	// Try up to n times to find an active dialer
	for i := int64(0); i < n; i++ {
		idx := p.cursor.Add(1) % n
		d := p.dialers[idx]
		if d.isActive() {
			return d
		}
	}
	return nil
}

// Do executes an *http.Request through the next available dialer.
// On timeout or connection failure it isolates the offending dialer and
// automatically retries through the next healthy line.
func (p *Pool) Do(req *http.Request) (*http.Response, error) {
	p.mu.RLock()
	total := len(p.dialers)
	p.mu.RUnlock()

	for attempt := 0; attempt < total; attempt++ {
		d := p.next()
		if d == nil {
			return nil, fmt.Errorf("no active SSH dialers available")
		}

		resp, err := d.httpClient(p.timeout).Do(req)
		if err != nil {
			fails := d.failures.Add(1)
			if int(fails) >= maxFailuresBeforeIsolation {
				d.isolate()
			}
			// Clone request for retry (body already nil for GET)
			req = req.Clone(req.Context())
			continue
		}
		// Success — reset failure counter
		d.failures.Store(0)
		return resp, nil
	}
	return nil, fmt.Errorf("all SSH dialers failed or are isolated")
}

// HasDialers reports whether the pool was initialized with at least one entry.
func (p *Pool) HasDialers() bool {
	return len(p.dialers) > 0
}

// Close shuts down all SSH connections in the pool.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, d := range p.dialers {
		d.mu.Lock()
		if d.client != nil {
			d.client.Close()
		}
		d.mu.Unlock()
	}
}

// recoveryLoop periodically attempts to reconnect isolated dialers.
func (p *Pool) recoveryLoop() {
	ticker := time.NewTicker(recoveryCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.RLock()
		isolated := make([]*sshDialer, 0)
		for _, d := range p.dialers {
			if !d.isActive() {
				isolated = append(isolated, d)
			}
		}
		p.mu.RUnlock()

		for _, d := range isolated {
			if err := d.dial(); err == nil {
				d.restore()
			}
		}
	}
}

// ─────────────────────────── Direct (no-proxy) transport ─────────────────────

// DirectTransport returns a plain HTTP transport (used when no SSH pool is configured).
func DirectTransport(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   20,
			DisableKeepAlives:     false,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

// ─────────────────────────── Jittered Adaptive Delay ─────────────────────────

// AdaptiveThrottle tracks server latency and computes jittered sleep durations
// that mimic natural human browsing behaviour and avoid rate-limiting.
type AdaptiveThrottle struct {
	mu          sync.Mutex
	latencySamples []time.Duration
	maxSamples  int
}

// NewAdaptiveThrottle creates a throttle with a rolling window of latency samples.
func NewAdaptiveThrottle() *AdaptiveThrottle {
	return &AdaptiveThrottle{maxSamples: 10}
}

// Record adds a new latency measurement.
func (t *AdaptiveThrottle) Record(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.latencySamples = append(t.latencySamples, d)
	if len(t.latencySamples) > t.maxSamples {
		t.latencySamples = t.latencySamples[1:]
	}
}

// Sleep blocks for a jittered duration derived from recent server latency.
//
// Formula:  sleep = avgLatency * [1.0 … 3.0] + uniformJitter([50ms … 300ms])
//
// This ensures organic inter-request spacing that scales with server load.
func (t *AdaptiveThrottle) Sleep() {
	t.mu.Lock()
	samples := make([]time.Duration, len(t.latencySamples))
	copy(samples, t.latencySamples)
	t.mu.Unlock()

	base := 200 * time.Millisecond
	if len(samples) > 0 {
		var total time.Duration
		for _, s := range samples {
			total += s
		}
		base = total / time.Duration(len(samples))
	}

	// Multiply by a random factor in [1.0, 3.0]
	factor := 1.0 + rand.Float64()*2.0 //nolint:gosec
	sleep := time.Duration(float64(base)*factor) + time.Duration(50+rand.Intn(250))*time.Millisecond //nolint:gosec

	// Clamp between 100 ms and 4 s
	if sleep < 100*time.Millisecond {
		sleep = 100 * time.Millisecond
	}
	if sleep > 4*time.Second {
		sleep = 4 * time.Second
	}
	time.Sleep(sleep)
}
