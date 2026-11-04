package halfopen

import (
	"sync"
	"sync/atomic"

	"firewall/pkg/config"
)

// Tracker guards against SYN and half-open connection exhaustion attacks (Layer 3).
type Tracker struct {
	mu           sync.Mutex
	globalActive int64
	perIPActive  map[string]int
}

// New creates a half-open connection tracker.
func New() *Tracker {
	return &Tracker{
		perIPActive: make(map[string]int),
	}
}

// Acquire attempts to register a new unverified half-open connection.
// Returns false if global or per-IP half-open limits are exceeded.
func (t *Tracker) Acquire(ipStr string, cfg *config.Config) bool {
	// Check global half-open cap
	current := atomic.AddInt64(&t.globalActive, 1)
	if current > int64(cfg.MaxGlobalHalfOpen) {
		atomic.AddInt64(&t.globalActive, -1)
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	ipCount := t.perIPActive[ipStr]
	if ipCount >= cfg.MaxHalfOpenPerIP {
		atomic.AddInt64(&t.globalActive, -1)
		return false
	}

	t.perIPActive[ipStr] = ipCount + 1
	return true
}

// Release marks the connection as verified (first data received) or dropped.
func (t *Tracker) Release(ipStr string) {
	atomic.AddInt64(&t.globalActive, -1)

	t.mu.Lock()
	defer t.mu.Unlock()

	if count, ok := t.perIPActive[ipStr]; ok {
		if count <= 1 {
			delete(t.perIPActive, ipStr)
		} else {
			t.perIPActive[ipStr] = count - 1
		}
	}
}

// GlobalHalfOpen returns current active half-open count.
func (t *Tracker) GlobalHalfOpen() int64 {
	return atomic.LoadInt64(&t.globalActive)
}
