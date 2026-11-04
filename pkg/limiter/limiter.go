package limiter

import (
	"sync"
	"sync/atomic"
	"time"

	"firewall/pkg/config"
)

// IPTracker maintains real-time statistics for a single IP address.
type IPTracker struct {
	mu             sync.Mutex
	ActiveConns    int
	LastSeen       time.Time
	ConnWindow     []time.Time
	MsgWindow      []time.Time
	BytesThisSec   int64
	LastByteReset  time.Time
}

// Limiter manages Layer 2 connection tracking and rate limits.
type Limiter struct {
	mu              sync.RWMutex
	trackers        map[string]*IPTracker
	globalActive    int64
	globalConnCount int64
	globalWindow    []time.Time
	windowMu        sync.Mutex
	cleanupInterval time.Duration
}

// New creates a new Limiter.
func New() *Limiter {
	l := &Limiter{
		trackers:        make(map[string]*IPTracker),
		globalWindow:    make([]time.Time, 0, 1000),
		cleanupInterval: 30 * time.Second,
	}

	go l.cleanupLoop()
	return l
}

// CheckAndRecordConnection checks if a new connection from ipStr is allowed.
// If allowed, increments active connection count and records timestamps.
func (l *Limiter) CheckAndRecordConnection(ipStr string, isWhitelisted bool, cfg *config.Config) (bool, string) {
	now := time.Now()

	// 1. Check Global active limit
	active := atomic.LoadInt64(&l.globalActive)
	if active >= int64(cfg.MaxGlobalActive) {
		return false, "Global active connection limit exceeded"
	}

	// 2. Check Global rate limit (sliding 1-second window)
	l.windowMu.Lock()
	cutoff := now.Add(-time.Second)
	validIdx := 0
	for i, t := range l.globalWindow {
		if t.After(cutoff) {
			validIdx = i
			break
		}
	}
	if len(l.globalWindow) > 0 && l.globalWindow[0].Before(cutoff) {
		l.globalWindow = l.globalWindow[validIdx:]
	}
	if len(l.globalWindow) >= cfg.MaxGlobalConnRate {
		l.windowMu.Unlock()
		return false, "Global connection rate limit exceeded"
	}
	l.globalWindow = append(l.globalWindow, now)
	l.windowMu.Unlock()

	// 3. Check Per-IP limits
	tracker := l.getOrCreateTracker(ipStr)
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	tracker.LastSeen = now

	// Determine limits
	maxConn := cfg.MaxConnPerExternalIP
	maxRate := cfg.MaxConnRateExternal
	if isWhitelisted {
		maxConn = cfg.MaxConnPerIP
		maxRate = cfg.MaxConnRate
	}

	// Check concurrent connections
	if tracker.ActiveConns >= maxConn {
		return false, "Max concurrent connections exceeded for IP"
	}

	// Check connection rate (sliding 1-second window)
	connCutoff := now.Add(-time.Second)
	newWindow := tracker.ConnWindow[:0]
	for _, t := range tracker.ConnWindow {
		if t.After(connCutoff) {
			newWindow = append(newWindow, t)
		}
	}
	if len(newWindow) >= maxRate {
		tracker.ConnWindow = newWindow
		return false, "Connection rate limit exceeded for IP"
	}

	// Allowed! Update counts
	tracker.ConnWindow = append(newWindow, now)
	tracker.ActiveConns++
	atomic.AddInt64(&l.globalActive, 1)

	return true, ""
}

// ReleaseConnection decrements active connection counts.
func (l *Limiter) ReleaseConnection(ipStr string) {
	atomic.AddInt64(&l.globalActive, -1)

	l.mu.RLock()
	tracker, ok := l.trackers[ipStr]
	l.mu.RUnlock()

	if ok {
		tracker.mu.Lock()
		if tracker.ActiveConns > 0 {
			tracker.ActiveConns--
		}
		tracker.mu.Unlock()
	}
}

// CheckPacketRate checks packet & bandwidth rate limits during active data exchange.
func (l *Limiter) CheckPacketRate(ipStr string, bytes int, isWhitelisted bool, cfg *config.Config) bool {
	l.mu.RLock()
	tracker, ok := l.trackers[ipStr]
	l.mu.RUnlock()
	if !ok {
		return true
	}

	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Second)

	// Filter message window
	newMsgs := tracker.MsgWindow[:0]
	for _, t := range tracker.MsgWindow {
		if t.After(cutoff) {
			newMsgs = append(newMsgs, t)
		}
	}

	maxMsgs := cfg.MaxMsgsPerSecExternal
	if isWhitelisted {
		maxMsgs = cfg.MaxMsgsPerSec
	}

	if len(newMsgs) >= maxMsgs {
		tracker.MsgWindow = newMsgs
		return false
	}
	tracker.MsgWindow = append(newMsgs, now)

	// Bandwidth check
	if now.Sub(tracker.LastByteReset) >= time.Second {
		tracker.BytesThisSec = 0
		tracker.LastByteReset = now
	}
	tracker.BytesThisSec += int64(bytes)
	if tracker.BytesThisSec > cfg.MaxBytesPerSec {
		return false
	}

	return true
}

func (l *Limiter) getOrCreateTracker(ipStr string) *IPTracker {
	l.mu.RLock()
	tracker, ok := l.trackers[ipStr]
	l.mu.RUnlock()
	if ok {
		return tracker
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if tracker, ok = l.trackers[ipStr]; ok {
		return tracker
	}

	tracker = &IPTracker{
		LastSeen:      time.Now(),
		ConnWindow:    make([]time.Time, 0, 20),
		MsgWindow:     make([]time.Time, 0, 100),
		LastByteReset: time.Now(),
	}
	l.trackers[ipStr] = tracker
	return tracker
}

// GlobalActive returns current total active connections.
func (l *Limiter) GlobalActive() int64 {
	return atomic.LoadInt64(&l.globalActive)
}

// ActiveIPCount returns the number of tracked active IPs.
func (l *Limiter) ActiveIPCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	count := 0
	for _, t := range l.trackers {
		t.mu.Lock()
		if t.ActiveConns > 0 {
			count++
		}
		t.mu.Unlock()
	}
	return count
}

func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(l.cleanupInterval)
	for range ticker.C {
		now := time.Now()
		staleCutoff := now.Add(-5 * time.Minute)

		l.mu.Lock()
		for ip, t := range l.trackers {
			t.mu.Lock()
			if t.ActiveConns == 0 && t.LastSeen.Before(staleCutoff) {
				delete(l.trackers, ip)
			}
			t.mu.Unlock()
		}
		l.mu.Unlock()
	}
}
