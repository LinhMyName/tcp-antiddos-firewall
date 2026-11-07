package behavior

import (
	"fmt"
	"sync"
	"time"

	"firewall/pkg/config"
)

// IPBehavior tracks behavioral penalties and temporary block states.
type IPBehavior struct {
	mu           sync.Mutex
	PenaltyScore int
	OffenseCount int
	BlockedUntil time.Time
	LastPenalty  time.Time
	BlockReason  string
}

// Manager orchestrates Layer 5 behavioral anomaly detection and penalties.
type Manager struct {
	mu           sync.RWMutex
	records      map[string]*IPBehavior
	onAutoBlacklist func(ip string, reason string)
	onKernelBlock   func(ip string, level int)
}

// New creates a new behavior Manager.
func New(onBlacklist func(ip, reason string), onKernel func(ip string, level int)) *Manager {
	m := &Manager{
		records:         make(map[string]*IPBehavior),
		onAutoBlacklist: onBlacklist,
		onKernelBlock:   onKernel,
	}

	go m.decayLoop()
	return m
}

// AddPenalty adds penalty points to an IP. If threshold reached, triggers progressive ban.
func (m *Manager) AddPenalty(ipStr string, points int, reason string, cfg *config.Config) (bool, time.Duration) {
	record := m.getOrCreate(ipStr)
	record.mu.Lock()
	defer record.mu.Unlock()

	record.PenaltyScore += points
	record.LastPenalty = time.Now()

	// Check if penalty threshold reached
	if record.PenaltyScore >= cfg.PenaltyThreshold {
		record.OffenseCount++
		record.PenaltyScore = 0 // reset score for next tier

		var duration time.Duration
		switch record.OffenseCount {
		case 1:
			duration = cfg.BlockDuration1
		case 2:
			duration = cfg.BlockDuration2
		case 3:
			duration = cfg.BlockDuration3
		default:
			duration = cfg.BlockDuration4
		}

		record.BlockedUntil = time.Now().Add(duration)
		record.BlockReason = reason

		// Trigger Kernel block on 3rd+ offense
		if record.OffenseCount >= cfg.KernelBlockMinLevel && m.onKernelBlock != nil && cfg.KernelBlockEnabled {
			m.onKernelBlock(ipStr, record.OffenseCount)
		}

		// Auto-blacklist permanently if reached threshold
		if record.OffenseCount >= cfg.AutoBlacklistOffenses && m.onAutoBlacklist != nil {
			m.onAutoBlacklist(ipStr, fmt.Sprintf("Auto-blacklisted after %d offenses: %s", record.OffenseCount, reason))
		}

		return true, duration
	}

	return false, 0
}

// IsBlocked checks if IP is currently under a temporary penalty block.
func (m *Manager) IsBlocked(ipStr string) (bool, time.Duration, string) {
	m.mu.RLock()
	record, ok := m.records[ipStr]
	m.mu.RUnlock()

	if !ok {
		return false, 0, ""
	}

	record.mu.Lock()
	defer record.mu.Unlock()

	now := time.Now()
	if now.Before(record.BlockedUntil) {
		remaining := record.BlockedUntil.Sub(now)
		return true, remaining, record.BlockReason
	}

	return false, 0, ""
}

// RecordShortLivedConnection penalizes rapid connect-and-disconnect cycles (common SYN/TCP flood or port scanner).
func (m *Manager) RecordShortLivedConnection(ipStr string, duration time.Duration, bytesExchanged int64, cfg *config.Config) {
	// If connection closed in < 500ms and transferred less than 32 bytes
	if duration < 500*time.Millisecond && bytesExchanged < 32 {
		m.AddPenalty(ipStr, 25, "Short-lived connection violation", cfg)
	}
}

// BlockedIPsCount returns the number of currently temporarily blocked IPs.
func (m *Manager) BlockedIPsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, rec := range m.records {
		rec.mu.Lock()
		if now.Before(rec.BlockedUntil) {
			count++
		}
		rec.mu.Unlock()
	}
	return count
}

func (m *Manager) getOrCreate(ipStr string) *IPBehavior {
	m.mu.RLock()
	r, ok := m.records[ipStr]
	m.mu.RUnlock()
	if ok {
		return r
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok = m.records[ipStr]; ok {
		return r
	}

	r = &IPBehavior{
		LastPenalty: time.Now(),
	}
	m.records[ipStr] = r
	return r
}

func (m *Manager) decayLoop() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		now := time.Now()
		m.mu.Lock()
		for ip, rec := range m.records {
			rec.mu.Lock()
			// Decay penalty if idle for > 1 minute
			if now.Sub(rec.LastPenalty) > 60*time.Second && rec.PenaltyScore > 0 {
				rec.PenaltyScore -= 15
				if rec.PenaltyScore < 0 {
					rec.PenaltyScore = 0
				}
			}
			// Clean up very old inactive records (> 2 hours and not blocked)
			if now.After(rec.BlockedUntil) && now.Sub(rec.LastPenalty) > 2*time.Hour {
				delete(m.records, ip)
			}
			rec.mu.Unlock()
		}
		m.mu.Unlock()
	}
}
