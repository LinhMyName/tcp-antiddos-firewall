package surge

import (
	"sync"
	"time"

	"firewall/pkg/config"
)

// DefenseMode indicates the overall system defense state.
type DefenseMode string

const (
	ModeNormal   DefenseMode = "NORMAL"
	ModeElevated DefenseMode = "ELEVATED"
	ModeCritical DefenseMode = "CRITICAL"
)

// SurgeDetector manages adaptive throttling and surge protection (Layer 8).
type SurgeDetector struct {
	mu           sync.RWMutex
	mode         DefenseMode
	modeUntil    time.Time
	recentRates  []int
	baselineRate float64

	currentSecConns int
	lastSec         time.Time

	attackTokens    int
	lastTokenRefill time.Time
}

// New creates a SurgeDetector.
func New() *SurgeDetector {
	return &SurgeDetector{
		mode:            ModeNormal,
		recentRates:     make([]int, 0, 60),
		baselineRate:    10.0,
		lastSec:         time.Now(),
		lastTokenRefill: time.Now(),
	}
}

// RecordConnection records an arrival, updates moving baseline, and checks for surge.
func (s *SurgeDetector) RecordConnection(cfg *config.Config) DefenseMode {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if now.Sub(s.lastSec) >= time.Second {
		// New second, record rate
		if s.currentSecConns > 0 {
			s.recentRates = append(s.recentRates, s.currentSecConns)
			if len(s.recentRates) > 30 {
				s.recentRates = s.recentRates[1:]
			}
			// Compute baseline
			sum := 0
			for _, r := range s.recentRates {
				sum += r
			}
			s.baselineRate = float64(sum) / float64(len(s.recentRates))
		}

		// Check surge
		currentRate := float64(s.currentSecConns)
		if s.baselineRate > 5.0 && currentRate >= s.baselineRate*cfg.SurgeMultiplier {
			// Trigger Critical if multiplier exceeded by 5x, else Elevated
			if currentRate >= s.baselineRate*(cfg.SurgeMultiplier+2.0) {
				s.mode = ModeCritical
			} else {
				s.mode = ModeElevated
			}
			s.modeUntil = now.Add(cfg.SurgeCooldownSec)
		}

		s.currentSecConns = 0
		s.lastSec = now
	}

	s.currentSecConns++

	// Check if mode expired
	if (s.mode == ModeElevated || s.mode == ModeCritical) && now.After(s.modeUntil) {
		s.mode = ModeNormal
	}

	return s.mode
}

// AllowExternalConnection checks if external non-whitelisted connections can be accepted in current mode.
func (s *SurgeDetector) AllowExternalConnection(cfg *config.Config) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if now.After(s.modeUntil) {
		s.mode = ModeNormal
	}

	switch s.mode {
	case ModeNormal:
		return true

	case ModeCritical:
		// Whitelist only in critical mode
		return false

	case ModeElevated:
		// Throttle accept rate to max_accept_rate_attack
		elapsed := now.Sub(s.lastTokenRefill).Seconds()
		if elapsed > 0 {
			s.attackTokens += int(elapsed * float64(cfg.MaxAcceptRateAttack))
			if s.attackTokens > cfg.MaxAcceptRateAttack {
				s.attackTokens = cfg.MaxAcceptRateAttack
			}
			s.lastTokenRefill = now
		}

		if s.attackTokens > 0 {
			s.attackTokens--
			return true
		}
		return false
	}

	return true
}

// CurrentMode returns active defense mode.
func (s *SurgeDetector) CurrentMode() DefenseMode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode
}

// SetMode manually triggers a defense mode.
func (s *SurgeDetector) SetMode(mode DefenseMode, duration time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = mode
	s.modeUntil = time.Now().Add(duration)
}
