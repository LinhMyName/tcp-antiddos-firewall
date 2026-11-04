package stats

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// AttackEvent represents an attack detection or block event.
type AttackEvent struct {
	Timestamp   time.Time
	IP          string
	ThreatLevel string
	Signature   string
	Reason      string
}

// Collector records metrics and displays the periodic dashboard.
type Collector struct {
	mu             sync.RWMutex
	startTime      time.Time
	totalConn      int64
	totalBlocked   int64
	recentAttacks  []AttackEvent
	maxRecent      int
}

// New creates a metrics Collector.
func New() *Collector {
	return &Collector{
		startTime:     time.Now(),
		recentAttacks: make([]AttackEvent, 0, 50),
		maxRecent:     10,
	}
}

// IncTotalConn increments total connection counter.
func (c *Collector) IncTotalConn() {
	atomic.AddInt64(&c.totalConn, 1)
}

// IncBlocked increments blocked attempts counter.
func (c *Collector) IncBlocked() {
	atomic.AddInt64(&c.totalBlocked, 1)
}

// RecordAttack logs an attack event to the recent ring buffer and console.
func (c *Collector) RecordAttack(ip, threat, sig, reason string) {
	c.IncBlocked()

	event := AttackEvent{
		Timestamp:   time.Now(),
		IP:          ip,
		ThreatLevel: threat,
		Signature:   sig,
		Reason:      reason,
	}

	c.mu.Lock()
	c.recentAttacks = append(c.recentAttacks, event)
	if len(c.recentAttacks) > c.maxRecent {
		c.recentAttacks = c.recentAttacks[1:]
	}
	c.mu.Unlock()

	// Print immediate alert log
	fmt.Printf("[%s] [ATTACK] %s BLOCKED [%s] %s (%s)\n",
		event.Timestamp.Format("2006-01-02 15:04:05"), ip, threat, sig, reason)
}

// TotalConn returns total connections seen.
func (c *Collector) TotalConn() int64 {
	return atomic.LoadInt64(&c.totalConn)
}

// TotalBlocked returns total blocked connections.
func (c *Collector) TotalBlocked() int64 {
	return atomic.LoadInt64(&c.totalBlocked)
}

// PrintDashboard outputs the current status dashboard.
func (c *Collector) PrintDashboard(
	activeConns int64,
	maxActive int,
	blockedIPs int,
	blockedSubnets int,
	whitelistCount int,
	blacklistCount int,
	defenseMode string,
	adminRights bool,
	listenAddr string,
	upstreamAddr string,
) {
	uptime := time.Since(c.startTime).Truncate(time.Second)

	adminStr := "YES (Kernel blocking enabled)"
	if !adminRights {
		adminStr = "NO (Kernel blocking disabled - socket level only)"
	}

	fmt.Printf("\n--- FIREWALL STATS [%s MODE] ---\n", defenseMode)
	fmt.Printf("  Uptime:          %s\n", uptime)
	fmt.Printf("  Active Conn:     %d / %d\n", activeConns, maxActive)
	fmt.Printf("  Total Conn:      %d\n", c.TotalConn())
	fmt.Printf("  Total Blocked:   %d\n", c.TotalBlocked())
	fmt.Printf("  Blocked IPs:     %d\n", blockedIPs)
	fmt.Printf("  Blocked Subnets: %d\n", blockedSubnets)
	fmt.Printf("  Whitelist:       %d entries\n", whitelistCount)
	fmt.Printf("  Blacklist:       %d entries\n", blacklistCount)
	fmt.Printf("  Listen Address:  %s\n", listenAddr)
	fmt.Printf("  Game Backend:    %s\n", upstreamAddr)
	fmt.Printf("  Admin Rights:    %s\n", adminStr)

	c.mu.RLock()
	if len(c.recentAttacks) > 0 {
		fmt.Println("  Recent Attacks:")
		start := 0
		if len(c.recentAttacks) > 3 {
			start = len(c.recentAttacks) - 3
		}
		for _, a := range c.recentAttacks[start:] {
			fmt.Printf("    * [%s] %s: %s (%s)\n", a.Timestamp.Format("15:04:05"), a.IP, a.Signature, a.Reason)
		}
	}
	c.mu.RUnlock()
	fmt.Println("--------------------------------")
}
