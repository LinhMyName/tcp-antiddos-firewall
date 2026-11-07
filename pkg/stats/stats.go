package stats

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// AttackEvent represents an attack detection or block event.
type AttackEvent struct {
	Timestamp   string `json:"timestamp"`
	TimeUnix    int64  `json:"ts"`
	IP          string `json:"ip"`
	Level       string `json:"level"`
	Signature   string `json:"signature"`
	Details     string `json:"details"`
	RouteName   string `json:"route_name,omitempty"`
}

// TrafficPoint represents a 1-second telemetry sample for the 180s oscilloscope chart.
type TrafficPoint struct {
	Time        string  `json:"time"`
	TimeUnix    int64   `json:"ts"`
	MbpsIn      float64 `json:"mbps_in"`
	MbpsOut     float64 `json:"mbps_out"`
	PPSIn       int64   `json:"pps_in"`
	PPSOut      int64   `json:"pps_out"`
	Blocked     int64   `json:"blocked"`
	ActiveConns int64   `json:"active_conns"`
}

// SnapshotData holds the full point-in-time telemetry snapshot for the Web Control Plane.
type SnapshotData struct {
	UptimeSec   int64            `json:"uptime_sec"`
	TotalConn   int64            `json:"total_conn"`
	BlockedConn int64            `json:"blocked_conn"`
	BytesIn     int64            `json:"bytes_in"`
	BytesOut    int64            `json:"bytes_out"`
	PacketsIn   int64            `json:"packets_in"`
	PacketsOut  int64            `json:"packets_out"`
	CurMbpsIn   float64          `json:"cur_mbps_in"`
	CurMbpsOut  float64          `json:"cur_mbps_out"`
	CurPPSIn    int64            `json:"cur_pps_in"`
	CurPPSOut   int64            `json:"cur_pps_out"`
	PeakMbpsIn  float64          `json:"peak_mbps_in"`
	PeakPPSIn   int64            `json:"peak_pps_in"`
	History     []TrafficPoint   `json:"history"`
	Events      []AttackEvent    `json:"events"`
	LayerCounts map[string]int64 `json:"layer_counts"`
}

// Collector records metrics, bandwidth time-series, and displays the periodic dashboard.
type Collector struct {
	mu            sync.RWMutex
	startTime     time.Time
	totalConn     int64
	totalBlocked  int64
	totalBytesIn  int64
	totalBytesOut int64
	totalPktsIn   int64
	totalPktsOut  int64

	lastBytesIn  int64
	lastBytesOut int64
	lastPktsIn   int64
	lastPktsOut  int64
	lastBlocked  int64

	curMbpsIn  float64
	curMbpsOut float64
	curPPSIn   int64
	curPPSOut  int64
	peakMbpsIn float64
	peakPPSIn  int64

	recentAttacks []AttackEvent
	maxRecent     int
	history       []TrafficPoint
	maxHistory    int
	layerCounts   map[string]int64
}

// New creates a metrics Collector and initializes the 180-second telemetry buffer.
func New() *Collector {
	now := time.Now()
	hist := make([]TrafficPoint, 0, 180)
	// Pre-fill 60s baseline so chart renders immediately on fresh start
	for i := 59; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Second)
		hist = append(hist, TrafficPoint{
			Time:     t.Format("15:04:05"),
			TimeUnix: t.Unix(),
		})
	}
	return &Collector{
		startTime:     now,
		recentAttacks: make([]AttackEvent, 0, 200),
		maxRecent:     200,
		history:       hist,
		maxHistory:    180,
		layerCounts:   make(map[string]int64),
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

// AddTrafficIn records inbound client -> firewall bytes and packets.
func (c *Collector) AddTrafficIn(bytes int64, pkts int64) {
	atomic.AddInt64(&c.totalBytesIn, bytes)
	atomic.AddInt64(&c.totalPktsIn, pkts)
}

// AddTrafficOut records outbound firewall -> client bytes and packets.
func (c *Collector) AddTrafficOut(bytes int64, pkts int64) {
	atomic.AddInt64(&c.totalBytesOut, bytes)
	atomic.AddInt64(&c.totalPktsOut, pkts)
}

// SampleTick computes 1-second bandwidth & packet rates and appends to the 180s ring buffer.
func (c *Collector) SampleTick(activeConns int64) {
	curIn := atomic.LoadInt64(&c.totalBytesIn)
	curOut := atomic.LoadInt64(&c.totalBytesOut)
	curPktsIn := atomic.LoadInt64(&c.totalPktsIn)
	curPktsOut := atomic.LoadInt64(&c.totalPktsOut)
	curBlocked := atomic.LoadInt64(&c.totalBlocked)

	c.mu.Lock()
	defer c.mu.Unlock()

	rxB := curIn - c.lastBytesIn
	if rxB < 0 {
		rxB = 0
	}
	txB := curOut - c.lastBytesOut
	if txB < 0 {
		txB = 0
	}
	rxP := curPktsIn - c.lastPktsIn
	if rxP < 0 {
		rxP = 0
	}
	txP := curPktsOut - c.lastPktsOut
	if txP < 0 {
		txP = 0
	}
	drp := curBlocked - c.lastBlocked
	if drp < 0 {
		drp = 0
	}

	c.lastBytesIn = curIn
	c.lastBytesOut = curOut
	c.lastPktsIn = curPktsIn
	c.lastPktsOut = curPktsOut
	c.lastBlocked = curBlocked

	mbpsIn := (float64(rxB) * 8.0) / 1_000_000.0
	mbpsOut := (float64(txB) * 8.0) / 1_000_000.0

	c.curMbpsIn = mbpsIn
	c.curMbpsOut = mbpsOut
	c.curPPSIn = rxP
	c.curPPSOut = txP

	if mbpsIn > c.peakMbpsIn {
		c.peakMbpsIn = mbpsIn
	}
	if rxP > c.peakPPSIn {
		c.peakPPSIn = rxP
	}

	now := time.Now()
	pt := TrafficPoint{
		Time:        now.Format("15:04:05"),
		TimeUnix:    now.Unix(),
		MbpsIn:      mbpsIn,
		MbpsOut:     mbpsOut,
		PPSIn:       rxP,
		PPSOut:      txP,
		Blocked:     drp,
		ActiveConns: activeConns,
	}
	c.history = append(c.history, pt)
	if len(c.history) > c.maxHistory {
		c.history = c.history[len(c.history)-c.maxHistory:]
	}
}

// RecordAttack logs an attack event to the recent ring buffer and console.
func (c *Collector) RecordAttack(ip, threat, sig, reason string) {
	c.IncBlocked()

	now := time.Now()
	event := AttackEvent{
		Timestamp: now.Format("15:04:05"),
		TimeUnix:  now.Unix(),
		IP:        ip,
		Level:     threat,
		Signature: sig,
		Details:   reason,
	}

	c.mu.Lock()
	c.recentAttacks = append(c.recentAttacks, event)
	if len(c.recentAttacks) > c.maxRecent {
		c.recentAttacks = c.recentAttacks[1:]
	}
	c.layerCounts[sig]++
	c.mu.Unlock()

	fmt.Printf("[%s] [ATTACK] %s BLOCKED [%s] %s (%s)\n",
		now.Format("2006-01-02 15:04:05"), ip, threat, sig, reason)
}

// TotalConn returns total connections seen.
func (c *Collector) TotalConn() int64 {
	return atomic.LoadInt64(&c.totalConn)
}

// TotalBlocked returns total blocked connections.
func (c *Collector) TotalBlocked() int64 {
	return atomic.LoadInt64(&c.totalBlocked)
}

// Snapshot returns a thread-safe snapshot of all telemetry metrics for the Web Control Plane.
func (c *Collector) Snapshot() SnapshotData {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hist := make([]TrafficPoint, len(c.history))
	copy(hist, c.history)

	evs := make([]AttackEvent, len(c.recentAttacks))
	copy(evs, c.recentAttacks)

	layers := make(map[string]int64, len(c.layerCounts))
	for k, v := range c.layerCounts {
		layers[k] = v
	}

	return SnapshotData{
		UptimeSec:   int64(time.Since(c.startTime).Seconds()),
		TotalConn:   atomic.LoadInt64(&c.totalConn),
		BlockedConn: atomic.LoadInt64(&c.totalBlocked),
		BytesIn:     atomic.LoadInt64(&c.totalBytesIn),
		BytesOut:    atomic.LoadInt64(&c.totalBytesOut),
		PacketsIn:   atomic.LoadInt64(&c.totalPktsIn),
		PacketsOut:  atomic.LoadInt64(&c.totalPktsOut),
		CurMbpsIn:   c.curMbpsIn,
		CurMbpsOut:  c.curMbpsOut,
		CurPPSIn:    c.curPPSIn,
		CurPPSOut:   c.curPPSOut,
		PeakMbpsIn:  c.peakMbpsIn,
		PeakPPSIn:   c.peakPPSIn,
		History:     hist,
		Events:      evs,
		LayerCounts: layers,
	}
}

// ClearEvents clears recent attack logs.
func (c *Collector) ClearEvents() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.recentAttacks)
	c.recentAttacks = make([]AttackEvent, 0, c.maxRecent)
	return n
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
			fmt.Printf("    * [%s] %s: %s (%s)\n", a.Timestamp, a.IP, a.Signature, a.Details)
		}
	}
	c.mu.RUnlock()
	fmt.Println("--------------------------------")
}
