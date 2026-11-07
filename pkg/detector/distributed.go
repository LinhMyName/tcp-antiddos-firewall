package detector

import (
	"fmt"
	"net"
	"sync"
	"time"

	"firewall/pkg/config"
)

// SubnetTracker tracks blocked IPs per /24 and /16 subnet.
type SubnetTracker struct {
	mu           sync.RWMutex
	blocked24    map[string]map[string]struct{} // subnet24 -> set of IPs
	blocked16    map[string]map[string]struct{} // subnet16 -> set of /24 subnets
	autoBlocked  map[string]time.Time           // CIDR -> BlockedUntil
	onBlockCIDR  func(cidr string, reason string)
}

// ClusterDetector detects rapid distributed attacks from multiple distinct IPs.
type ClusterDetector struct {
	mu            sync.Mutex
	recentIPs     map[string]time.Time
	isUnderAttack bool
	attackUntil   time.Time
}

// Detector manages Layer 7 distributed and subnet cluster attack defenses.
type Detector struct {
	subnets *SubnetTracker
	cluster *ClusterDetector
}

// New creates a new Detector instance.
func New(onBlockCIDR func(cidr, reason string)) *Detector {
	return &Detector{
		subnets: &SubnetTracker{
			blocked24:   make(map[string]map[string]struct{}),
			blocked16:   make(map[string]map[string]struct{}),
			autoBlocked: make(map[string]time.Time),
			onBlockCIDR: onBlockCIDR,
		},
		cluster: &ClusterDetector{
			recentIPs: make(map[string]time.Time),
		},
	}
}

// RecordIPBlocked reports a blocked IP to the subnet detector.
// If enough IPs in the same subnet are blocked, escalates to block the /24 or /16.
func (d *Detector) RecordIPBlocked(ipStr string, cfg *config.Config) {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return // IPv4 subnet aggregation
	}

	st := d.subnets
	st.mu.Lock()
	defer st.mu.Unlock()

	v4 := ip.To4()
	subnet24 := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	subnet16 := fmt.Sprintf("%d.%d.0.0/16", v4[0], v4[1])

	// 1. Add to /24 tracking
	if _, ok := st.blocked24[subnet24]; !ok {
		st.blocked24[subnet24] = make(map[string]struct{})
	}
	st.blocked24[subnet24][ipStr] = struct{}{}

	// Check /24 threshold
	if len(st.blocked24[subnet24]) >= cfg.SubnetBlockThreshold24 {
		if _, alreadyBlocked := st.autoBlocked[subnet24]; !alreadyBlocked {
			st.autoBlocked[subnet24] = time.Now().Add(cfg.BlockDuration3)
			if st.onBlockCIDR != nil {
				st.onBlockCIDR(subnet24, fmt.Sprintf("Cluster attack: %d IPs blocked in /24", len(st.blocked24[subnet24])))
			}

			// 2. Add /24 to /16 tracking
			if _, ok := st.blocked16[subnet16]; !ok {
				st.blocked16[subnet16] = make(map[string]struct{})
			}
			st.blocked16[subnet16][subnet24] = struct{}{}

			// Check /16 threshold
			if len(st.blocked16[subnet16]) >= cfg.SubnetBlockThreshold16 {
				if _, alreadyBlocked16 := st.autoBlocked[subnet16]; !alreadyBlocked16 {
					st.autoBlocked[subnet16] = time.Now().Add(cfg.BlockDuration4)
					if st.onBlockCIDR != nil {
						st.onBlockCIDR(subnet16, fmt.Sprintf("Massive cluster: %d /24 subnets blocked in /16", len(st.blocked16[subnet16])))
					}
				}
			}
		}
	}
}

// IsSubnetBlocked checks whether an IP falls into an auto-blocked subnet.
func (d *Detector) IsSubnetBlocked(ipStr string) (bool, string) {
	st := d.subnets
	st.mu.RLock()
	defer st.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, ""
	}

	now := time.Now()
	for cidr, until := range st.autoBlocked {
		if now.Before(until) {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(ip) {
				return true, fmt.Sprintf("Subnet %s is blocked until %s", cidr, until.Format("15:04:05"))
			}
		}
	}

	return false, ""
}

// RecordNewConnectionForCluster records a connection and tests for cluster attack.
// Returns true if a distributed cluster attack is in progress.
func (d *Detector) RecordNewConnectionForCluster(ipStr string, cfg *config.Config) bool {
	cd := d.cluster
	cd.mu.Lock()
	defer cd.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-cfg.ClusterDetectWindowSec)

	// Clean older IPs in window
	for ip, t := range cd.recentIPs {
		if t.Before(cutoff) {
			delete(cd.recentIPs, ip)
		}
	}

	cd.recentIPs[ipStr] = now

	// Check if unique IPs in window exceed threshold
	if len(cd.recentIPs) >= cfg.ClusterDetectMinIPs {
		cd.isUnderAttack = true
		cd.attackUntil = now.Add(cfg.SurgeCooldownSec)
		return true
	}

	if cd.isUnderAttack && now.Before(cd.attackUntil) {
		return true
	}
	cd.isUnderAttack = false
	return false
}

// IsUnderClusterAttack checks if the firewall is currently under distributed attack.
func (d *Detector) IsUnderClusterAttack() bool {
	cd := d.cluster
	cd.mu.Lock()
	defer cd.mu.Unlock()

	if cd.isUnderAttack && time.Now().Before(cd.attackUntil) {
		return true
	}
	cd.isUnderAttack = false
	return false
}

// ActiveBlockedSubnetCount returns the count of currently active blocked subnets.
func (d *Detector) ActiveBlockedSubnetCount() int {
	st := d.subnets
	st.mu.RLock()
	defer st.mu.RUnlock()

	now := time.Now()
	count := 0
	for _, until := range st.autoBlocked {
		if now.Before(until) {
			count++
		}
	}
	return count
}
