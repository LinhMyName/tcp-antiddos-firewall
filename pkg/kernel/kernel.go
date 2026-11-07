package kernel

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Blocker interfaces with OS packet filtering (Windows Firewall or Linux ipset/iptables).
type Blocker struct {
	mu           sync.Mutex
	enabled      bool
	hasAdmin     bool
	useIPSet     bool
	blockedRules map[string]time.Time
}

// New creates a new Kernel Blocker and checks system privileges.
func New(enabled bool) *Blocker {
	b := &Blocker{
		enabled:      enabled,
		blockedRules: make(map[string]time.Time),
	}

	if enabled {
		b.hasAdmin = b.checkPrivileges()
		if b.hasAdmin && runtime.GOOS == "linux" {
			// Check if ipset is available for O(1) ultra-fast packet dropping
			if _, err := exec.LookPath("ipset"); err == nil {
				b.useIPSet = true
			}
			b.initLinuxFirewall()
		}
	}

	go b.cleanupLoop()
	return b
}

// HasAdminRights returns true if current process can manipulate OS firewall.
func (b *Blocker) HasAdminRights() bool {
	return b.hasAdmin
}

// SetEnabled dynamically toggles kernel-level packet dropping.
func (b *Blocker) SetEnabled(enabled bool) {
	b.mu.Lock()
	b.enabled = enabled
	if enabled && !b.hasAdmin {
		b.hasAdmin = b.checkPrivileges()
		if b.hasAdmin && runtime.GOOS == "linux" {
			if _, err := exec.LookPath("ipset"); err == nil {
				b.useIPSet = true
			}
			b.initLinuxFirewall()
		}
	}
	b.mu.Unlock()
}

// ActiveRuleCount returns the number of OS-level rules managed by the blocker.
func (b *Blocker) ActiveRuleCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.blockedRules)
}

// BlockIP adds an OS-level kernel drop rule for the IP or subnet.
func (b *Blocker) BlockIP(target string, reason string) error {
	if !b.enabled || !b.hasAdmin {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	target = strings.TrimSpace(target)
	if _, exists := b.blockedRules[target]; exists {
		return nil // already blocked
	}

	var err error
	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("AntiDDoS_%s", sanitizeName(target))
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ruleName, "dir=in", "action=block", "remoteip="+target)
		err = cmd.Run()
	} else if runtime.GOOS == "linux" {
		if b.useIPSet {
			// Ultra high-performance O(1) hash lookup
			if strings.Contains(target, "/") {
				cmd := exec.Command("ipset", "add", "antiddos_subnets", target, "-exist")
				err = cmd.Run()
			} else {
				cmd := exec.Command("ipset", "add", "antiddos_blacklist", target, "-exist")
				err = cmd.Run()
			}
		} else {
			// Fallback to standard iptables
			cmd := exec.Command("iptables", "-t", "mangle", "-I", "PREROUTING", "-s", target, "-j", "DROP", "-m", "comment", "--comment", "AntiDDoS")
			err = cmd.Run()
		}
	}

	if err == nil {
		b.blockedRules[target] = time.Now()
	}
	return err
}

// UnblockIP removes the OS-level rule.
func (b *Blocker) UnblockIP(target string) error {
	if !b.enabled || !b.hasAdmin {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	target = strings.TrimSpace(target)
	delete(b.blockedRules, target)

	if runtime.GOOS == "windows" {
		ruleName := fmt.Sprintf("AntiDDoS_%s", sanitizeName(target))
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)
		return cmd.Run()
	} else if runtime.GOOS == "linux" {
		if b.useIPSet {
			if strings.Contains(target, "/") {
				return exec.Command("ipset", "del", "antiddos_subnets", target).Run()
			}
			return exec.Command("ipset", "del", "antiddos_blacklist", target).Run()
		}
		return exec.Command("iptables", "-t", "mangle", "-D", "PREROUTING", "-s", target, "-j", "DROP").Run()
	}
	return nil
}

// ClearAllAntiDDoSRules cleans up all rules created by the firewall.
func (b *Blocker) ClearAllAntiDDoSRules() {
	if !b.hasAdmin {
		return
	}

	if runtime.GOOS == "windows" {
		_ = exec.Command("powershell", "-Command", "Get-NetFirewallRule -Name 'AntiDDoS_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule").Run()
	} else if runtime.GOOS == "linux" {
		b.clearLinuxGeoIPRules()
		if b.useIPSet {
			_ = exec.Command("ipset", "flush", "antiddos_blacklist").Run()
			_ = exec.Command("ipset", "flush", "antiddos_subnets").Run()
			_ = exec.Command("ipset", "flush", "antiddos_geo_allow").Run()
		} else {
			_ = exec.Command("bash", "-c", "iptables -t mangle -S PREROUTING | grep 'AntiDDoS' | sed 's/-A/-D/' | while read line; do iptables -t mangle $line; done").Run()
		}
	}
}

// SyncGeoIPKernelRules configures OS-level ipset/iptables rules for Inbound and Outbound country filtering on Linux.
func (b *Blocker) SyncGeoIPKernelRules(enforce bool, direction string, firewallPort int, allowedCIDRs []string, extraAllowed []string) {
	if !b.enabled || !b.hasAdmin || runtime.GOOS != "linux" || !b.useIPSet {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	b.clearLinuxGeoIPRules()
	if !enforce || len(allowedCIDRs) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString("create antiddos_geo_allow hash:net family inet hashsize 16384 maxelem 500000 -exist\n")
	sb.WriteString("create antiddos_geo_tmp hash:net family inet hashsize 16384 maxelem 500000 -exist\n")
	sb.WriteString("flush antiddos_geo_tmp\n")

	// Always allow private/loopback subnets in kernel set
	privateNets := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
	for _, netStr := range privateNets {
		sb.WriteString(fmt.Sprintf("add antiddos_geo_tmp %s -exist\n", netStr))
	}
	for _, extra := range extraAllowed {
		extra = strings.TrimSpace(extra)
		if extra != "" && !strings.Contains(extra, ":") {
			sb.WriteString(fmt.Sprintf("add antiddos_geo_tmp %s -exist\n", extra))
		}
	}
	for _, cidr := range allowedCIDRs {
		sb.WriteString(fmt.Sprintf("add antiddos_geo_tmp %s -exist\n", cidr))
	}
	sb.WriteString("swap antiddos_geo_tmp antiddos_geo_allow\n")
	sb.WriteString("destroy antiddos_geo_tmp\n")

	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = strings.NewReader(sb.String())
	if err := cmd.Run(); err != nil {
		fmt.Printf("[KERNEL-GEOIP] Failed to load ipset antiddos_geo_allow: %v\n", err)
		return
	}

	dir := strings.ToLower(strings.TrimSpace(direction))
	if dir == "in" || dir == "both" || dir == "" {
		inCmd := fmt.Sprintf("iptables -t mangle -I PREROUTING 1 -p tcp --dport %d -m set ! --match-set antiddos_geo_allow src -j DROP -m comment --comment AntiDDoS_GeoIP_In", firewallPort)
		_ = exec.Command("bash", "-c", inCmd).Run()
	}
	if dir == "out" || dir == "both" || dir == "" {
		outCmd := "iptables -I OUTPUT 1 -p tcp -m conntrack --ctstate NEW ! --dport 53 -m set ! --match-set antiddos_geo_allow dst -j REJECT -m comment --comment AntiDDoS_GeoIP_Out"
		_ = exec.Command("bash", "-c", outCmd).Run()
	}
	fmt.Printf("[KERNEL-GEOIP] Active OS-level GeoIP enforcement [Direction: %s, Subnets: %d]\n", strings.ToUpper(dir), len(allowedCIDRs))
}

func (b *Blocker) clearLinuxGeoIPRules() {
	_ = exec.Command("bash", "-c", "iptables -t mangle -S PREROUTING | grep 'AntiDDoS_GeoIP_In' | sed 's/-A/-D/' | while read line; do iptables -t mangle $line; done").Run()
	_ = exec.Command("bash", "-c", "iptables -S OUTPUT | grep 'AntiDDoS_GeoIP_Out' | sed 's/-A/-D/' | while read line; do iptables $line; done").Run()
}

func (b *Blocker) checkPrivileges() bool {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("net", "session")
		return cmd.Run() == nil
	} else if runtime.GOOS == "linux" {
		out, err := exec.Command("id", "-u").Output()
		if err == nil && strings.TrimSpace(string(out)) == "0" {
			return true
		}
	}
	return false
}

func (b *Blocker) initLinuxFirewall() {
	if b.useIPSet {
		// Initialize hash:ip and hash:net sets
		_ = exec.Command("ipset", "create", "antiddos_blacklist", "hash:ip", "hashsize", "65536", "maxelem", "1000000", "-exist").Run()
		_ = exec.Command("ipset", "create", "antiddos_subnets", "hash:net", "hashsize", "4096", "maxelem", "1000000", "-exist").Run()

		// Hook into PREROUTING mangle table for early packet dropping before socket allocation
		hookBlacklist := "iptables -t mangle -C PREROUTING -m set --match-set antiddos_blacklist src -j DROP 2>/dev/null || iptables -t mangle -I PREROUTING 1 -m set --match-set antiddos_blacklist src -j DROP"
		hookSubnets := "iptables -t mangle -C PREROUTING -m set --match-set antiddos_subnets src -j DROP 2>/dev/null || iptables -t mangle -I PREROUTING 1 -m set --match-set antiddos_subnets src -j DROP"

		_ = exec.Command("bash", "-c", hookBlacklist).Run()
		_ = exec.Command("bash", "-c", hookSubnets).Run()
	}
}

func (b *Blocker) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		b.mu.Lock()
		now := time.Now()
		for target, added := range b.blockedRules {
			if now.Sub(added) >= 24*time.Hour {
				b.mu.Unlock()
				_ = b.UnblockIP(target)
				b.mu.Lock()
			}
		}
		b.mu.Unlock()
	}
}

func sanitizeName(target string) string {
	r := strings.ReplaceAll(target, ".", "_")
	r = strings.ReplaceAll(r, "/", "_")
	r = strings.ReplaceAll(r, ":", "_")
	return r
}
