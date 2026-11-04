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
		if b.useIPSet {
			_ = exec.Command("ipset", "flush", "antiddos_blacklist").Run()
			_ = exec.Command("ipset", "flush", "antiddos_subnets").Run()
		} else {
			_ = exec.Command("bash", "-c", "iptables -t mangle -S PREROUTING | grep 'AntiDDoS' | sed 's/-A/-D/' | while read line; do iptables -t mangle $line; done").Run()
		}
	}
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
