package acl

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// AccessControl handles IP and CIDR whitelisting and blacklisting.
type AccessControl struct {
	mu            sync.RWMutex
	whitelistIPs  map[string]struct{}
	whitelistNets []*net.IPNet
	blacklistIPs  map[string]string // IP -> Reason
	blacklistNets []netWithReason   // CIDR -> Reason

	whitelistPath string
	blacklistPath string

	lastWhitelistMod time.Time
	lastBlacklistMod time.Time
}

type netWithReason struct {
	network *net.IPNet
	reason  string
}

// New creates an AccessControl instance.
func New(whitelistPath, blacklistPath string) *AccessControl {
	ac := &AccessControl{
		whitelistIPs:  make(map[string]struct{}),
		whitelistNets: make([]*net.IPNet, 0),
		blacklistIPs:  make(map[string]string),
		blacklistNets: make([]netWithReason, 0),
		whitelistPath: whitelistPath,
		blacklistPath: blacklistPath,
	}

	_ = ac.ReloadWhitelist()
	_ = ac.ReloadBlacklist()
	return ac
}

// ReloadWhitelist reads whitelist file and rebuilds in-memory index.
func (ac *AccessControl) ReloadWhitelist() error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	info, err := os.Stat(ac.whitelistPath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = ac.createDefaultWhitelist()
		}
		return err
	}

	ac.lastWhitelistMod = info.ModTime()

	file, err := os.Open(ac.whitelistPath)
	if err != nil {
		return err
	}
	defer file.Close()

	newIPs := make(map[string]struct{})
	newNets := make([]*net.IPNet, 0)

	// Always whitelist localhost
	newIPs["127.0.0.1"] = struct{}{}
	newIPs["::1"] = struct{}{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err == nil {
				newNets = append(newNets, ipNet)
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				newIPs[ip.String()] = struct{}{}
			}
		}
	}

	ac.whitelistIPs = newIPs
	ac.whitelistNets = newNets
	return nil
}

// ReloadBlacklist reads blacklist file and rebuilds in-memory index.
func (ac *AccessControl) ReloadBlacklist() error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	info, err := os.Stat(ac.blacklistPath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = ac.createDefaultBlacklist()
		}
		return err
	}

	ac.lastBlacklistMod = info.ModTime()

	file, err := os.Open(ac.blacklistPath)
	if err != nil {
		return err
	}
	defer file.Close()

	newIPs := make(map[string]string)
	newNets := make([]netWithReason, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		reason := "Blacklisted from file"
		if idx := strings.Index(line, "#"); idx != -1 {
			reason = strings.TrimSpace(line[idx+1:])
			line = strings.TrimSpace(line[:idx])
		}

		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err == nil {
				newNets = append(newNets, netWithReason{network: ipNet, reason: reason})
			}
		} else {
			ip := net.ParseIP(line)
			if ip != nil {
				newIPs[ip.String()] = reason
			}
		}
	}

	ac.blacklistIPs = newIPs
	ac.blacklistNets = newNets
	return nil
}

// ReloadWhitelistIfModified checks if whitelist file changed on disk and reloads.
// Returns (changed, totalEntries, error).
func (ac *AccessControl) ReloadWhitelistIfModified() (bool, int, error) {
	info, err := os.Stat(ac.whitelistPath)
	if err != nil {
		return false, 0, err
	}

	ac.mu.RLock()
	lastMod := ac.lastWhitelistMod
	ac.mu.RUnlock()

	if !info.ModTime().After(lastMod) {
		wlCount, _ := ac.Counts()
		return false, wlCount, nil
	}

	if err := ac.ReloadWhitelist(); err != nil {
		return false, 0, err
	}

	wlCount, _ := ac.Counts()
	return true, wlCount, nil
}

// ReloadBlacklistIfModified checks if blacklist file changed on disk and reloads.
// Returns (changed, totalEntries, error).
func (ac *AccessControl) ReloadBlacklistIfModified() (bool, int, error) {
	info, err := os.Stat(ac.blacklistPath)
	if err != nil {
		return false, 0, err
	}

	ac.mu.RLock()
	lastMod := ac.lastBlacklistMod
	ac.mu.RUnlock()

	if !info.ModTime().After(lastMod) {
		_, blCount := ac.Counts()
		return false, blCount, nil
	}

	if err := ac.ReloadBlacklist(); err != nil {
		return false, 0, err
	}

	_, blCount := ac.Counts()
	return true, blCount, nil
}

// IsWhitelisted checks if the IP is in the whitelist or a whitelisted subnet.
func (ac *AccessControl) IsWhitelisted(ip net.IP) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	if _, ok := ac.whitelistIPs[ip.String()]; ok {
		return true
	}

	for _, ipNet := range ac.whitelistNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// IsBlacklisted checks if the IP is blacklisted and returns reason.
func (ac *AccessControl) IsBlacklisted(ip net.IP) (bool, string) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	// Whitelist always overrides blacklist
	if _, ok := ac.whitelistIPs[ip.String()]; ok {
		return false, ""
	}
	for _, ipNet := range ac.whitelistNets {
		if ipNet.Contains(ip) {
			return false, ""
		}
	}

	if reason, ok := ac.blacklistIPs[ip.String()]; ok {
		return true, reason
	}

	for _, entry := range ac.blacklistNets {
		if entry.network.Contains(ip) {
			return true, entry.reason
		}
	}

	return false, ""
}

// AddBlacklist permanently adds an IP or CIDR to the in-memory blacklist and persists to blacklist.txt.
// Thread-safe and deduplicated.
func (ac *AccessControl) AddBlacklist(target, reason string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	target = strings.TrimSpace(target)

	// If CIDR
	if strings.Contains(target, "/") {
		_, ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return err
		}
		// Deduplication check
		for _, existing := range ac.blacklistNets {
			if existing.network.String() == ipNet.String() {
				return nil // already blacklisted
			}
		}
		ac.blacklistNets = append(ac.blacklistNets, netWithReason{network: ipNet, reason: reason})
	} else {
		ip := net.ParseIP(target)
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", target)
		}
		// Deduplication check
		if _, exists := ac.blacklistIPs[ip.String()]; exists {
			return nil // already blacklisted
		}
		ac.blacklistIPs[ip.String()] = reason
	}

	// Append to file immediately
	f, err := os.OpenFile(ac.blacklistPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	entry := fmt.Sprintf("%s # %s [%s]\n", target, reason, time.Now().Format("2006-01-02 15:04:05"))
	_, err = f.WriteString(entry)
	if err == nil {
		// Update our recorded mod time so we don't trigger unnecessary re-read
		if fi, statErr := f.Stat(); statErr == nil {
			ac.lastBlacklistMod = fi.ModTime()
		}
	}
	return err
}

// Counts returns number of entries in whitelist and blacklist.
func (ac *AccessControl) Counts() (whitelistCount, blacklistCount int) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return len(ac.whitelistIPs) + len(ac.whitelistNets), len(ac.blacklistIPs) + len(ac.blacklistNets)
}

// WhitelistEntries returns all currently whitelisted IPs and CIDRs.
func (ac *AccessControl) WhitelistEntries() []string {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entries := make([]string, 0, len(ac.whitelistIPs)+len(ac.whitelistNets))
	for ip := range ac.whitelistIPs {
		entries = append(entries, ip)
	}
	for _, n := range ac.whitelistNets {
		entries = append(entries, n.String())
	}
	return entries
}

// BlacklistEntry represents an IP or CIDR on the blacklist with its reason.
type BlacklistEntry struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// BlacklistEntries returns all currently blacklisted IPs and CIDRs with reasons.
func (ac *AccessControl) BlacklistEntries() []BlacklistEntry {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entries := make([]BlacklistEntry, 0, len(ac.blacklistIPs)+len(ac.blacklistNets))
	for ip, reason := range ac.blacklistIPs {
		entries = append(entries, BlacklistEntry{Target: ip, Reason: reason})
	}
	for _, n := range ac.blacklistNets {
		entries = append(entries, BlacklistEntry{Target: n.network.String(), Reason: n.reason})
	}
	return entries
}

// AddWhitelist adds an IP or CIDR to the whitelist and persists it to whitelist.txt.
func (ac *AccessControl) AddWhitelist(target string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	target = strings.TrimSpace(target)
	if strings.Contains(target, "/") {
		_, ipNet, err := net.ParseCIDR(target)
		if err != nil {
			return err
		}
		for _, existing := range ac.whitelistNets {
			if existing.String() == ipNet.String() {
				return nil
			}
		}
		ac.whitelistNets = append(ac.whitelistNets, ipNet)
	} else {
		ip := net.ParseIP(target)
		if ip == nil {
			return fmt.Errorf("invalid IP: %s", target)
		}
		if _, exists := ac.whitelistIPs[ip.String()]; exists {
			return nil
		}
		ac.whitelistIPs[ip.String()] = struct{}{}
	}

	return ac.saveWhitelistLocked()
}

// RemoveWhitelist removes an IP or CIDR from the whitelist and updates whitelist.txt.
func (ac *AccessControl) RemoveWhitelist(target string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	target = strings.TrimSpace(target)
	if target == "127.0.0.1" || target == "::1" {
		return fmt.Errorf("cannot remove localhost from whitelist")
	}

	delete(ac.whitelistIPs, target)
	filtered := make([]*net.IPNet, 0, len(ac.whitelistNets))
	for _, n := range ac.whitelistNets {
		if n.String() != target {
			filtered = append(filtered, n)
		}
	}
	ac.whitelistNets = filtered
	return ac.saveWhitelistLocked()
}

// RemoveBlacklist removes an IP or CIDR from the blacklist and updates blacklist.txt.
func (ac *AccessControl) RemoveBlacklist(target string) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	target = strings.TrimSpace(target)
	delete(ac.blacklistIPs, target)
	filtered := make([]netWithReason, 0, len(ac.blacklistNets))
	for _, n := range ac.blacklistNets {
		if n.network.String() != target {
			filtered = append(filtered, n)
		}
	}
	ac.blacklistNets = filtered
	return ac.saveBlacklistLocked()
}

func (ac *AccessControl) saveWhitelistLocked() error {
	var sb strings.Builder
	sb.WriteString("# Anti-DDoS Firewall - Whitelist\n")
	for ip := range ac.whitelistIPs {
		sb.WriteString(ip + "\n")
	}
	for _, n := range ac.whitelistNets {
		sb.WriteString(n.String() + "\n")
	}
	err := os.WriteFile(ac.whitelistPath, []byte(sb.String()), 0644)
	if err == nil {
		if fi, statErr := os.Stat(ac.whitelistPath); statErr == nil {
			ac.lastWhitelistMod = fi.ModTime()
		}
	}
	return err
}

func (ac *AccessControl) saveBlacklistLocked() error {
	var sb strings.Builder
	sb.WriteString("# Anti-DDoS Firewall - Blacklist\n")
	for ip, reason := range ac.blacklistIPs {
		sb.WriteString(fmt.Sprintf("%s # %s\n", ip, reason))
	}
	for _, n := range ac.blacklistNets {
		sb.WriteString(fmt.Sprintf("%s # %s\n", n.network.String(), n.reason))
	}
	err := os.WriteFile(ac.blacklistPath, []byte(sb.String()), 0644)
	if err == nil {
		if fi, statErr := os.Stat(ac.blacklistPath); statErr == nil {
			ac.lastBlacklistMod = fi.ModTime()
		}
	}
	return err
}

func (ac *AccessControl) createDefaultWhitelist() error {
	content := `# Anti-DDoS Firewall - Whitelist
# IPs and subnets in this file bypass all rate limits and signatures.
# Examples:
#   127.0.0.1
#   192.168.1.100
#   10.0.0.0/8
127.0.0.1
`
	return os.WriteFile(ac.whitelistPath, []byte(content), 0644)
}

func (ac *AccessControl) createDefaultBlacklist() error {
	content := `# Anti-DDoS Firewall - Blacklist
# Blocked IPs and CIDR ranges
# Automatically updated when attackers are blocked.
# Examples:
#   1.2.3.4 # Malicious scanner
#   10.50.0.0/16 # Abusive botnet
`
	return os.WriteFile(ac.blacklistPath, []byte(content), 0644)
}
