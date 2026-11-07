package geoip

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ipRange struct {
	start   uint32
	end     uint32
	country string
}

// Filter manages high-speed O(log N) GeoIP country filtering for Inbound and Outbound traffic.
type Filter struct {
	mu               sync.RWMutex
	enabled          bool
	direction        string // "both", "in", "out"
	allowedCountries []string
	blockedCountries []string
	allowedSet       map[string]bool
	blockedSet       map[string]bool
	ranges           []ipRange
	countryCIDRs     map[string][]string
	dataDir          string
	lastConfigSig    string
}

// New creates a new GeoIP Filter instance.
func New() *Filter {
	return &Filter{
		direction:    "both",
		allowedSet:   make(map[string]bool),
		blockedSet:   make(map[string]bool),
		countryCIDRs: make(map[string][]string),
		dataDir:      "geoip",
	}
}

// SyncConfig updates the GeoIP engine if configuration parameters changed.
// Returns (changed, totalCIDRsLoaded).
func (f *Filter) SyncConfig(enabled bool, direction string, allowedCountries, blockedCountries []string, dataDir string) (bool, int) {
	dirNorm := normalizeDirection(direction)
	allowNorm := normalizeCountryList(allowedCountries)
	blockNorm := normalizeCountryList(blockedCountries)
	if dataDir == "" {
		dataDir = "geoip"
	}

	sig := fmt.Sprintf("%v|%s|%s|%s|%s",
		enabled,
		dirNorm,
		strings.Join(allowNorm, ","),
		strings.Join(blockNorm, ","),
		dataDir,
	)

	f.mu.RLock()
	if f.lastConfigSig == sig {
		count := len(f.ranges)
		f.mu.RUnlock()
		return false, count
	}
	f.mu.RUnlock()

	if !enabled {
		f.mu.Lock()
		f.enabled = false
		f.direction = dirNorm
		f.allowedCountries = allowNorm
		f.blockedCountries = blockNorm
		f.allowedSet = make(map[string]bool)
		f.blockedSet = make(map[string]bool)
		f.lastConfigSig = sig
		f.mu.Unlock()
		return true, 0
	}

	// Collect all unique countries we need to load into the interval tree
	countriesToLoad := make(map[string]bool)
	countriesToLoad["VN"] = true // Always load VN embedded database for accurate logging
	for _, cc := range allowNorm {
		countriesToLoad[cc] = true
	}
	for _, cc := range blockNorm {
		countriesToLoad[cc] = true
	}

	newCountryCIDRs := make(map[string][]string)
	var rawRanges []ipRange

	for cc := range countriesToLoad {
		cidrs, err := loadOrFetchCountryCIDRs(cc, dataDir)
		if err != nil {
			fmt.Printf("[GEOIP] Warning: could not load CIDRs for country %s: %v\n", cc, err)
			continue
		}
		newCountryCIDRs[cc] = cidrs
		for _, cidr := range cidrs {
			start, end, ok := cidrToUint32Range(cidr)
			if ok {
				rawRanges = append(rawRanges, ipRange{
					start:   start,
					end:     end,
					country: cc,
				})
			}
		}
	}

	sortedRanges := buildDisjointRanges(rawRanges)

	allowMap := make(map[string]bool, len(allowNorm))
	for _, cc := range allowNorm {
		allowMap[cc] = true
	}
	blockMap := make(map[string]bool, len(blockNorm))
	for _, cc := range blockNorm {
		blockMap[cc] = true
	}

	f.mu.Lock()
	f.enabled = enabled
	f.direction = dirNorm
	f.allowedCountries = allowNorm
	f.blockedCountries = blockNorm
	f.allowedSet = allowMap
	f.blockedSet = blockMap
	f.ranges = sortedRanges
	f.countryCIDRs = newCountryCIDRs
	f.dataDir = dataDir
	f.lastConfigSig = sig
	f.mu.Unlock()

	return true, len(sortedRanges)
}

// CheckInbound verifies whether an incoming client IP is permitted by GeoIP rules.
func (f *Filter) CheckInbound(ip net.IP) (allowed bool, country string, reason string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled || f.direction == "out" {
		return true, "", ""
	}

	if IsPrivateOrLoopback(ip) {
		return true, "LOCAL", ""
	}

	country = f.lookupLocked(ip)

	if f.blockedSet[country] {
		return false, country, fmt.Sprintf("Inbound blocked from restricted country [%s]", country)
	}

	if len(f.allowedSet) > 0 && !f.allowedSet[country] {
		return false, country, fmt.Sprintf("Inbound international IP blocked (Origin: %s, Allowed: %s)",
			country, strings.Join(f.allowedCountries, ","))
	}

	return true, country, ""
}

// CheckOutbound verifies whether an outgoing connection to destIP is permitted by GeoIP rules.
func (f *Filter) CheckOutbound(ip net.IP) (allowed bool, country string, reason string) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled || f.direction == "in" {
		return true, "", ""
	}

	if IsPrivateOrLoopback(ip) {
		return true, "LOCAL", ""
	}

	country = f.lookupLocked(ip)

	if f.blockedSet[country] {
		return false, country, fmt.Sprintf("Outbound blocked to restricted country [%s]", country)
	}

	if len(f.allowedSet) > 0 && !f.allowedSet[country] {
		return false, country, fmt.Sprintf("Outbound international IP blocked (Dest: %s, Allowed: %s)",
			country, strings.Join(f.allowedCountries, ","))
	}

	return true, country, ""
}

// LookupCountry returns the detected ISO country code for an IP (or "LOCAL" / "INTL").
func (f *Filter) LookupCountry(ip net.IP) string {
	if IsPrivateOrLoopback(ip) {
		return "LOCAL"
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.lookupLocked(ip)
}

func (f *Filter) lookupLocked(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return "INTL"
	}
	val := binary.BigEndian.Uint32(ip4)

	// Binary search for the last range with start <= val
	idx := sort.Search(len(f.ranges), func(i int) bool {
		return f.ranges[i].start > val
	}) - 1

	if idx >= 0 && idx < len(f.ranges) {
		if val >= f.ranges[idx].start && val <= f.ranges[idx].end {
			return f.ranges[idx].country
		}
	}
	return "INTL"
}

// AllowedCIDRs returns the combined list of CIDR blocks for all allowed countries.
func (f *Filter) AllowedCIDRs() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	var result []string
	for _, cc := range f.allowedCountries {
		if cidrs, ok := f.countryCIDRs[cc]; ok {
			result = append(result, cidrs...)
		}
	}
	return result
}

// Summary returns a human-readable summary of the active GeoIP policy for the dashboard.
func (f *Filter) Summary() string {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled {
		return "DISABLED (All Countries Allowed)"
	}
	dirLabel := strings.ToUpper(f.direction)
	if len(f.allowedCountries) > 0 {
		return fmt.Sprintf("ENABLED [%s] Allow Only: %s (%d subnets)",
			dirLabel, strings.Join(f.allowedCountries, ","), len(f.ranges))
	}
	if len(f.blockedCountries) > 0 {
		return fmt.Sprintf("ENABLED [%s] Block: %s (%d subnets)",
			dirLabel, strings.Join(f.blockedCountries, ","), len(f.ranges))
	}
	return fmt.Sprintf("ENABLED [%s]", dirLabel)
}

// IsPrivateOrLoopback checks if an IP is loopback, RFC1918 LAN, link-local, or CGNAT.
func IsPrivateOrLoopback(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// Carrier-Grade NAT (100.64.0.0/10)
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
	}
	return false
}

func loadOrFetchCountryCIDRs(cc string, dataDir string) ([]string, error) {
	ccUpper := strings.ToUpper(strings.TrimSpace(cc))
	ccLower := strings.ToLower(ccUpper)

	if dataDir != "" {
		_ = os.MkdirAll(dataDir, 0755)
		localFile := filepath.Join(dataDir, ccLower+".zone")
		if cidrs, err := readCIDRFile(localFile); err == nil && len(cidrs) > 0 {
			return cidrs, nil
		}

		// If Vietnam (VN) is requested and not yet on disk, write embedded VN database to disk and return it
		if ccUpper == "VN" {
			cidrs := parseCIDRString(EmbeddedVNCIDRs)
			_ = os.WriteFile(localFile, []byte(strings.TrimSpace(EmbeddedVNCIDRs)+"\n"), 0644)
			return cidrs, nil
		}

		// Attempt to download from public CIDR registries
		urls := []string{
			fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", ccLower),
			fmt.Sprintf("https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/%s.cidr", ccLower),
		}

		client := &http.Client{Timeout: 8 * time.Second}
		for _, url := range urls {
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && readErr == nil {
				cidrs := parseCIDRString(string(body))
				if len(cidrs) > 0 {
					_ = os.WriteFile(localFile, body, 0644)
					fmt.Printf("[GEOIP] Downloaded %d CIDR blocks for country [%s] -> %s\n", len(cidrs), ccUpper, localFile)
					return cidrs, nil
				}
			}
		}
	}

	if ccUpper == "VN" {
		return parseCIDRString(EmbeddedVNCIDRs), nil
	}

	return nil, fmt.Errorf("no CIDR data available for country %s", ccUpper)
}

func readCIDRFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var result []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			result = append(result, line)
		}
	}
	return result, scanner.Err()
}

func parseCIDRString(content string) []string {
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			result = append(result, line)
		}
	}
	return result
}

func cidrToUint32Range(cidr string) (uint32, uint32, bool) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, false
	}
	ip4 := ip.To4()
	if ip4 == nil || len(ipNet.Mask) != 4 {
		return 0, 0, false
	}
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return 0, 0, false
	}
	start := binary.BigEndian.Uint32(networkIP)
	mask := binary.BigEndian.Uint32(ipNet.Mask)
	end := start | (^mask)
	return start, end, true
}

func buildDisjointRanges(raw []ipRange) []ipRange {
	if len(raw) == 0 {
		return nil
	}
	// Sort by start ASC, then end DESC
	sort.Slice(raw, func(i, j int) bool {
		if raw[i].start == raw[j].start {
			return raw[i].end > raw[j].end
		}
		return raw[i].start < raw[j].start
	})

	merged := make([]ipRange, 0, len(raw))
	for _, r := range raw {
		if len(merged) == 0 {
			merged = append(merged, r)
			continue
		}
		last := &merged[len(merged)-1]
		if r.start <= last.end {
			// Overlapping range
			if r.country == last.country {
				if r.end > last.end {
					last.end = r.end
				}
			} else if r.end > last.end {
				// Disjoint tail for different country
				merged = append(merged, ipRange{
					start:   last.end + 1,
					end:     r.end,
					country: r.country,
				})
			}
		} else if r.start == last.end+1 && r.country == last.country {
			// Adjacent range of same country
			last.end = r.end
		} else {
			merged = append(merged, r)
		}
	}
	return merged
}

func normalizeDirection(dir string) string {
	switch strings.ToLower(strings.TrimSpace(dir)) {
	case "in", "inbound", "ingress":
		return "in"
	case "out", "outbound", "egress":
		return "out"
	default:
		return "both"
	}
}

func normalizeCountryList(list []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range list {
		for _, part := range strings.Split(item, ",") {
			cc := strings.ToUpper(strings.TrimSpace(part))
			if len(cc) == 2 && !seen[cc] {
				seen[cc] = true
				out = append(out, cc)
			}
		}
	}
	return out
}
