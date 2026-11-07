package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config represents all configuration options for the Anti-DDoS Firewall.
type Config struct {
	// Network binding
	FirewallHost string
	FirewallPort int
	BackendHost  string
	BackendPort  int

	// Web Control Plane & Observability Dashboard
	WebEnabled      bool
	WebHost         string
	WebPort         int
	WebPublicDomain string
	WebAdminPass    string

	// PROXY Protocol (Real Client IP forwarding: "off", "v1", "v2")
	ProxyProtocol string

	// Defense Layer ON/OFF Toggles (Real-time switchable from Web UI & config.txt)
	LayerSignatureEnabled bool
	LayerHalfOpenEnabled  bool
	LayerSlowlorisEnabled bool
	LayerSubnetEnabled    bool
	LayerSurgeEnabled     bool
	LockdownWhitelistOnly bool

	// Connection limits per IP (Whitelisted)
	MaxConnPerIP int
	MaxConnRate  int

	// Connection limits per IP (External / Non-whitelisted)
	MaxConnPerExternalIP  int
	MaxConnRateExternal   int
	MaxMsgsPerSecExternal int

	// Global limits
	MaxGlobalConnRate int
	MaxGlobalActive   int
	MaxBytesPerSec    int64
	MaxMsgsPerSec     int

	// Blocking & Penalties
	PenaltyThreshold      int
	AutoBlacklistOffenses int
	BlockDuration1        time.Duration
	BlockDuration2        time.Duration
	BlockDuration3        time.Duration
	BlockDuration4        time.Duration

	// SYN / Half-open flood defense
	MaxHalfOpenPerIP   int
	MaxGlobalHalfOpen  int
	HalfOpenTimeoutSec time.Duration

	// Slowloris defense
	SlowlorisTimeoutSec time.Duration
	SlowlorisMinBytes   int64

	// Distributed & Subnet detection
	SubnetBlockThreshold24 int
	SubnetBlockThreshold16 int
	ClusterDetectMinIPs    int
	ClusterDetectWindowSec time.Duration

	// Surge protection
	SurgeMultiplier     float64
	SurgeCooldownSec    time.Duration
	MaxAcceptRateAttack int

	// Kernel blocking
	KernelBlockEnabled     bool
	KernelBlockMinLevel    int
	KernelRuleCleanupHours int

	// GeoIP & International Traffic Control
	GeoIPEnabled          bool
	GeoIPDirection        string   // "both", "in", "out"
	GeoIPAllowedCountries []string // e.g., ["VN"] or ["VN", "SG", "JP"]
	GeoIPBlockedCountries []string // e.g., ["CN", "RU"]
	GeoIPKernelEnforce    bool     // Enforce GeoIP at OS kernel level (Linux ipset/iptables)
	GeoIPDataDir          string   // Directory for country CIDR zone files

	// Reload & Stats
	WhitelistReloadSec time.Duration
	StatsIntervalSec   time.Duration

	// File paths
	ConfigFile    string
	WhitelistFile string
	BlacklistFile string
}

// DefaultConfig returns reasonable defaults matching v3.8 specs.
func DefaultConfig() *Config {
	return &Config{
		FirewallHost:           "0.0.0.0",
		FirewallPort:           9999,
		BackendHost:            "127.0.0.1",
		BackendPort:            14445,
		WebEnabled:             true,
		WebHost:                "0.0.0.0",
		WebPort:                8080,
		WebPublicDomain:        "",
		WebAdminPass:           "admin",
		ProxyProtocol:          "off",
		LayerSignatureEnabled:  true,
		LayerHalfOpenEnabled:   true,
		LayerSlowlorisEnabled:  true,
		LayerSubnetEnabled:     true,
		LayerSurgeEnabled:      true,
		LockdownWhitelistOnly:  false,
		MaxConnPerIP:           200,
		MaxConnRate:            100,
		MaxConnPerExternalIP:   5,
		MaxConnRateExternal:    3,
		MaxMsgsPerSecExternal:  50,
		MaxGlobalConnRate:      500,
		MaxGlobalActive:        2000,
		MaxBytesPerSec:         10 * 1024 * 1024, // 10 MB/s
		MaxMsgsPerSec:          500,
		PenaltyThreshold:       150,
		AutoBlacklistOffenses:  3,
		BlockDuration1:         30 * time.Second,
		BlockDuration2:         120 * time.Second,
		BlockDuration3:         600 * time.Second,
		BlockDuration4:         86400 * time.Second,
		MaxHalfOpenPerIP:       10,
		MaxGlobalHalfOpen:      200,
		HalfOpenTimeoutSec:     3 * time.Second,
		SlowlorisTimeoutSec:    8 * time.Second,
		SlowlorisMinBytes:      100,
		SubnetBlockThreshold24: 3,
		SubnetBlockThreshold16: 2,
		ClusterDetectMinIPs:    10,
		ClusterDetectWindowSec: 5 * time.Second,
		SurgeMultiplier:        3.0,
		SurgeCooldownSec:       30 * time.Second,
		MaxAcceptRateAttack:    50,
		KernelBlockEnabled:     true,
		KernelBlockMinLevel:    3,
		KernelRuleCleanupHours: 24,
		GeoIPEnabled:           false,
		GeoIPDirection:         "both",
		GeoIPAllowedCountries:  []string{"VN"},
		GeoIPBlockedCountries:  nil,
		GeoIPKernelEnforce:     false,
		GeoIPDataDir:           "geoip",
		WhitelistReloadSec:     60 * time.Second,
		StatsIntervalSec:       5 * time.Second,
		ConfigFile:             "config.txt",
		WhitelistFile:          "whitelist.txt",
		BlacklistFile:          "blacklist.txt",
	}
}

// Manager manages dynamic config loading with thread-safe atomic access.
type Manager struct {
	mu      sync.RWMutex
	cfg     *Config
	path    string
	lastMod time.Time
}

// NewManager creates a new config manager.
func NewManager(path string) (*Manager, error) {
	m := &Manager{
		cfg:  DefaultConfig(),
		path: path,
	}
	m.cfg.ConfigFile = path
	if err := m.Load(); err != nil {
		// If file doesn't exist, create default config file
		if os.IsNotExist(err) {
			_ = m.SaveDefault(path)
		} else {
			return nil, err
		}
	}
	return m, nil
}

// Get returns the current active configuration snapshot.
func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfgCopy := *m.cfg
	if m.cfg.GeoIPAllowedCountries != nil {
		cfgCopy.GeoIPAllowedCountries = append([]string(nil), m.cfg.GeoIPAllowedCountries...)
	}
	if m.cfg.GeoIPBlockedCountries != nil {
		cfgCopy.GeoIPBlockedCountries = append([]string(nil), m.cfg.GeoIPBlockedCountries...)
	}
	return &cfgCopy
}

// Update applies a mutation function to the active configuration safely.
func (m *Manager) Update(fn func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn(m.cfg)
}

func parseBool(val string) bool {
	v := strings.ToLower(strings.TrimSpace(val))
	return v == "true" || v == "1" || v == "yes" || v == "on"
}

// Load reads and parses the config file.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, err := os.Stat(m.path)
	if err != nil {
		return err
	}
	m.lastMod = info.ModTime()

	file, err := os.Open(m.path)
	if err != nil {
		return err
	}
	defer file.Close()

	newCfg := *m.cfg
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "firewall_host":
			newCfg.FirewallHost = val
		case "firewall_port":
			if p, err := strconv.Atoi(val); err == nil && p > 0 {
				newCfg.FirewallPort = p
			}
		case "backend_host":
			newCfg.BackendHost = val
		case "backend_port":
			if p, err := strconv.Atoi(val); err == nil && p > 0 {
				newCfg.BackendPort = p
			}
		case "web_enabled":
			newCfg.WebEnabled = parseBool(val)
		case "web_host":
			if val != "" {
				newCfg.WebHost = val
			}
		case "web_port":
			if p, err := strconv.Atoi(val); err == nil && p > 0 {
				newCfg.WebPort = p
			}
		case "web_public_domain":
			newCfg.WebPublicDomain = val
		case "web_admin_pass":
			if val != "" {
				newCfg.WebAdminPass = val
			}
		case "proxy_protocol":
			valLower := strings.ToLower(val)
			if valLower == "v1" || valLower == "1" {
				newCfg.ProxyProtocol = "v1"
			} else if valLower == "v2" || valLower == "2" {
				newCfg.ProxyProtocol = "v2"
			} else {
				newCfg.ProxyProtocol = "off"
			}
		case "layer_signature_enabled":
			newCfg.LayerSignatureEnabled = parseBool(val)
		case "layer_halfopen_enabled":
			newCfg.LayerHalfOpenEnabled = parseBool(val)
		case "layer_slowloris_enabled":
			newCfg.LayerSlowlorisEnabled = parseBool(val)
		case "layer_subnet_enabled":
			newCfg.LayerSubnetEnabled = parseBool(val)
		case "layer_surge_enabled":
			newCfg.LayerSurgeEnabled = parseBool(val)
		case "lockdown_whitelist_only":
			newCfg.LockdownWhitelistOnly = parseBool(val)
		case "max_conn_per_ip":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxConnPerIP = n
			}
		case "max_conn_rate":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxConnRate = n
			}
		case "max_conn_per_external_ip":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxConnPerExternalIP = n
			}
		case "max_conn_rate_external":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxConnRateExternal = n
			}
		case "max_msgs_per_sec_external":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxMsgsPerSecExternal = n
			}
		case "max_global_conn_rate":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxGlobalConnRate = n
			}
		case "max_global_active":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxGlobalActive = n
			}
		case "max_bytes_per_sec":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				newCfg.MaxBytesPerSec = n
			}
		case "max_msgs_per_sec":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxMsgsPerSec = n
			}
		case "penalty_threshold":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.PenaltyThreshold = n
			}
		case "auto_blacklist_offenses":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.AutoBlacklistOffenses = n
			}
		case "block_duration_1":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.BlockDuration1 = time.Duration(s) * time.Second
			}
		case "block_duration_2":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.BlockDuration2 = time.Duration(s) * time.Second
			}
		case "block_duration_3":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.BlockDuration3 = time.Duration(s) * time.Second
			}
		case "block_duration_4":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.BlockDuration4 = time.Duration(s) * time.Second
			}
		case "max_halfopen_per_ip":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxHalfOpenPerIP = n
			}
		case "max_global_halfopen":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxGlobalHalfOpen = n
			}
		case "halfopen_timeout_sec":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.HalfOpenTimeoutSec = time.Duration(s) * time.Second
			}
		case "slowloris_timeout_sec":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.SlowlorisTimeoutSec = time.Duration(s) * time.Second
			}
		case "slowloris_min_bytes":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				newCfg.SlowlorisMinBytes = n
			}
		case "subnet_block_threshold_24":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.SubnetBlockThreshold24 = n
			}
		case "subnet_block_threshold_16":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.SubnetBlockThreshold16 = n
			}
		case "cluster_detect_min_ips":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.ClusterDetectMinIPs = n
			}
		case "cluster_detect_window_sec":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.ClusterDetectWindowSec = time.Duration(s) * time.Second
			}
		case "surge_multiplier":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				newCfg.SurgeMultiplier = f
			}
		case "surge_cooldown_sec":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.SurgeCooldownSec = time.Duration(s) * time.Second
			}
		case "max_accept_rate_attack":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.MaxAcceptRateAttack = n
			}
		case "kernel_block_enabled":
			newCfg.KernelBlockEnabled = parseBool(val)
		case "kernel_block_min_level":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.KernelBlockMinLevel = n
			}
		case "kernel_rule_cleanup_hours":
			if n, err := strconv.Atoi(val); err == nil {
				newCfg.KernelRuleCleanupHours = n
			}
		case "whitelist_reload_sec":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.WhitelistReloadSec = time.Duration(s) * time.Second
			}
		case "stats_interval_sec":
			if s, err := strconv.Atoi(val); err == nil {
				newCfg.StatsIntervalSec = time.Duration(s) * time.Second
			}
		case "whitelist_file":
			newCfg.WhitelistFile = val
		case "blacklist_file":
			newCfg.BlacklistFile = val
		case "geoip_enabled":
			newCfg.GeoIPEnabled = parseBool(val)
		case "geoip_direction":
			newCfg.GeoIPDirection = strings.ToLower(val)
		case "geoip_allowed_countries", "allowed_countries":
			if val == "" || strings.EqualFold(val, "all") || strings.EqualFold(val, "off") {
				newCfg.GeoIPAllowedCountries = nil
			} else {
				parts := strings.Split(val, ",")
				var list []string
				for _, p := range parts {
					cc := strings.ToUpper(strings.TrimSpace(p))
					if cc != "" {
						list = append(list, cc)
					}
				}
				newCfg.GeoIPAllowedCountries = list
			}
		case "geoip_blocked_countries", "blocked_countries":
			if val == "" || strings.EqualFold(val, "none") || strings.EqualFold(val, "off") {
				newCfg.GeoIPBlockedCountries = nil
			} else {
				parts := strings.Split(val, ",")
				var list []string
				for _, p := range parts {
					cc := strings.ToUpper(strings.TrimSpace(p))
					if cc != "" {
						list = append(list, cc)
					}
				}
				newCfg.GeoIPBlockedCountries = list
			}
		case "geoip_kernel_enforce":
			newCfg.GeoIPKernelEnforce = parseBool(val)
		case "geoip_data_dir":
			if val != "" {
				newCfg.GeoIPDataDir = val
			}
		}
	}

	m.cfg = &newCfg
	return scanner.Err()
}

// Save writes the current active configuration to disk.
func (m *Manager) Save() error {
	m.mu.RLock()
	cfg := *m.cfg
	path := m.path
	m.mu.RUnlock()

	allowed := strings.Join(cfg.GeoIPAllowedCountries, ",")
	blocked := strings.Join(cfg.GeoIPBlockedCountries, ",")

	content := fmt.Sprintf(`# Anti-DDoS High-Performance Firewall v3.8
# Cross-Platform TCP Reverse Proxy & Cyber Control Plane (Linux / Windows)

# ============================================================
# NETWORK & BINDING CONFIGURATION (Primary Endpoint)
# ============================================================
firewall_host=%s
firewall_port=%d
backend_host=%s
backend_port=%d

# ============================================================
# WEB CONTROL PLANE & OBSERVABILITY DASHBOARD
# ============================================================
web_enabled=%v
web_host=%s
web_port=%d
web_public_domain=%s
web_admin_pass=%s

# ============================================================
# PROXY PROTOCOL (Day IP that cua Client ve Backend Server)
# ============================================================
# off: Tat (mac dinh) | v1: Text header | v2: Binary header
proxy_protocol=%s

# ============================================================
# DEFENSE LAYER SWITCHES (ON / OFF Real-time Toggles)
# ============================================================
layer_signature_enabled=%v
layer_halfopen_enabled=%v
layer_slowloris_enabled=%v
layer_subnet_enabled=%v
layer_surge_enabled=%v
lockdown_whitelist_only=%v

# ============================================================
# CONNECTION LIMITS (Per IP)
# ============================================================
max_conn_per_ip=%d
max_conn_rate=%d
max_conn_per_external_ip=%d
max_conn_rate_external=%d
max_msgs_per_sec_external=%d

# ============================================================
# GLOBAL LIMITS
# ============================================================
max_global_conn_rate=%d
max_global_active=%d
max_bytes_per_sec=%d
max_msgs_per_sec=%d

# ============================================================
# BLOCKING & PENALTIES
# ============================================================
penalty_threshold=%d
auto_blacklist_offenses=%d
block_duration_1=%d
block_duration_2=%d
block_duration_3=%d
block_duration_4=%d

# ============================================================
# ATTACK DETECTION
# ============================================================
max_halfopen_per_ip=%d
max_global_halfopen=%d
halfopen_timeout_sec=%d
slowloris_timeout_sec=%d
slowloris_min_bytes=%d
subnet_block_threshold_24=%d
subnet_block_threshold_16=%d
cluster_detect_min_ips=%d
cluster_detect_window_sec=%d
surge_multiplier=%.1f
surge_cooldown_sec=%d
max_accept_rate_attack=%d

# ============================================================
# GEOIP & INTERNATIONAL FILTERING (Chan Quoc Te / Loc Quoc Gia)
# ============================================================
geoip_enabled=%v
geoip_allowed_countries=%s
geoip_blocked_countries=%s
geoip_direction=%s
geoip_kernel_enforce=%v
geoip_data_dir=%s

# ============================================================
# KERNEL-LEVEL BLOCKING (Windows netsh / Linux iptables)
# ============================================================
kernel_block_enabled=%v
kernel_block_min_level=%d
kernel_rule_cleanup_hours=%d

# ============================================================
# RELOAD & STATS INTERVALS
# ============================================================
whitelist_reload_sec=%d
stats_interval_sec=%d
`,
		cfg.FirewallHost,
		cfg.FirewallPort,
		cfg.BackendHost,
		cfg.BackendPort,
		cfg.WebEnabled,
		cfg.WebHost,
		cfg.WebPort,
		cfg.WebPublicDomain,
		cfg.WebAdminPass,
		cfg.ProxyProtocol,
		cfg.LayerSignatureEnabled,
		cfg.LayerHalfOpenEnabled,
		cfg.LayerSlowlorisEnabled,
		cfg.LayerSubnetEnabled,
		cfg.LayerSurgeEnabled,
		cfg.LockdownWhitelistOnly,
		cfg.MaxConnPerIP,
		cfg.MaxConnRate,
		cfg.MaxConnPerExternalIP,
		cfg.MaxConnRateExternal,
		cfg.MaxMsgsPerSecExternal,
		cfg.MaxGlobalConnRate,
		cfg.MaxGlobalActive,
		cfg.MaxBytesPerSec,
		cfg.MaxMsgsPerSec,
		cfg.PenaltyThreshold,
		cfg.AutoBlacklistOffenses,
		int(cfg.BlockDuration1.Seconds()),
		int(cfg.BlockDuration2.Seconds()),
		int(cfg.BlockDuration3.Seconds()),
		int(cfg.BlockDuration4.Seconds()),
		cfg.MaxHalfOpenPerIP,
		cfg.MaxGlobalHalfOpen,
		int(cfg.HalfOpenTimeoutSec.Seconds()),
		int(cfg.SlowlorisTimeoutSec.Seconds()),
		cfg.SlowlorisMinBytes,
		cfg.SubnetBlockThreshold24,
		cfg.SubnetBlockThreshold16,
		cfg.ClusterDetectMinIPs,
		int(cfg.ClusterDetectWindowSec.Seconds()),
		cfg.SurgeMultiplier,
		int(cfg.SurgeCooldownSec.Seconds()),
		cfg.MaxAcceptRateAttack,
		cfg.GeoIPEnabled,
		allowed,
		blocked,
		cfg.GeoIPDirection,
		cfg.GeoIPKernelEnforce,
		cfg.GeoIPDataDir,
		cfg.KernelBlockEnabled,
		cfg.KernelBlockMinLevel,
		cfg.KernelRuleCleanupHours,
		int(cfg.WhitelistReloadSec.Seconds()),
		int(cfg.StatsIntervalSec.Seconds()),
	)

	return os.WriteFile(path, []byte(content), 0644)
}

// SaveDefault writes a clean default config file.
func (m *Manager) SaveDefault(path string) error {
	m.mu.Lock()
	m.path = path
	m.mu.Unlock()
	return m.Save()
}

// BackendAddress returns host:port for upstream connection.
func (c *Config) BackendAddress() string {
	return fmt.Sprintf("%s:%d", c.BackendHost, c.BackendPort)
}

// FirewallAddress returns host:port for public listening.
func (c *Config) FirewallAddress() string {
	return fmt.Sprintf("%s:%d", c.FirewallHost, c.FirewallPort)
}

// WebAddress returns host:port for the Web Control Plane.
func (c *Config) WebAddress() string {
	return fmt.Sprintf("%s:%d", c.WebHost, c.WebPort)
}
