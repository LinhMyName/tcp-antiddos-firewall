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

	// Connection limits per IP (Whitelisted)
	MaxConnPerIP int
	MaxConnRate  int

	// Connection limits per IP (External / Non-whitelisted)
	MaxConnPerExternalIP int
	MaxConnRateExternal  int
	MaxMsgsPerSecExternal int

	// Global limits
	MaxGlobalConnRate int
	MaxGlobalActive   int
	MaxBytesPerSec    int64
	MaxMsgsPerSec     int

	// Blocking & Penalties
	PenaltyThreshold     int
	AutoBlacklistOffenses int
	BlockDuration1       time.Duration
	BlockDuration2       time.Duration
	BlockDuration3       time.Duration
	BlockDuration4       time.Duration

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
	SurgeMultiplier    float64
	SurgeCooldownSec   time.Duration
	MaxAcceptRateAttack int

	// Kernel blocking
	KernelBlockEnabled     bool
	KernelBlockMinLevel    int
	KernelRuleCleanupHours int

	// Reload & Stats
	WhitelistReloadSec time.Duration
	StatsIntervalSec   time.Duration

	// File paths
	ConfigFile    string
	WhitelistFile string
	BlacklistFile string
}

// DefaultConfig returns reasonable defaults matching v3.0 specs.
func DefaultConfig() *Config {
	return &Config{
		FirewallHost:          "0.0.0.0",
		FirewallPort:          9999,
		BackendHost:           "127.0.0.1",
		BackendPort:           14445,
		MaxConnPerIP:          200,
		MaxConnRate:           100,
		MaxConnPerExternalIP:  5,
		MaxConnRateExternal:   3,
		MaxMsgsPerSecExternal: 50,
		MaxGlobalConnRate:     500,
		MaxGlobalActive:       2000,
		MaxBytesPerSec:        10 * 1024 * 1024, // 10 MB/s
		MaxMsgsPerSec:         500,
		PenaltyThreshold:      150,
		AutoBlacklistOffenses: 3,
		BlockDuration1:       30 * time.Second,
		BlockDuration2:       120 * time.Second,
		BlockDuration3:       600 * time.Second,
		BlockDuration4:       86400 * time.Second,
		MaxHalfOpenPerIP:     10,
		MaxGlobalHalfOpen:    200,
		HalfOpenTimeoutSec:   3 * time.Second,
		SlowlorisTimeoutSec:  8 * time.Second,
		SlowlorisMinBytes:    100,
		SubnetBlockThreshold24: 3,
		SubnetBlockThreshold16: 2,
		ClusterDetectMinIPs:    10,
		ClusterDetectWindowSec: 5 * time.Second,
		SurgeMultiplier:      3.0,
		SurgeCooldownSec:     30 * time.Second,
		MaxAcceptRateAttack:  50,
		KernelBlockEnabled:   true,
		KernelBlockMinLevel:  3,
		KernelRuleCleanupHours: 24,
		WhitelistReloadSec:   60 * time.Second,
		StatsIntervalSec:     5 * time.Second,
		ConfigFile:           "config.txt",
		WhitelistFile:        "whitelist.txt",
		BlacklistFile:        "blacklist.txt",
	}
}

// Manager manages dynamic config loading with thread-safe atomic access.
type Manager struct {
	mu     sync.RWMutex
	cfg    *Config
	path   string
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
	// Return shallow copy
	cfgCopy := *m.cfg
	return &cfgCopy
}

// Load reads and parses the config file.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

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
			newCfg.KernelBlockEnabled = (val == "true" || val == "1" || val == "yes")
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
		}
	}

	m.cfg = &newCfg
	return scanner.Err()
}

// SaveDefault writes a clean default config file.
func (m *Manager) SaveDefault(path string) error {
	content := `# Anti-DDoS High-Performance Firewall v3.5
# Cross-Platform TCP Reverse Proxy (Linux / Windows)

# ============================================================
# NETWORK & BINDING CONFIGURATION
# ============================================================
# Port firewall lang nghe tren VPS trung gian (Public-facing)
firewall_host=0.0.0.0
firewall_port=9999

# Dia chi va Port cua Game Server backend goc
backend_host=127.0.0.1
backend_port=14445

# ============================================================
# CONNECTION LIMITS (Per IP)
# ============================================================
# Whitelisted IPs
max_conn_per_ip=200          # Max concurrent connections per whitelisted IP
max_conn_rate=100            # Max new connections/sec per whitelisted IP

# External IPs (non-whitelisted) - STRICT
max_conn_per_external_ip=5   # Max concurrent connections per external IP
max_conn_rate_external=3     # Max new connections/sec per external IP
max_msgs_per_sec_external=50 # Max packets/sec per external IP

# ============================================================
# GLOBAL LIMITS
# ============================================================
max_global_conn_rate=500     # Max new connections/sec globally
max_global_active=2000       # Max total active connections
max_bytes_per_sec=10485760   # Max bandwidth per IP (10 MB/s)
max_msgs_per_sec=500         # Max packets/sec per IP

# ============================================================
# BLOCKING & PENALTIES
# ============================================================
penalty_threshold=150        # Auto-block when penalty score reaches this
auto_blacklist_offenses=3    # Permanent blacklist after N offenses

# Block durations (seconds) - Progressive escalation
block_duration_1=30          # 1st offense: 30 seconds
block_duration_2=120         # 2nd offense: 2 minutes
block_duration_3=600         # 3rd offense: 10 minutes
block_duration_4=86400       # 4th+ offense: 24 hours

# ============================================================
# ATTACK DETECTION
# ============================================================
# SYN / Half-open Flood
max_halfopen_per_ip=10       # Max half-open connections per IP
max_global_halfopen=200      # Max total half-open connections
halfopen_timeout_sec=3       # Half-open connection timeout (seconds)

# Slowloris
slowloris_timeout_sec=8      # Slow connection timeout
slowloris_min_bytes=100      # Min bytes required in timeout window

# Distributed Attack & Subnet Detection
subnet_block_threshold_24=3  # Block /24 subnet after N IPs blocked
subnet_block_threshold_16=2  # Block /16 after N /24 subnets blocked
cluster_detect_min_ips=10    # Cluster attack = N IPs in window
cluster_detect_window_sec=5  # Cluster detection time window

# Surge Protection
surge_multiplier=3           # Surge = N x baseline connection rate
surge_cooldown_sec=30        # Whitelist-only mode duration after surge
max_accept_rate_attack=50    # Max accept/sec when under attack

# ============================================================
# KERNEL-LEVEL BLOCKING (Windows netsh / Linux iptables)
# ============================================================
kernel_block_enabled=true    # Enable kernel level dropping
kernel_block_min_level=3     # Min offenses to trigger kernel block
kernel_rule_cleanup_hours=24 # Auto-cleanup kernel rules after N hours

# ============================================================
# RELOAD & STATS INTERVALS
# ============================================================
whitelist_reload_sec=60      # Reload whitelist.txt every N seconds
stats_interval_sec=5         # Dashboard refresh interval
`
	return os.WriteFile(path, []byte(content), 0644)
}

// BackendAddress returns host:port for upstream connection.
func (c *Config) BackendAddress() string {
	return fmt.Sprintf("%s:%d", c.BackendHost, c.BackendPort)
}

// FirewallAddress returns host:port for public listening.
func (c *Config) FirewallAddress() string {
	return fmt.Sprintf("%s:%d", c.FirewallHost, c.FirewallPort)
}
