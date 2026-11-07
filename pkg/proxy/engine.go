package proxy

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"firewall/pkg/acl"
	"firewall/pkg/behavior"
	"firewall/pkg/config"
	"firewall/pkg/detector"
	"firewall/pkg/geoip"
	"firewall/pkg/halfopen"
	"firewall/pkg/kernel"
	"firewall/pkg/limiter"
	"firewall/pkg/signatures"
	"firewall/pkg/stats"
	"firewall/pkg/surge"
)

// Engine is the core TCP reverse proxy and anti-DDoS mitigation engine.
type Engine struct {
	cfgMgr     *config.Manager
	acl        *acl.AccessControl
	geoip      *geoip.Filter
	limiter    *limiter.Limiter
	signatures *signatures.SignatureEngine
	behavior   *behavior.Manager
	detector   *detector.Detector
	surge      *surge.SurgeDetector
	halfopen   *halfopen.Tracker
	kernel     *kernel.Blocker
	stats      *stats.Collector

	routesMu sync.RWMutex
	routes   []*Route

	listener net.Listener
	stopChan chan struct{}
}

// NewEngine constructs and wires all 9 defense layers together.
func NewEngine(cfgMgr *config.Manager) *Engine {
	cfg := cfgMgr.Get()

	statsCollector := stats.New()
	kernelBlocker := kernel.New(cfg.KernelBlockEnabled)

	accessControl := acl.New(cfg.WhitelistFile, cfg.BlacklistFile)

	var det *detector.Detector
	behaviorMgr := behavior.New(
		// onAutoBlacklist
		func(ip, reason string) {
			_ = accessControl.AddBlacklist(ip, reason)
			statsCollector.RecordAttack(ip, "CRITICAL", "AUTO_BLACKLIST", reason)
		},
		// onKernelBlock
		func(ip string, level int) {
			_ = kernelBlocker.BlockIP(ip, fmt.Sprintf("Level %d repeated offender", level))
			fmt.Printf("[KERNEL] Blocked at firewall level: %s\n", ip)
		},
	)

	det = detector.New(func(cidr, reason string) {
		_ = accessControl.AddBlacklist(cidr, reason)
		_ = kernelBlocker.BlockIP(cidr, reason)
		fmt.Printf("[DISTRIBUTED] Subnet blocked: %s (%s)\n", cidr, reason)
	})

	e := &Engine{
		cfgMgr:     cfgMgr,
		acl:        accessControl,
		geoip:      geoip.New(),
		limiter:    limiter.New(),
		signatures: signatures.New(),
		behavior:   behaviorMgr,
		detector:   det,
		surge:      surge.New(),
		halfopen:   halfopen.New(),
		kernel:     kernelBlocker,
		stats:      statsCollector,
		stopChan:   make(chan struct{}),
	}

	e.initRoutes()
	e.syncGeoIP()
	return e
}

func (e *Engine) syncGeoIP() {
	cfg := e.cfgMgr.Get()
	e.kernel.SetEnabled(cfg.KernelBlockEnabled)

	changed, _ := e.geoip.SyncConfig(
		cfg.GeoIPEnabled,
		cfg.GeoIPDirection,
		cfg.GeoIPAllowedCountries,
		cfg.GeoIPBlockedCountries,
		cfg.GeoIPDataDir,
	)
	if changed {
		extra := e.acl.WhitelistEntries()
		if cfg.BackendHost != "" {
			if ip := net.ParseIP(cfg.BackendHost); ip != nil {
				extra = append(extra, ip.String())
			}
		}
		e.routesMu.RLock()
		for _, r := range e.routes {
			if ip := net.ParseIP(r.OriginIP); ip != nil {
				extra = append(extra, ip.String())
			}
		}
		e.routesMu.RUnlock()

		e.kernel.SyncGeoIPKernelRules(
			cfg.GeoIPEnabled && cfg.GeoIPKernelEnforce,
			cfg.GeoIPDirection,
			cfg.FirewallPort,
			e.geoip.AllowedCIDRs(),
			extra,
		)
	}
}

// Start launches the TCP listener(s) and background loops.
func (e *Engine) Start() error {
	cfg := e.cfgMgr.Get()
	addr := cfg.FirewallAddress()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind() failed on %s: %w", addr, err)
	}
	e.listener = ln

	// Start secondary route listeners
	e.routesMu.Lock()
	for _, r := range e.routes {
		if !r.IsPrimary && r.Enabled {
			if err := e.startRouteListener(r); err != nil {
				fmt.Printf("[WARN] %v\n", err)
			}
		}
	}
	e.routesMu.Unlock()

	e.printBanner(cfg)

	// Background loops
	go e.telemetryLoop()
	go e.statsLoop()
	go e.reloadLoop()

	// Accept loop for Primary Route #1
	for {
		clientConn, err := e.listener.Accept()
		if err != nil {
			select {
			case <-e.stopChan:
				return nil
			default:
				fmt.Printf("[ERROR] accept() failed: %v\n", err)
				continue
			}
		}

		go e.handleClient(clientConn)
	}
}

// Stop cleanly shuts down the firewall and clears kernel rules if configured.
func (e *Engine) Stop() {
	select {
	case <-e.stopChan:
		return
	default:
		close(e.stopChan)
	}
	if e.listener != nil {
		_ = e.listener.Close()
	}
	e.routesMu.Lock()
	for _, r := range e.routes {
		e.stopRouteListener(r)
	}
	e.routesMu.Unlock()
	e.kernel.ClearAllAntiDDoSRules()
}

func (e *Engine) primaryRoute() *Route {
	e.routesMu.RLock()
	defer e.routesMu.RUnlock()
	if len(e.routes) > 0 {
		return e.routes[0]
	}
	return nil
}

func (e *Engine) handleClient(clientConn net.Conn) {
	e.handleClientForRoute(clientConn, e.primaryRoute())
}

func (e *Engine) handleClientForRoute(clientConn net.Conn, route *Route) {
	defer clientConn.Close()

	e.stats.IncTotalConn()
	if route != nil {
		atomic.AddInt64(&route.totalConns, 1)
		if !route.Enabled {
			atomic.AddInt64(&route.blockedConns, 1)
			e.stats.IncBlocked()
			return
		}
	}

	cfg := e.cfgMgr.Get()

	// 0. Extract Client IP
	clientRemote := clientConn.RemoteAddr().String()
	ipStr, _, err := net.SplitHostPort(clientRemote)
	if err != nil {
		return
	}
	clientIP := net.ParseIP(ipStr)
	if clientIP == nil {
		return
	}

	recordDrop := func(level, sig, desc string) {
		if route != nil {
			atomic.AddInt64(&route.blockedConns, 1)
		}
		e.stats.RecordAttack(ipStr, level, sig, desc)
	}

	// 1. Layer 1: Access Control (Whitelist, Lockdown Mode & Blacklist)
	isWhitelisted := e.acl.IsWhitelisted(clientIP)
	if !isWhitelisted {
		if cfg.LockdownWhitelistOnly {
			recordDrop("HIGH", "LOCKDOWN_DROP", "Dropped by Whitelist-Only Lockdown Mode")
			return
		}
		if blacklisted, reason := e.acl.IsBlacklisted(clientIP); blacklisted {
			recordDrop("HIGH", "BLACKLISTED_IP", reason)
			return
		}
		// Layer 1.5: GeoIP & International Inbound Filtering (Only allowed countries IN)
		if allowed, _, reason := e.geoip.CheckInbound(clientIP); !allowed {
			recordDrop("HIGH", "GEOIP_BLOCK_IN", reason)
			return
		}
	}

	// 2. Layer 7: Subnet & Distributed Attack Check
	if !isWhitelisted && cfg.LayerSubnetEnabled {
		if blocked, reason := e.detector.IsSubnetBlocked(ipStr); blocked {
			recordDrop("HIGH", "SUBNET_BLOCKED", reason)
			return
		}

		if e.detector.RecordNewConnectionForCluster(ipStr, cfg) {
			if e.detector.IsUnderClusterAttack() {
				recordDrop("HIGH", "CLUSTER_ATTACK", "Connection dropped during cluster surge")
				return
			}
		}
	}

	// 3. Layer 5: Behavioral Penalty Block Check
	if !isWhitelisted {
		if blocked, remaining, reason := e.behavior.IsBlocked(ipStr); blocked {
			if route != nil {
				atomic.AddInt64(&route.blockedConns, 1)
			}
			e.stats.IncBlocked()
			_ = remaining
			_ = reason
			return
		}
	}

	// 4. Layer 8: Surge & Defense Mode
	mode := e.surge.RecordConnection(cfg)
	if !isWhitelisted && cfg.LayerSurgeEnabled {
		if !e.surge.AllowExternalConnection(cfg) {
			recordDrop("MEDIUM", "SURGE_THROTTLED", fmt.Sprintf("Dropped under %s mode", mode))
			return
		}
	}

	// 5. Layer 2: Rate Limiting & Connection Tracker
	allowed, limitReason := e.limiter.CheckAndRecordConnection(ipStr, isWhitelisted, cfg)
	if !allowed {
		recordDrop("MEDIUM", "RATE_LIMIT_EXCEEDED", limitReason)
		if !isWhitelisted {
			e.behavior.AddPenalty(ipStr, 35, limitReason, cfg)
			if cfg.LayerSubnetEnabled {
				e.detector.RecordIPBlocked(ipStr, cfg)
			}
		}
		return
	}
	defer e.limiter.ReleaseConnection(ipStr)

	if route != nil {
		atomic.AddInt64(&route.activeConns, 1)
		defer atomic.AddInt64(&route.activeConns, -1)
	}

	// 6. Layer 3: Half-Open Connection Defense (SYN / Connection Flood)
	if !isWhitelisted && cfg.LayerHalfOpenEnabled {
		if !e.halfopen.Acquire(ipStr, cfg) {
			recordDrop("HIGH", "HALFOPEN_FLOOD", "Max half-open connections reached")
			e.behavior.AddPenalty(ipStr, 50, "Half-open flood", cfg)
			return
		}
	}

	// Wait for first data packet within halfopen_timeout_sec
	if !isWhitelisted && cfg.LayerHalfOpenEnabled {
		_ = clientConn.SetReadDeadline(time.Now().Add(cfg.HalfOpenTimeoutSec))
	} else {
		_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}

	initialBuf := make([]byte, 2048)
	n, readErr := clientConn.Read(initialBuf)

	if !isWhitelisted && cfg.LayerHalfOpenEnabled {
		e.halfopen.Release(ipStr)
	}

	if readErr != nil {
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			if !isWhitelisted && cfg.LayerHalfOpenEnabled {
				recordDrop("MEDIUM", "HALFOPEN_TIMEOUT", "Client failed to send initial payload in time")
				e.behavior.AddPenalty(ipStr, 30, "Idle half-open connection", cfg)
			}
		}
		return
	}

	e.stats.AddTrafficIn(int64(n), 1)
	if route != nil {
		atomic.AddInt64(&route.bytesIn, int64(n))
	}

	// 7. Layer 4: Attack Signature Engine (+ 29 signatures & proxy inspection)
	inspectL7 := cfg.LayerSignatureEnabled
	if route != nil && route.InspectionMode == "l4_fast" {
		inspectL7 = false
	}
	if !isWhitelisted && inspectL7 {
		result := e.signatures.InspectFirstPacket(initialBuf[:n])
		if result.Matched {
			recordDrop(string(result.Threat), result.Signature, result.Description)
			e.behavior.AddPenalty(ipStr, result.Penalty, result.Description, cfg)
			if cfg.LayerSubnetEnabled {
				e.detector.RecordIPBlocked(ipStr, cfg)
			}

			// Real-time auto-add to blacklist & kernel block
			if result.Threat == signatures.ThreatCritical || result.Threat == signatures.ThreatHigh {
				_ = e.acl.AddBlacklist(ipStr, fmt.Sprintf("%s (%s)", result.Signature, result.Description))
				if cfg.KernelBlockEnabled {
					_ = e.kernel.BlockIP(ipStr, result.Signature)
				}
			}
			return
		}
	}

	// Clear initial read deadline & optimize TCP for game latency (disable Nagle)
	_ = clientConn.SetReadDeadline(time.Time{})
	if tc, ok := clientConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}

	// Determine target Origin Server & Proxy Protocol for this route
	backendHost := cfg.BackendHost
	backendPort := cfg.BackendPort
	proxyProto := cfg.ProxyProtocol
	if route != nil && !route.IsPrimary {
		backendHost = route.OriginIP
		backendPort = route.OriginPort
		if route.ProxyProtocol != "" && route.ProxyProtocol != "inherit" {
			proxyProto = route.ProxyProtocol
		}
	} else if route != nil && route.ProxyProtocol != "" && route.ProxyProtocol != "inherit" {
		proxyProto = route.ProxyProtocol
	}

	// 8. Connect to Backend Game Server (with Outbound GeoIP Enforcement)
	startTime := time.Now()
	if backendIP := net.ParseIP(backendHost); backendIP != nil {
		if !e.acl.IsWhitelisted(backendIP) {
			if allowed, _, reason := e.geoip.CheckOutbound(backendIP); !allowed {
				if route != nil {
					atomic.AddInt64(&route.blockedConns, 1)
				}
				e.stats.RecordAttack(backendIP.String(), "HIGH", "GEOIP_BLOCK_OUT", reason)
				return
			}
		}
	}

	backendAddr := fmt.Sprintf("%s:%d", backendHost, backendPort)
	dialStart := time.Now()
	backendConn, dialErr := net.DialTimeout("tcp", backendAddr, 3*time.Second)
	if dialErr != nil {
		if route != nil {
			route.statusMu.Lock()
			route.originStatus = "OFFLINE"
			route.statusMu.Unlock()
		}
		fmt.Printf("[FIREWALL] Failed to connect to origin on %s: %v\n", backendAddr, dialErr)
		return
	}
	defer backendConn.Close()

	if route != nil {
		lat := time.Since(dialStart).Milliseconds()
		if lat == 0 {
			lat = 1
		}
		atomic.StoreInt64(&route.latencyMs, lat)
		route.statusMu.Lock()
		route.originStatus = "ONLINE"
		route.statusMu.Unlock()
	}

	// Verify resolved remote IP if BackendHost was a domain name
	if remoteTCP, ok := backendConn.RemoteAddr().(*net.TCPAddr); ok && remoteTCP.IP != nil {
		if !e.acl.IsWhitelisted(remoteTCP.IP) {
			if allowed, _, reason := e.geoip.CheckOutbound(remoteTCP.IP); !allowed {
				if route != nil {
					atomic.AddInt64(&route.blockedConns, 1)
				}
				e.stats.RecordAttack(remoteTCP.IP.String(), "HIGH", "GEOIP_BLOCK_OUT", reason)
				return
			}
		}
	}

	if tc, ok := backendConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}

	// PROXY Protocol Header injection (Forward real client IP to backend)
	if proxyProto != "" && proxyProto != "off" {
		header := BuildProxyHeader(proxyProto, clientConn, backendConn)
		if len(header) > 0 {
			if _, err := backendConn.Write(header); err != nil {
				return
			}
		}
	}

	// Forward initial handshake payload to backend
	if _, err := backendConn.Write(initialBuf[:n]); err != nil {
		return
	}

	// 9. Layer 6 & Bidirectional Zero-Copy TCP Forwarding
	var bytesClientToBackend int64 = int64(n)
	var bytesBackendToClient int64 = 0

	var pipeWg sync.WaitGroup
	pipeWg.Add(2)

	// Stream: Client -> Backend (Ingress)
	go func() {
		defer pipeWg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := clientConn.Read(buf)
			if nr > 0 {
				bytesClientToBackend += int64(nr)
				e.stats.AddTrafficIn(int64(nr), 1)
				if route != nil {
					atomic.AddInt64(&route.bytesIn, int64(nr))
				}
				// Layer 2 & 6: Rate limit & slowloris throughput monitoring
				if !isWhitelisted {
					if !e.limiter.CheckPacketRate(ipStr, nr, isWhitelisted, cfg) {
						recordDrop("MEDIUM", "PACKET_FLOOD", "Packet/bandwidth rate exceeded")
						_ = clientConn.Close()
						_ = backendConn.Close()
						return
					}
				}
				nw, ew := backendConn.Write(buf[:nr])
				if ew != nil || nw != nr {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := backendConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	// Stream: Backend -> Client (Egress)
	go func() {
		defer pipeWg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := backendConn.Read(buf)
			if nr > 0 {
				bytesBackendToClient += int64(nr)
				e.stats.AddTrafficOut(int64(nr), 1)
				if route != nil {
					atomic.AddInt64(&route.bytesOut, int64(nr))
				}
				nw, ew := clientConn.Write(buf[:nr])
				if ew != nil || nw != nr {
					break
				}
			}
			if err != nil {
				break
			}
		}
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	pipeWg.Wait()

	// Connection closed - record duration for behavioral / slowloris penalty
	duration := time.Since(startTime)
	if !isWhitelisted && cfg.LayerSlowlorisEnabled {
		e.behavior.RecordShortLivedConnection(ipStr, duration, bytesClientToBackend, cfg)
	}
}

func (e *Engine) telemetryLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			e.stats.SampleTick(e.limiter.GlobalActive())
		}
	}
}

func (e *Engine) statsLoop() {
	ticker := time.NewTicker(e.cfgMgr.Get().StatsIntervalSec)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			cfg := e.cfgMgr.Get()
			wlCount, blCount := e.acl.Counts()
			e.stats.PrintDashboard(
				e.limiter.GlobalActive(),
				cfg.MaxGlobalActive,
				e.behavior.BlockedIPsCount(),
				e.detector.ActiveBlockedSubnetCount(),
				wlCount,
				blCount,
				string(e.surge.CurrentMode()),
				e.kernel.HasAdminRights(),
				cfg.FirewallAddress(),
				cfg.BackendAddress(),
			)
		}
	}
}

func (e *Engine) reloadLoop() {
	ticker := time.NewTicker(e.cfgMgr.Get().WhitelistReloadSec)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			if changedW, countW, err := e.acl.ReloadWhitelistIfModified(); err == nil && changedW {
				fmt.Printf("[WHITELIST] Dynamic reload complete. Total entries: %d\n", countW)
			}
			if changedB, countB, err := e.acl.ReloadBlacklistIfModified(); err == nil && changedB {
				fmt.Printf("[BLACKLIST] Dynamic reload complete. Total entries: %d\n", countB)
			}
			_ = e.cfgMgr.Load()
			e.syncGeoIP()
		}
	}
}

// ApplyConfigMutation updates the active configuration, persists it to config.txt, and hot-syncs GeoIP/Kernel/Routes.
func (e *Engine) ApplyConfigMutation(fn func(*config.Config)) error {
	e.cfgMgr.Update(fn)
	cfg := e.cfgMgr.Get()

	// Keep Primary Route #1 synced with config.txt
	e.routesMu.Lock()
	for _, r := range e.routes {
		if r.IsPrimary {
			r.OriginIP = cfg.BackendHost
			r.OriginPort = cfg.BackendPort
			r.ListenPort = cfg.FirewallPort
			if cfg.WebPublicDomain != "" {
				r.Domain = cfg.WebPublicDomain
			}
		}
	}
	_ = e.saveRoutesLocked()
	e.routesMu.Unlock()

	e.syncGeoIP()
	return e.cfgMgr.Save()
}

// ConfigManager returns the underlying config manager.
func (e *Engine) ConfigManager() *config.Manager { return e.cfgMgr }

// Stats returns the telemetry collector.
func (e *Engine) Stats() *stats.Collector { return e.stats }

// ACL returns the whitelist/blacklist access controller.
func (e *Engine) ACL() *acl.AccessControl { return e.acl }

// GeoIP returns the GeoIP filter.
func (e *Engine) GeoIP() *geoip.Filter { return e.geoip }

// Kernel returns the OS kernel blocker.
func (e *Engine) Kernel() *kernel.Blocker { return e.kernel }

// ActiveConnections returns the current number of active TCP connections.
func (e *Engine) ActiveConnections() int64 { return e.limiter.GlobalActive() }

// BehaviorBlockedCount returns the number of temporarily blocked IPs in the behavior engine.
func (e *Engine) BehaviorBlockedCount() int { return e.behavior.BlockedIPsCount() }

// BlockedSubnetsCount returns the number of blocked /24 and /16 subnets.
func (e *Engine) BlockedSubnetsCount() int { return e.detector.ActiveBlockedSubnetCount() }

// SurgeMode returns the current surge defense mode ("NORMAL", "ELEVATED", "EMERGENCY").
func (e *Engine) SurgeMode() string { return string(e.surge.CurrentMode()) }

func (e *Engine) printBanner(cfg *config.Config) {
	fmt.Println("============================================================")
	fmt.Println("  ANTI-DDOS HIGH-PERFORMANCE TCP FIREWALL v3.8")
	fmt.Println("  9-Layer Defense + GeoIP + Hacker Web Control Plane")
	fmt.Println("============================================================")
	fmt.Printf("  Primary Endpoint: %s -> %s\n", cfg.FirewallAddress(), cfg.BackendAddress())
	if cfg.WebEnabled {
		fmt.Printf("  Web Dashboard:    http://%s (Cyber Control Plane)\n", cfg.WebAddress())
	}
	if e.kernel.HasAdminRights() {
		fmt.Println("  Admin Rights:     YES (Kernel-level OS blocking ENABLED)")
	} else {
		fmt.Println("  Admin Rights:     NO (Kernel blocking disabled - socket level only)")
	}
	fmt.Printf("  Defense Mode:     %s\n", e.surge.CurrentMode())
	fmt.Printf("  GeoIP Filter:     %s\n", e.geoip.Summary())
	fmt.Printf("  Proxy Protocol:   %s\n", cfg.ProxyProtocol)
	fmt.Printf("  Protected Routes: %d active endpoint(s)\n", len(e.GetRoutes()))
	fmt.Println("============================================================")
	fmt.Println("[FIREWALL] Proxy engine listening for connections...")
}
