package proxy

import (
	"fmt"
	"net"
	"sync"
	"time"

	"firewall/pkg/acl"
	"firewall/pkg/behavior"
	"firewall/pkg/config"
	"firewall/pkg/detector"
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
	limiter    *limiter.Limiter
	signatures *signatures.SignatureEngine
	behavior   *behavior.Manager
	detector   *detector.Detector
	surge      *surge.SurgeDetector
	halfopen   *halfopen.Tracker
	kernel     *kernel.Blocker
	stats      *stats.Collector

	listener net.Listener
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewEngine constructs and wires all 8 defense layers together.
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

	return e
}

// Start launches the TCP listener and background loops.
func (e *Engine) Start() error {
	cfg := e.cfgMgr.Get()
	addr := e.cfgMgr.Get().FirewallAddress()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind() failed on %s: %w", addr, err)
	}
	e.listener = ln

	e.printBanner(cfg)

	// Background loops
	go e.statsLoop()
	go e.reloadLoop()

	// Accept loop
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
	close(e.stopChan)
	if e.listener != nil {
		_ = e.listener.Close()
	}
	e.kernel.ClearAllAntiDDoSRules()
}

func (e *Engine) handleClient(clientConn net.Conn) {
	defer clientConn.Close()

	e.stats.IncTotalConn()
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

	// 1. Layer 1: Access Control (Whitelist & Blacklist)
	isWhitelisted := e.acl.IsWhitelisted(clientIP)
	if !isWhitelisted {
		if blacklisted, reason := e.acl.IsBlacklisted(clientIP); blacklisted {
			e.stats.RecordAttack(ipStr, "HIGH", "BLACKLISTED_IP", reason)
			return // silent drop
		}
	}

	// 2. Layer 7: Subnet & Distributed Attack Check
	if !isWhitelisted {
		if blocked, reason := e.detector.IsSubnetBlocked(ipStr); blocked {
			e.stats.RecordAttack(ipStr, "HIGH", "SUBNET_BLOCKED", reason)
			return
		}

		if e.detector.RecordNewConnectionForCluster(ipStr, cfg) {
			if e.detector.IsUnderClusterAttack() {
				e.stats.RecordAttack(ipStr, "HIGH", "CLUSTER_ATTACK", "Connection dropped during cluster surge")
				return
			}
		}
	}

	// 3. Layer 5: Behavioral Penalty Block Check
	if !isWhitelisted {
		if blocked, remaining, reason := e.behavior.IsBlocked(ipStr); blocked {
			e.stats.IncBlocked()
			_ = remaining
			_ = reason
			return
		}
	}

	// 4. Layer 8: Surge & Defense Mode
	mode := e.surge.RecordConnection(cfg)
	if !isWhitelisted {
		if !e.surge.AllowExternalConnection(cfg) {
			e.stats.RecordAttack(ipStr, "MEDIUM", "SURGE_THROTTLED", fmt.Sprintf("Dropped under %s mode", mode))
			return
		}
	}

	// 5. Layer 2: Rate Limiting & Connection Tracker
	allowed, limitReason := e.limiter.CheckAndRecordConnection(ipStr, isWhitelisted, cfg)
	if !allowed {
		e.stats.RecordAttack(ipStr, "MEDIUM", "RATE_LIMIT_EXCEEDED", limitReason)
		if !isWhitelisted {
			e.behavior.AddPenalty(ipStr, 35, limitReason, cfg)
			e.detector.RecordIPBlocked(ipStr, cfg)
		}
		return
	}
	defer e.limiter.ReleaseConnection(ipStr)

	// 6. Layer 3: Half-Open Connection Defense (SYN / Connection Flood)
	if !isWhitelisted {
		if !e.halfopen.Acquire(ipStr, cfg) {
			e.stats.RecordAttack(ipStr, "HIGH", "HALFOPEN_FLOOD", "Max half-open connections reached")
			e.behavior.AddPenalty(ipStr, 50, "Half-open flood", cfg)
			return
		}
	}

	// Wait for first data packet within halfopen_timeout_sec
	if !isWhitelisted {
		_ = clientConn.SetReadDeadline(time.Now().Add(cfg.HalfOpenTimeoutSec))
	} else {
		_ = clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	}

	initialBuf := make([]byte, 2048)
	n, readErr := clientConn.Read(initialBuf)

	if !isWhitelisted {
		e.halfopen.Release(ipStr)
	}

	if readErr != nil {
		if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
			if !isWhitelisted {
				e.stats.RecordAttack(ipStr, "MEDIUM", "HALFOPEN_TIMEOUT", "Client failed to send initial payload in time")
				e.behavior.AddPenalty(ipStr, 30, "Idle half-open connection", cfg)
			}
		}
		return
	}

	// 7. Layer 4: Attack Signature Engine (+ 29 signatures & proxy inspection)
	if !isWhitelisted {
		result := e.signatures.InspectFirstPacket(initialBuf[:n])
		if result.Matched {
			e.stats.RecordAttack(ipStr, string(result.Threat), result.Signature, result.Description)
			e.behavior.AddPenalty(ipStr, result.Penalty, result.Description, cfg)
			e.detector.RecordIPBlocked(ipStr, cfg)

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

	// 8. Connect to Backend Game Server
	startTime := time.Now()
	backendAddr := cfg.BackendAddress()
	backendConn, dialErr := net.DialTimeout("tcp", backendAddr, 3*time.Second)
	if dialErr != nil {
		fmt.Printf("[FIREWALL] Failed to connect to backend on %s: %v\n", backendAddr, dialErr)
		return
	}
	defer backendConn.Close()

	if tc, ok := backendConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
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

	// Stream: Client -> Backend
	go func() {
		defer pipeWg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := clientConn.Read(buf)
			if nr > 0 {
				bytesClientToBackend += int64(nr)
				// Layer 2 & 6: Rate limit & slowloris throughput monitoring
				if !isWhitelisted {
					if !e.limiter.CheckPacketRate(ipStr, nr, isWhitelisted, cfg) {
						e.stats.RecordAttack(ipStr, "MEDIUM", "PACKET_FLOOD", "Packet/bandwidth rate exceeded")
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
		// Close writing half to signal EOF
		if tc, ok := backendConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	// Stream: Backend -> Client
	go func() {
		defer pipeWg.Done()
		buf := make([]byte, 32*1024)
		for {
			nr, err := backendConn.Read(buf)
			if nr > 0 {
				bytesBackendToClient += int64(nr)
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

	// Connection closed - record duration for behavioral penalty
	duration := time.Since(startTime)
	if !isWhitelisted {
		e.behavior.RecordShortLivedConnection(ipStr, duration, bytesClientToBackend, cfg)
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
			// Dynamic reload Whitelist and Blacklist from disk if files were modified
			if changedW, countW, err := e.acl.ReloadWhitelistIfModified(); err == nil && changedW {
				fmt.Printf("[WHITELIST] Dynamic reload complete. Total entries: %d\n", countW)
			}
			if changedB, countB, err := e.acl.ReloadBlacklistIfModified(); err == nil && changedB {
				fmt.Printf("[BLACKLIST] Dynamic reload complete. Total entries: %d\n", countB)
			}
			// Reload config file if changed
			_ = e.cfgMgr.Load()
		}
	}
}

func (e *Engine) printBanner(cfg *config.Config) {
	fmt.Println("============================================================")
	fmt.Println("  ANTI-DDOS HIGH-PERFORMANCE TCP FIREWALL v3.5")
	fmt.Println("  8-Layer Defense System + Distributed Attack Detection")
	fmt.Println("============================================================")
	fmt.Printf("  Listen Address:   %s (Public-facing VPS)\n", cfg.FirewallAddress())
	fmt.Printf("  Backend Game:     %s\n", cfg.BackendAddress())
	if e.kernel.HasAdminRights() {
		fmt.Println("  Admin Rights:     YES (Kernel-level OS blocking ENABLED)")
	} else {
		fmt.Println("  Admin Rights:     NO (Kernel blocking disabled - socket level only)")
	}
	fmt.Printf("  Defense Mode:     %s\n", e.surge.CurrentMode())
	fmt.Printf("  Whitelist Reload: Every %v\n", cfg.WhitelistReloadSec)
	fmt.Println("============================================================")
	fmt.Println("[FIREWALL] Proxy engine listening for connections...")
}
