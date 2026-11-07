package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"firewall/pkg/config"
)

func (e *Engine) routesFilePath() string {
	cfg := e.cfgMgr.Get()
	if cfg.ConfigFile != "" {
		dir := filepath.Dir(cfg.ConfigFile)
		if dir != "" && dir != "." {
			return filepath.Join(dir, "routes.json")
		}
	}
	return "routes.json"
}

// Route represents a linked Firewall Endpoint -> Origin Game Server tunnel.
type Route struct {
	ID             int    `json:"id"`
	Name           string `json:"name"`
	Domain         string `json:"domain"`
	ListenPort     int    `json:"listen_port"`
	OriginIP       string `json:"origin_ip"`
	OriginPort     int    `json:"origin_port"`
	Protocol       string `json:"protocol"`        // "TCP", "TCP+SYN", "GAME-NRO"
	ProxyProtocol  string `json:"proxy_protocol"`  // "inherit", "off", "v1", "v2"
	InspectionMode string `json:"inspection_mode"` // "standard", "strict_game", "l4_fast"
	Enabled        bool   `json:"enabled"`
	IsPrimary      bool   `json:"is_primary"`
	CreatedAt      string `json:"created_at"`

	// Runtime telemetry (populated in snapshots)
	ActiveConns   int64  `json:"active_conns"`
	TotalConns    int64  `json:"total_conns"`
	BlockedConns  int64  `json:"blocked_conns"`
	BytesIn       int64  `json:"bytes_in"`
	BytesOut      int64  `json:"bytes_out"`
	LastLatencyMs int64  `json:"last_latency_ms"`
	OriginStatus  string `json:"origin_status"` // "ONLINE", "OFFLINE", "UNCHECKED"
	Endpoint      string `json:"endpoint"`      // Computed "domain:listen_port"

	// Internal atomic counters & listener state
	activeConns  int64
	totalConns   int64
	blockedConns int64
	bytesIn      int64
	bytesOut     int64
	latencyMs    int64
	statusMu     sync.RWMutex
	originStatus string
	listener     net.Listener
	stopListener chan struct{}
}

// Snapshot returns a clean copy of the route with atomic counters populated for JSON output.
func (r *Route) Snapshot(defaultHost string) Route {
	r.statusMu.RLock()
	st := r.originStatus
	r.statusMu.RUnlock()
	if st == "" {
		st = "ONLINE"
	}
	dom := strings.TrimSpace(r.Domain)
	if dom == "" {
		dom = defaultHost
	}
	if dom == "" || dom == "0.0.0.0" {
		dom = "127.0.0.1"
	}

	return Route{
		ID:             r.ID,
		Name:           r.Name,
		Domain:         dom,
		ListenPort:     r.ListenPort,
		OriginIP:       r.OriginIP,
		OriginPort:     r.OriginPort,
		Protocol:       r.Protocol,
		ProxyProtocol:  r.ProxyProtocol,
		InspectionMode: r.InspectionMode,
		Enabled:        r.Enabled,
		IsPrimary:      r.IsPrimary,
		CreatedAt:      r.CreatedAt,
		ActiveConns:    atomic.LoadInt64(&r.activeConns),
		TotalConns:     atomic.LoadInt64(&r.totalConns),
		BlockedConns:   atomic.LoadInt64(&r.blockedConns),
		BytesIn:        atomic.LoadInt64(&r.bytesIn),
		BytesOut:       atomic.LoadInt64(&r.bytesOut),
		LastLatencyMs:  atomic.LoadInt64(&r.latencyMs),
		OriginStatus:   st,
		Endpoint:       fmt.Sprintf("%s:%d", dom, r.ListenPort),
	}
}

func (e *Engine) initRoutes() {
	e.routesMu.Lock()
	defer e.routesMu.Unlock()

	cfg := e.cfgMgr.Get()
	defaultDom := cfg.WebPublicDomain
	if defaultDom == "" {
		defaultDom = cfg.FirewallHost
		if defaultDom == "0.0.0.0" || defaultDom == "" {
			defaultDom = "fw.edge-node.vn"
		}
	}

	// Load saved routes if routes.json exists
	var saved []Route
	if data, err := os.ReadFile(e.routesFilePath()); err == nil {
		_ = json.Unmarshal(data, &saved)
	}

	e.routes = make([]*Route, 0)
	primaryFound := false

	for i := range saved {
		sr := saved[i]
		r := &Route{
			ID:             sr.ID,
			Name:           sr.Name,
			Domain:         sr.Domain,
			ListenPort:     sr.ListenPort,
			OriginIP:       sr.OriginIP,
			OriginPort:     sr.OriginPort,
			Protocol:       sr.Protocol,
			ProxyProtocol:  sr.ProxyProtocol,
			InspectionMode: sr.InspectionMode,
			Enabled:        sr.Enabled,
			IsPrimary:      sr.IsPrimary,
			CreatedAt:      sr.CreatedAt,
			originStatus:   "ONLINE",
		}
		if r.ID == 1 || r.IsPrimary {
			r.ID = 1
			r.IsPrimary = true
			r.ListenPort = cfg.FirewallPort
			r.OriginIP = cfg.BackendHost
			r.OriginPort = cfg.BackendPort
			primaryFound = true
		}
		e.routes = append(e.routes, r)
	}

	if !primaryFound {
		primary := &Route{
			ID:             1,
			Name:           "Primary Game Core #1",
			Domain:         defaultDom,
			ListenPort:     cfg.FirewallPort,
			OriginIP:       cfg.BackendHost,
			OriginPort:     cfg.BackendPort,
			Protocol:       "TCP+SYN",
			ProxyProtocol:  "inherit",
			InspectionMode: "strict_game",
			Enabled:        true,
			IsPrimary:      true,
			CreatedAt:      time.Now().Format("2006-01-02 15:04:05"),
			originStatus:   "ONLINE",
		}
		e.routes = append([]*Route{primary}, e.routes...)
	}

	_ = e.saveRoutesLocked()
}

func (e *Engine) saveRoutesLocked() error {
	cfg := e.cfgMgr.Get()
	defaultDom := cfg.WebPublicDomain
	if defaultDom == "" {
		defaultDom = cfg.FirewallHost
	}
	snapshots := make([]Route, 0, len(e.routes))
	for _, r := range e.routes {
		snapshots = append(snapshots, r.Snapshot(defaultDom))
	}
	data, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.routesFilePath(), data, 0644)
}

func (e *Engine) allocateNextPortLocked(preferred int) int {
	used := make(map[int]bool)
	cfg := e.cfgMgr.Get()
	if cfg.WebPort > 0 {
		used[cfg.WebPort] = true
	}
	for _, r := range e.routes {
		used[r.ListenPort] = true
	}
	if preferred > 0 && !used[preferred] {
		return preferred
	}
	for p := 20001; p < 65000; p++ {
		if !used[p] {
			return p
		}
	}
	return 20001
}

// startRouteListener starts the TCP listener for a secondary route.
func (e *Engine) startRouteListener(r *Route) error {
	if r.IsPrimary {
		return nil // Primary route uses e.listener in Start()
	}
	if !r.Enabled {
		return nil
	}
	if r.listener != nil {
		return nil
	}

	cfg := e.cfgMgr.Get()
	bindHost := cfg.FirewallHost
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", bindHost, r.ListenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind route #%d on %s: %w", r.ID, addr, err)
	}

	r.listener = ln
	r.stopListener = make(chan struct{})
	stopCh := r.stopListener

	go func(route *Route, listener net.Listener, stop <-chan struct{}) {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				case <-e.stopChan:
					return
				default:
					continue
				}
			}
			go e.handleClientForRoute(conn, route)
		}
	}(r, ln, stopCh)

	fmt.Printf("[ROUTE] Active Endpoint #%d (%s) listening on %s -> Origin %s:%d\n",
		r.ID, r.Name, addr, r.OriginIP, r.OriginPort)
	return nil
}

func (e *Engine) stopRouteListener(r *Route) {
	if r.stopListener != nil {
		close(r.stopListener)
		r.stopListener = nil
	}
	if r.listener != nil {
		_ = r.listener.Close()
		r.listener = nil
	}
}

// GetRoutes returns snapshots of all configured routes.
func (e *Engine) GetRoutes() []Route {
	e.routesMu.RLock()
	defer e.routesMu.RUnlock()

	cfg := e.cfgMgr.Get()
	defaultDom := cfg.WebPublicDomain
	if defaultDom == "" {
		defaultDom = cfg.FirewallHost
	}

	out := make([]Route, 0, len(e.routes))
	for _, r := range e.routes {
		out = append(out, r.Snapshot(defaultDom))
	}
	return out
}

// AddRoute provisions a new Firewall Endpoint linked to an Origin Server.
func (e *Engine) AddRoute(name, domain string, listenPort int, originIP string, originPort int, protocol, proxyProto, inspectionMode string) (Route, error) {
	originIP = strings.TrimSpace(originIP)
	if originIP == "" || originPort <= 0 || originPort > 65535 {
		return Route{}, fmt.Errorf("invalid origin server IP or port")
	}

	e.routesMu.Lock()
	defer e.routesMu.Unlock()

	cfg := e.cfgMgr.Get()
	if listenPort == cfg.WebPort {
		return Route{}, fmt.Errorf("listen port %d conflicts with Web Control Plane port", listenPort)
	}
	for _, existing := range e.routes {
		if listenPort > 0 && existing.ListenPort == listenPort {
			return Route{}, fmt.Errorf("firewall port %d is already allocated to route '%s'", listenPort, existing.Name)
		}
	}

	finalPort := e.allocateNextPortLocked(listenPort)
	maxID := 0
	for _, r := range e.routes {
		if r.ID > maxID {
			maxID = r.ID
		}
	}

	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("Protected Node #%d", maxID+1)
	}
	if strings.TrimSpace(domain) == "" {
		domain = cfg.WebPublicDomain
		if domain == "" {
			domain = cfg.FirewallHost
			if domain == "0.0.0.0" || domain == "" {
				domain = "fw.edge-node.vn"
			}
		}
	}
	if protocol == "" {
		protocol = "TCP+SYN"
	}
	if proxyProto == "" {
		proxyProto = "inherit"
	}
	if inspectionMode == "" {
		inspectionMode = "strict_game"
	}

	newRoute := &Route{
		ID:             maxID + 1,
		Name:           strings.TrimSpace(name),
		Domain:         strings.TrimSpace(domain),
		ListenPort:     finalPort,
		OriginIP:       originIP,
		OriginPort:     originPort,
		Protocol:       strings.ToUpper(strings.TrimSpace(protocol)),
		ProxyProtocol:  strings.ToLower(strings.TrimSpace(proxyProto)),
		InspectionMode: strings.ToLower(strings.TrimSpace(inspectionMode)),
		Enabled:        true,
		IsPrimary:      false,
		CreatedAt:      time.Now().Format("2006-01-02 15:04:05"),
		originStatus:   "ONLINE",
	}

	// Whitelist the origin IP automatically so outbound GeoIP / ACL never blocks it
	if parsedIP := net.ParseIP(originIP); parsedIP != nil {
		_ = e.acl.AddWhitelist(parsedIP.String())
	}

	// Start listener if engine is already running
	if e.listener != nil {
		if err := e.startRouteListener(newRoute); err != nil {
			return Route{}, err
		}
	}

	e.routes = append(e.routes, newRoute)
	_ = e.saveRoutesLocked()

	go e.PingOrigin(newRoute.ID)
	return newRoute.Snapshot(domain), nil
}

// UpdateRoute modifies an existing route or toggles its ON/OFF status.
func (e *Engine) UpdateRoute(id int, name, domain string, listenPort int, originIP string, originPort int, protocol, proxyProto, inspectionMode string, enabled *bool) (Route, error) {
	e.routesMu.Lock()
	defer e.routesMu.Unlock()

	var target *Route
	for _, r := range e.routes {
		if r.ID == id {
			target = r
			break
		}
	}
	if target == nil {
		return Route{}, fmt.Errorf("route #%d not found", id)
	}

	portChanged := false
	if listenPort > 0 && listenPort != target.ListenPort {
		for _, other := range e.routes {
			if other.ID != id && other.ListenPort == listenPort {
				return Route{}, fmt.Errorf("port %d is already in use by %s", listenPort, other.Name)
			}
		}
		if !target.IsPrimary {
			target.ListenPort = listenPort
			portChanged = true
		}
	}

	if strings.TrimSpace(name) != "" {
		target.Name = strings.TrimSpace(name)
	}
	if strings.TrimSpace(domain) != "" {
		target.Domain = strings.TrimSpace(domain)
	}
	if strings.TrimSpace(originIP) != "" {
		target.OriginIP = strings.TrimSpace(originIP)
		if parsedIP := net.ParseIP(target.OriginIP); parsedIP != nil {
			_ = e.acl.AddWhitelist(parsedIP.String())
		}
	}
	if originPort > 0 && originPort <= 65535 {
		target.OriginPort = originPort
	}
	if strings.TrimSpace(protocol) != "" {
		target.Protocol = strings.ToUpper(strings.TrimSpace(protocol))
	}
	if strings.TrimSpace(proxyProto) != "" {
		target.ProxyProtocol = strings.ToLower(strings.TrimSpace(proxyProto))
	}
	if strings.TrimSpace(inspectionMode) != "" {
		target.InspectionMode = strings.ToLower(strings.TrimSpace(inspectionMode))
	}
	if enabled != nil {
		target.Enabled = *enabled
	}

	// Sync primary route changes back to config.txt
	if target.IsPrimary {
		e.cfgMgr.Update(func(c *config.Config) {
			c.BackendHost = target.OriginIP
			c.BackendPort = target.OriginPort
			if target.ProxyProtocol != "" && target.ProxyProtocol != "inherit" {
				c.ProxyProtocol = target.ProxyProtocol
			}
		})
		_ = e.cfgMgr.Save()
	} else if e.listener != nil {
		if !target.Enabled || portChanged {
			e.stopRouteListener(target)
		}
		if target.Enabled {
			if err := e.startRouteListener(target); err != nil {
				return Route{}, err
			}
		}
	}

	_ = e.saveRoutesLocked()
	return target.Snapshot(target.Domain), nil
}

// DeleteRoute stops and removes a secondary route.
func (e *Engine) DeleteRoute(id int) error {
	e.routesMu.Lock()
	defer e.routesMu.Unlock()

	idx := -1
	for i, r := range e.routes {
		if r.ID == id {
			if r.IsPrimary {
				return fmt.Errorf("cannot delete Primary Route #1 (edit its Origin IP/Port instead)")
			}
			idx = i
			e.stopRouteListener(r)
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("route #%d not found", id)
	}

	e.routes = append(e.routes[:idx], e.routes[idx+1:]...)
	return e.saveRoutesLocked()
}

// PingOrigin checks TCP connectivity and latency (in ms) to a route's Origin Server.
func (e *Engine) PingOrigin(id int) (Route, error) {
	e.routesMu.RLock()
	var target *Route
	for _, r := range e.routes {
		if r.ID == id {
			target = r
			break
		}
	}
	e.routesMu.RUnlock()

	if target == nil {
		return Route{}, fmt.Errorf("route #%d not found", id)
	}

	addr := fmt.Sprintf("%s:%d", target.OriginIP, target.OriginPort)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 2500*time.Millisecond)
	elapsed := time.Since(start).Milliseconds()
	if elapsed == 0 && err == nil {
		elapsed = 1
	}

	target.statusMu.Lock()
	if err != nil {
		target.originStatus = "OFFLINE"
		atomic.StoreInt64(&target.latencyMs, -1)
	} else {
		_ = conn.Close()
		target.originStatus = "ONLINE"
		atomic.StoreInt64(&target.latencyMs, elapsed)
	}
	target.statusMu.Unlock()

	return target.Snapshot(target.Domain), nil
}

// LookupRoute finds a protected route by Origin IP and optional Origin Port (used by Public Lookup panel).
func (e *Engine) LookupRoute(originIP string, originPort int) (Route, bool) {
	originIP = strings.TrimSpace(originIP)
	e.routesMu.RLock()
	defer e.routesMu.RUnlock()

	for _, r := range e.routes {
		if strings.EqualFold(r.OriginIP, originIP) {
			if originPort <= 0 || r.OriginPort == originPort {
				return r.Snapshot(r.Domain), true
			}
		}
	}
	return Route{}, false
}
