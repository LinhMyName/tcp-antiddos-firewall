package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"firewall/pkg/config"
	"firewall/pkg/proxy"
)

//go:embed static/*
var staticFS embed.FS

// Server is the HTTP Control Plane & Hacker Observability Dashboard.
type Server struct {
	engine  *proxy.Engine
	httpSrv *http.Server
}

// NewServer creates a new Web Control Plane server bound to the firewall engine.
func NewServer(engine *proxy.Engine) *Server {
	return &Server{
		engine: engine,
	}
}

// Start launches the HTTP server in the background.
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// REST API routes
	mux.HandleFunc("/api/overview", s.handleOverview)
	mux.HandleFunc("/api/routes", s.handleRoutes)
	mux.HandleFunc("/api/routes/ping", s.handleRoutePing)
	mux.HandleFunc("/api/lookup", s.handleLookup)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/acl", s.handleACL)
	mux.HandleFunc("/api/events/clear", s.handleClearEvents)

	// Embedded static Hacker UI
	subFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(subFS))
	mux.Handle("/", fileServer)

	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           corsMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("[WEB-ERROR] Control Plane failed on %s: %v\n", addr, err)
		}
	}()

	return nil
}

// Stop shuts down the HTTP server.
func (s *Server) Stop() {
	if s.httpSrv != nil {
		_ = s.httpSrv.Close()
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Admin-Key")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	cfg := s.engine.ConfigManager().Get()
	snap := s.engine.Stats().Snapshot()
	wlCount, blCount := s.engine.ACL().Counts()
	routes := s.engine.GetRoutes()

	resp := map[string]interface{}{
		"ok":        true,
		"timestamp": time.Now().Format("15:04:05"),
		"system": map[string]interface{}{
			"version":          "v3.8-CYBER-CORE",
			"os":               runtime.GOOS,
			"arch":             runtime.GOARCH,
			"goroutines":       runtime.NumGoroutine(),
			"uptime_sec":       snap.UptimeSec,
			"defense_mode":     s.engine.SurgeMode(),
			"has_admin_rights": s.engine.Kernel().HasAdminRights(),
			"kernel_rules":     s.engine.Kernel().ActiveRuleCount(),
			"geoip_summary":    s.engine.GeoIP().Summary(),
			"geoip_cidrs":      len(s.engine.GeoIP().AllowedCIDRs()),
		},
		"metrics": map[string]interface{}{
			"active_conns":     s.engine.ActiveConnections(),
			"max_global_conns": cfg.MaxGlobalActive,
			"total_conns":      snap.TotalConn,
			"blocked_conns":    snap.BlockedConn,
			"bytes_in":         snap.BytesIn,
			"bytes_out":        snap.BytesOut,
			"packets_in":       snap.PacketsIn,
			"packets_out":      snap.PacketsOut,
			"cur_mbps_in":      snap.CurMbpsIn,
			"cur_mbps_out":     snap.CurMbpsOut,
			"cur_pps_in":       snap.CurPPSIn,
			"cur_pps_out":      snap.CurPPSOut,
			"peak_mbps_in":     snap.PeakMbpsIn,
			"peak_pps_in":      snap.PeakPPSIn,
			"temp_blocked_ips": s.engine.BehaviorBlockedCount(),
			"blocked_subnets":  s.engine.BlockedSubnetsCount(),
			"whitelist_count":  wlCount,
			"blacklist_count":  blCount,
		},
		"config": map[string]interface{}{
			"firewall_host":             cfg.FirewallHost,
			"firewall_port":             cfg.FirewallPort,
			"backend_host":              cfg.BackendHost,
			"backend_port":              cfg.BackendPort,
			"web_port":                  cfg.WebPort,
			"web_public_domain":         cfg.WebPublicDomain,
			"proxy_protocol":            cfg.ProxyProtocol,
			"geoip_enabled":             cfg.GeoIPEnabled,
			"geoip_direction":           cfg.GeoIPDirection,
			"geoip_allowed_countries":    strings.Join(cfg.GeoIPAllowedCountries, ","),
			"geoip_blocked_countries":   strings.Join(cfg.GeoIPBlockedCountries, ","),
			"geoip_kernel_enforce":      cfg.GeoIPKernelEnforce,
			"kernel_block_enabled":      cfg.KernelBlockEnabled,
			"layer_signature_enabled":   cfg.LayerSignatureEnabled,
			"layer_halfopen_enabled":    cfg.LayerHalfOpenEnabled,
			"layer_slowloris_enabled":   cfg.LayerSlowlorisEnabled,
			"layer_subnet_enabled":      cfg.LayerSubnetEnabled,
			"layer_surge_enabled":       cfg.LayerSurgeEnabled,
			"lockdown_whitelist_only":   cfg.LockdownWhitelistOnly,
			"max_conn_per_external_ip":  cfg.MaxConnPerExternalIP,
			"max_conn_rate_external":    cfg.MaxConnRateExternal,
			"max_msgs_per_sec_external": cfg.MaxMsgsPerSecExternal,
			"max_global_conn_rate":      cfg.MaxGlobalConnRate,
			"max_global_active":         cfg.MaxGlobalActive,
		},
		"routes":       routes,
		"history":      snap.History,
		"layer_counts": snap.LayerCounts,
		"events":       snap.Events,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":     true,
			"routes": s.engine.GetRoutes(),
		})

	case http.MethodPost:
		var req struct {
			Name           string `json:"name"`
			Domain         string `json:"domain"`
			ListenPort     int    `json:"listen_port"`
			OriginIP       string `json:"origin_ip"`
			OriginPort     int    `json:"origin_port"`
			Protocol       string `json:"protocol"`
			ProxyProtocol  string `json:"proxy_protocol"`
			InspectionMode string `json:"inspection_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "Invalid JSON payload"})
			return
		}
		route, err := s.engine.AddRoute(
			req.Name, req.Domain, req.ListenPort,
			req.OriginIP, req.OriginPort,
			req.Protocol, req.ProxyProtocol, req.InspectionMode,
		)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "route": route})

	case http.MethodPatch:
		var req struct {
			ID             int    `json:"id"`
			Name           string `json:"name"`
			Domain         string `json:"domain"`
			ListenPort     int    `json:"listen_port"`
			OriginIP       string `json:"origin_ip"`
			OriginPort     int    `json:"origin_port"`
			Protocol       string `json:"protocol"`
			ProxyProtocol  string `json:"proxy_protocol"`
			InspectionMode string `json:"inspection_mode"`
			Enabled        *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "Invalid JSON payload"})
			return
		}
		route, err := s.engine.UpdateRoute(
			req.ID, req.Name, req.Domain, req.ListenPort,
			req.OriginIP, req.OriginPort,
			req.Protocol, req.ProxyProtocol, req.InspectionMode,
			req.Enabled,
		)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "route": route})

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		if id <= 0 {
			var body struct {
				ID int `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			id = body.ID
		}
		if err := s.engine.DeleteRoute(id); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "Method not allowed"})
	}
}

func (s *Server) handleRoutePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "Method not allowed"})
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "Invalid route ID"})
		return
	}
	route, err := s.engine.PingOrigin(req.ID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "route": route})
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "Method not allowed"})
		return
	}
	var req struct {
		OriginIP   string `json:"origin_ip"`
		OriginPort int    `json:"origin_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.OriginIP) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "Origin IP is required"})
		return
	}

	route, found := s.engine.LookupRoute(req.OriginIP, req.OriginPort)
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"ok":    false,
			"error": fmt.Sprintf("No protected firewall endpoint linked to origin %s:%d", req.OriginIP, req.OriginPort),
		})
		return
	}

	snap := s.engine.Stats().Snapshot()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":      true,
		"route":   route,
		"history": snap.History,
		"metrics": map[string]interface{}{
			"cur_mbps_in":  snap.CurMbpsIn,
			"cur_mbps_out": snap.CurMbpsOut,
			"cur_pps_in":   snap.CurPPSIn,
			"cur_pps_out":  snap.CurPPSOut,
		},
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "Method not allowed"})
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "Invalid JSON body"})
		return
	}

	err := s.engine.ApplyConfigMutation(func(c *config.Config) {
		if v, ok := req["backend_host"].(string); ok && strings.TrimSpace(v) != "" {
			c.BackendHost = strings.TrimSpace(v)
		}
		if v, ok := toInt(req["backend_port"]); ok && v > 0 && v <= 65535 {
			c.BackendPort = v
		}
		if v, ok := req["web_public_domain"].(string); ok {
			c.WebPublicDomain = strings.TrimSpace(v)
		}
		if v, ok := req["proxy_protocol"].(string); ok {
			val := strings.ToLower(strings.TrimSpace(v))
			if val == "v1" || val == "v2" {
				c.ProxyProtocol = val
			} else {
				c.ProxyProtocol = "off"
			}
		}
		if v, ok := req["geoip_enabled"].(bool); ok {
			c.GeoIPEnabled = v
		}
		if v, ok := req["geoip_direction"].(string); ok {
			dir := strings.ToLower(strings.TrimSpace(v))
			if dir == "in" || dir == "out" || dir == "both" {
				c.GeoIPDirection = dir
			}
		}
		if v, ok := req["geoip_allowed_countries"].(string); ok {
			c.GeoIPAllowedCountries = splitCSVUpper(v)
		}
		if v, ok := req["geoip_blocked_countries"].(string); ok {
			c.GeoIPBlockedCountries = splitCSVUpper(v)
		}
		if v, ok := req["geoip_kernel_enforce"].(bool); ok {
			c.GeoIPKernelEnforce = v
		}
		if v, ok := req["kernel_block_enabled"].(bool); ok {
			c.KernelBlockEnabled = v
		}
		if v, ok := req["layer_signature_enabled"].(bool); ok {
			c.LayerSignatureEnabled = v
		}
		if v, ok := req["layer_halfopen_enabled"].(bool); ok {
			c.LayerHalfOpenEnabled = v
		}
		if v, ok := req["layer_slowloris_enabled"].(bool); ok {
			c.LayerSlowlorisEnabled = v
		}
		if v, ok := req["layer_subnet_enabled"].(bool); ok {
			c.LayerSubnetEnabled = v
		}
		if v, ok := req["layer_surge_enabled"].(bool); ok {
			c.LayerSurgeEnabled = v
		}
		if v, ok := req["lockdown_whitelist_only"].(bool); ok {
			c.LockdownWhitelistOnly = v
		}
		if v, ok := toInt(req["max_conn_per_external_ip"]); ok && v > 0 {
			c.MaxConnPerExternalIP = v
		}
		if v, ok := toInt(req["max_conn_rate_external"]); ok && v > 0 {
			c.MaxConnRateExternal = v
		}
		if v, ok := toInt(req["max_msgs_per_sec_external"]); ok && v > 0 {
			c.MaxMsgsPerSecExternal = v
		}
		if v, ok := toInt(req["max_global_conn_rate"]); ok && v > 0 {
			c.MaxGlobalConnRate = v
		}
		if v, ok := toInt(req["max_global_active"]); ok && v > 0 {
			c.MaxGlobalActive = v
		}
	})

	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":            true,
		"geoip_summary": s.engine.GeoIP().Summary(),
	})
}

func (s *Server) handleACL(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":        true,
			"whitelist": s.engine.ACL().WhitelistEntries(),
			"blacklist": s.engine.ACL().BlacklistEntries(),
		})

	case http.MethodPost:
		var req struct {
			List   string `json:"list"`   // "whitelist" or "blacklist"
			Action string `json:"action"` // "add" or "remove"
			Target string `json:"target"` // IP or CIDR
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "Invalid JSON body"})
			return
		}
		target := strings.TrimSpace(req.Target)
		if target == "" {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": "IP or CIDR is required"})
			return
		}

		var err error
		if req.List == "whitelist" {
			if req.Action == "remove" {
				err = s.engine.ACL().RemoveWhitelist(target)
			} else {
				err = s.engine.ACL().AddWhitelist(target)
			}
		} else if req.List == "blacklist" {
			if req.Action == "remove" {
				err = s.engine.ACL().RemoveBlacklist(target)
				_ = s.engine.Kernel().UnblockIP(target)
			} else {
				reason := strings.TrimSpace(req.Reason)
				if reason == "" {
					reason = "Manual block via Cyber Control Plane"
				}
				err = s.engine.ACL().AddBlacklist(target, reason)
				if s.engine.ConfigManager().Get().KernelBlockEnabled {
					_ = s.engine.Kernel().BlockIP(target, reason)
				}
			}
		} else {
			err = fmt.Errorf("unknown list '%s'", req.List)
		}

		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"ok":        true,
			"whitelist": s.engine.ACL().WhitelistEntries(),
			"blacklist": s.engine.ACL().BlacklistEntries(),
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "Method not allowed"})
	}
}

func (s *Server) handleClearEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{"ok": false, "error": "Method not allowed"})
		return
	}
	s.engine.Stats().ClearEvents()
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func splitCSVUpper(val string) []string {
	val = strings.TrimSpace(val)
	if val == "" || strings.EqualFold(val, "off") || strings.EqualFold(val, "none") {
		return nil
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		cc := strings.ToUpper(strings.TrimSpace(p))
		if cc != "" {
			out = append(out, cc)
		}
	}
	return out
}

func toInt(v interface{}) (int, bool) {
	switch val := v.(type) {
	case float64:
		return int(val), true
	case int:
		return val, true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(val))
		return n, err == nil
	default:
		return 0, false
	}
}
