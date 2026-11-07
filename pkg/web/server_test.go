package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"firewall/pkg/config"
	"firewall/pkg/proxy"
)

func TestWebControlPlaneEndpoints(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.txt")
	cfgMgr, err := config.NewManager(cfgPath)
	if err != nil {
		t.Fatalf("failed to create config manager: %v", err)
	}
	cfgMgr.Update(func(c *config.Config) {
		c.KernelBlockEnabled = false
		c.WhitelistFile = filepath.Join(tmpDir, "whitelist.txt")
		c.BlacklistFile = filepath.Join(tmpDir, "blacklist.txt")
		c.GeoIPDataDir = filepath.Join(tmpDir, "geoip")
	})

	engine := proxy.NewEngine(cfgMgr)
	defer engine.Stop()

	srv := NewServer(engine)

	// 1. Test GET /api/overview
	reqOv := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	recOv := httptest.NewRecorder()
	srv.handleOverview(recOv, reqOv)
	if recOv.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/overview, got %d", recOv.Code)
	}

	// 2. Test POST /api/config (Toggle GeoIP ON, Lockdown ON, Proxy Protocol v1)
	cfgBody := map[string]interface{}{
		"geoip_enabled":           true,
		"geoip_allowed_countries": "VN,SG",
		"geoip_direction":         "both",
		"proxy_protocol":          "v1",
		"lockdown_whitelist_only": true,
	}
	rawCfg, _ := json.Marshal(cfgBody)
	reqCfg := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewReader(rawCfg))
	recCfg := httptest.NewRecorder()
	srv.handleConfig(recCfg, reqCfg)
	if recCfg.Code != http.StatusOK {
		t.Fatalf("expected 200 on /api/config, got %d: %s", recCfg.Code, recCfg.Body.String())
	}

	updated := cfgMgr.Get()
	if !updated.GeoIPEnabled || updated.ProxyProtocol != "v1" || !updated.LockdownWhitelistOnly {
		t.Fatalf("config toggles did not persist: %+v", updated)
	}

	// 3. Test POST /api/routes (Provision Origin Server -> FW Endpoint)
	routeBody := map[string]interface{}{
		"name":            "Test Game Node 2",
		"domain":          "anti.test.vn",
		"listen_port":     0, // auto-assign 20001+
		"origin_ip":       "103.142.10.25",
		"origin_port":     14445,
		"protocol":        "GAME-NRO",
		"proxy_protocol":  "v1",
		"inspection_mode": "strict_game",
	}
	rawRoute, _ := json.Marshal(routeBody)
	reqRoute := httptest.NewRequest(http.MethodPost, "/api/routes", bytes.NewReader(rawRoute))
	recRoute := httptest.NewRecorder()
	srv.handleRoutes(recRoute, reqRoute)
	if recRoute.Code != http.StatusOK {
		t.Fatalf("expected 200 on POST /api/routes, got %d: %s", recRoute.Code, recRoute.Body.String())
	}

	// 4. Test POST /api/lookup (Find endpoint by Origin IP + Port)
	lookupBody := map[string]interface{}{
		"origin_ip":   "103.142.10.25",
		"origin_port": 14445,
	}
	rawLookup, _ := json.Marshal(lookupBody)
	reqLookup := httptest.NewRequest(http.MethodPost, "/api/lookup", bytes.NewReader(rawLookup))
	recLookup := httptest.NewRecorder()
	srv.handleLookup(recLookup, reqLookup)
	if recLookup.Code != http.StatusOK {
		t.Fatalf("expected 200 on POST /api/lookup, got %d: %s", recLookup.Code, recLookup.Body.String())
	}
}
