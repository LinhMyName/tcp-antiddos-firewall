package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"firewall/pkg/config"
	"firewall/pkg/proxy"
	"firewall/pkg/web"
)

func main() {
	configPath := flag.String("config", "config.txt", "Path to configuration file")
	listenAddr := flag.String("listen", "", "Override listen address (host:port, e.g. 0.0.0.0:9999)")
	backendAddr := flag.String("backend", "", "Override backend game server address (host:port, e.g. 192.168.1.50:14445)")
	webAddr := flag.String("web", "", "Override Web Control Plane address (host:port, e.g. 0.0.0.0:8080, or 'off')")
	whitelistPath := flag.String("whitelist", "", "Path to whitelist file (default: whitelist.txt)")
	blacklistPath := flag.String("blacklist", "", "Path to blacklist file (default: blacklist.txt)")
	proxyProto := flag.String("proxy-protocol", "", "Override proxy protocol mode to send client IP (off, v1, v2)")
	geoipFlag := flag.String("geoip", "", "Enable/disable GeoIP international blocker (true/false)")
	countriesFlag := flag.String("countries", "", "Allowed ISO country codes separated by comma (e.g. VN or VN,SG,JP)")
	geoipDirFlag := flag.String("geoip-dir", "", "GeoIP filtering direction: both, in, out")
	flag.Parse()

	// 1. Load configuration
	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		fmt.Printf("[FATAL] Failed to initialize configuration: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI overrides if provided
	cfgMgr.Update(func(cfg *config.Config) {
		if *listenAddr != "" {
			host, portStr, err := net.SplitHostPort(*listenAddr)
			if err == nil {
				cfg.FirewallHost = host
				if p, err := strconv.Atoi(portStr); err == nil {
					cfg.FirewallPort = p
				}
			}
		}

		if *backendAddr != "" {
			host, portStr, err := net.SplitHostPort(*backendAddr)
			if err == nil {
				cfg.BackendHost = host
				if p, err := strconv.Atoi(portStr); err == nil {
					cfg.BackendPort = p
				}
			}
		}

		if *webAddr != "" {
			if strings.EqualFold(*webAddr, "off") || strings.EqualFold(*webAddr, "false") {
				cfg.WebEnabled = false
			} else {
				cfg.WebEnabled = true
				host, portStr, err := net.SplitHostPort(*webAddr)
				if err == nil {
					if host != "" {
						cfg.WebHost = host
					}
					if p, err := strconv.Atoi(portStr); err == nil && p > 0 {
						cfg.WebPort = p
					}
				} else if p, err := strconv.Atoi(*webAddr); err == nil && p > 0 {
					cfg.WebPort = p
				}
			}
		}

		if *whitelistPath != "" {
			cfg.WhitelistFile = *whitelistPath
		}
		if *blacklistPath != "" {
			cfg.BlacklistFile = *blacklistPath
		}
		if *proxyProto != "" {
			cfg.ProxyProtocol = *proxyProto
		}
		if *geoipFlag != "" {
			v := strings.ToLower(strings.TrimSpace(*geoipFlag))
			cfg.GeoIPEnabled = (v == "true" || v == "1" || v == "yes" || v == "on")
		}
		if *countriesFlag != "" {
			var list []string
			for _, p := range strings.Split(*countriesFlag, ",") {
				cc := strings.ToUpper(strings.TrimSpace(p))
				if cc != "" {
					list = append(list, cc)
				}
			}
			cfg.GeoIPAllowedCountries = list
			cfg.GeoIPEnabled = true
		}
		if *geoipDirFlag != "" {
			cfg.GeoIPDirection = strings.ToLower(strings.TrimSpace(*geoipDirFlag))
		}
	})

	// 2. Initialize Proxy Engine & Web Control Plane
	engine := proxy.NewEngine(cfgMgr)
	webSrv := web.NewServer(engine)

	cfg := cfgMgr.Get()
	if cfg.WebEnabled {
		if err := webSrv.Start(cfg.WebAddress()); err != nil {
			fmt.Printf("[WARN] Failed to start Web Control Plane on %s: %v\n", cfg.WebAddress(), err)
		}
	}

	// 3. Setup Graceful Shutdown Hook
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[FIREWALL] Shutting down cleanly... Releasing resources.")
		webSrv.Stop()
		engine.Stop()
		os.Exit(0)
	}()

	// 4. Start Firewall Proxy
	if err := engine.Start(); err != nil {
		fmt.Printf("[FATAL] Firewall engine error: %v\n", err)
		os.Exit(1)
	}
}
