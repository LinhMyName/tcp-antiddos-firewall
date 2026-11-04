package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"firewall/pkg/config"
	"firewall/pkg/proxy"
)

func main() {
	configPath := flag.String("config", "config.txt", "Path to configuration file")
	listenAddr := flag.String("listen", "", "Override listen address (host:port, e.g. 0.0.0.0:9999)")
	backendAddr := flag.String("backend", "", "Override backend game server address (host:port, e.g. 192.168.1.50:14445)")
	whitelistPath := flag.String("whitelist", "", "Path to whitelist file (default: whitelist.txt)")
	blacklistPath := flag.String("blacklist", "", "Path to blacklist file (default: blacklist.txt)")
	flag.Parse()

	// 1. Load configuration
	cfgMgr, err := config.NewManager(*configPath)
	if err != nil {
		fmt.Printf("[FATAL] Failed to initialize configuration: %v\n", err)
		os.Exit(1)
	}

	cfg := cfgMgr.Get()

	// Apply CLI overrides if provided
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

	if *whitelistPath != "" {
		cfg.WhitelistFile = *whitelistPath
	}
	if *blacklistPath != "" {
		cfg.BlacklistFile = *blacklistPath
	}

	// 2. Initialize Proxy Engine
	engine := proxy.NewEngine(cfgMgr)

	// 3. Setup Graceful Shutdown Hook
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[FIREWALL] Shutting down cleanly... Releasing resources.")
		engine.Stop()
		os.Exit(0)
	}()

	// 4. Start Firewall Proxy
	if err := engine.Start(); err != nil {
		fmt.Printf("[FATAL] Firewall engine error: %v\n", err)
		os.Exit(1)
	}
}
