package limiter

import (
	"testing"

	"firewall/pkg/config"
)

func TestLimiter(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MaxConnPerExternalIP = 2
	cfg.MaxConnRateExternal = 2

	l := New()

	ip := "203.0.113.195"

	// 1st connection: allowed
	allowed1, _ := l.CheckAndRecordConnection(ip, false, cfg)
	if !allowed1 {
		t.Fatalf("first connection should be allowed")
	}

	// 2nd connection: allowed
	allowed2, _ := l.CheckAndRecordConnection(ip, false, cfg)
	if !allowed2 {
		t.Fatalf("second connection should be allowed")
	}

	// 3rd concurrent connection: rejected
	allowed3, reason := l.CheckAndRecordConnection(ip, false, cfg)
	if allowed3 {
		t.Fatalf("third connection should be rejected due to max conns, got allowed with reason: %s", reason)
	}

	// Release 1 connection
	l.ReleaseConnection(ip)

	// Now active count is 1, but rate limit in same second is 2 (already used 2).
	// So new connection in same second will hit rate limit
	allowed4, _ := l.CheckAndRecordConnection(ip, false, cfg)
	if allowed4 {
		t.Fatalf("fourth connection should be rejected due to rate limit")
	}
}
