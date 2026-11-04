package acl

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestAccessControl(t *testing.T) {
	tmpDir := t.TempDir()
	wlPath := filepath.Join(tmpDir, "whitelist.txt")
	blPath := filepath.Join(tmpDir, "blacklist.txt")

	_ = os.WriteFile(wlPath, []byte("10.0.0.1\n192.168.1.0/24\n"), 0644)
	_ = os.WriteFile(blPath, []byte("1.2.3.4 # Known hacker\n172.16.0.0/16 # Abusive ISP\n"), 0644)

	ac := New(wlPath, blPath)

	// Whitelist tests
	if !ac.IsWhitelisted(net.ParseIP("10.0.0.1")) {
		t.Errorf("10.0.0.1 should be whitelisted")
	}
	if !ac.IsWhitelisted(net.ParseIP("192.168.1.55")) {
		t.Errorf("192.168.1.55 should be whitelisted via CIDR")
	}
	if ac.IsWhitelisted(net.ParseIP("8.8.8.8")) {
		t.Errorf("8.8.8.8 should not be whitelisted")
	}

	// Blacklist tests
	bl, reason := ac.IsBlacklisted(net.ParseIP("1.2.3.4"))
	if !bl || reason != "Known hacker" {
		t.Errorf("1.2.3.4 should be blacklisted with reason 'Known hacker', got bl=%v, reason=%s", bl, reason)
	}

	blSub, _ := ac.IsBlacklisted(net.ParseIP("172.16.5.10"))
	if !blSub {
		t.Errorf("172.16.5.10 should be blacklisted via /16 CIDR")
	}

	// Dynamic blacklist
	_ = ac.AddBlacklist("5.6.7.8", "DDoS bot")
	blDyn, dynReason := ac.IsBlacklisted(net.ParseIP("5.6.7.8"))
	if !blDyn || dynReason != "DDoS bot" {
		t.Errorf("5.6.7.8 should be dynamically blacklisted")
	}
}
