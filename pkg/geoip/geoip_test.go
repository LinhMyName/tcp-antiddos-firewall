package geoip

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGeoIP_VietnamOnly_InAndOut(t *testing.T) {
	tmpDir := t.TempDir()
	f := New()

	changed, count := f.SyncConfig(true, "both", []string{"VN"}, nil, tmpDir)
	if !changed || count == 0 {
		t.Fatalf("expected GeoIP SyncConfig to load VN ranges, got changed=%v, count=%d", changed, count)
	}

	// 1. Vietnam ISP IPs (Viettel, VNPT, FPT, DataCenter VN)
	vnIPs := []string{
		"14.162.50.21",   // VNPT
		"27.68.12.34",    // Viettel
		"113.161.72.10",  // VNPT
		"180.93.115.156", // Vietnam DC
		"171.224.10.5",   // Viettel
	}
	for _, ipStr := range vnIPs {
		ip := net.ParseIP(ipStr)
		if ok, cc, reason := f.CheckInbound(ip); !ok || cc != "VN" {
			t.Errorf("expected VN IP %s to be allowed inbound (cc=%s, reason=%s)", ipStr, cc, reason)
		}
		if ok, cc, reason := f.CheckOutbound(ip); !ok || cc != "VN" {
			t.Errorf("expected VN IP %s to be allowed outbound (cc=%s, reason=%s)", ipStr, cc, reason)
		}
	}

	// 2. International IPs (US, CN, RU, EU) -> Must be BLOCKED both IN and OUT
	intlIPs := []string{
		"8.8.8.8",        // US (Google)
		"1.1.1.1",        // AU/US (Cloudflare)
		"223.5.5.5",      // CN (Alibaba)
		"77.88.8.8",      // RU (Yandex)
		"185.199.108.15", // US/EU (GitHub)
	}
	for _, ipStr := range intlIPs {
		ip := net.ParseIP(ipStr)
		if ok, _, _ := f.CheckInbound(ip); ok {
			t.Errorf("expected international IP %s to be BLOCKED inbound", ipStr)
		}
		if ok, _, _ := f.CheckOutbound(ip); ok {
			t.Errorf("expected international IP %s to be BLOCKED outbound", ipStr)
		}
	}

	// 3. Localhost & Private LAN -> Always allowed
	localIPs := []string{"127.0.0.1", "192.168.1.50", "10.0.0.5", "100.64.10.1"}
	for _, ipStr := range localIPs {
		ip := net.ParseIP(ipStr)
		if ok, cc, _ := f.CheckInbound(ip); !ok || cc != "LOCAL" {
			t.Errorf("expected private IP %s to be allowed inbound, got ok=%v cc=%s", ipStr, ok, cc)
		}
		if ok, cc, _ := f.CheckOutbound(ip); !ok || cc != "LOCAL" {
			t.Errorf("expected private IP %s to be allowed outbound, got ok=%v cc=%s", ipStr, ok, cc)
		}
	}
}

func TestGeoIP_MultiCountryAndDirection(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock SG zone file in tmpDir
	sgZone := "103.11.200.0/22\n128.199.64.0/18\n"
	if err := os.WriteFile(filepath.Join(tmpDir, "sg.zone"), []byte(sgZone), 0644); err != nil {
		t.Fatalf("failed to write sg.zone: %v", err)
	}

	f := New()
	// Allow VN and SG, direction = "in" only
	f.SyncConfig(true, "in", []string{"VN", "SG"}, nil, tmpDir)

	sgIP := net.ParseIP("128.199.80.10")
	usIP := net.ParseIP("8.8.8.8")

	// SG IP allowed inbound
	if ok, cc, _ := f.CheckInbound(sgIP); !ok || cc != "SG" {
		t.Fatalf("expected SG IP allowed inbound, got ok=%v cc=%s", ok, cc)
	}

	// US IP blocked inbound
	if ok, _, _ := f.CheckInbound(usIP); ok {
		t.Fatalf("expected US IP blocked inbound")
	}

	// Because direction="in", outbound to US IP should be allowed
	if ok, _, _ := f.CheckOutbound(usIP); !ok {
		t.Fatalf("expected US IP allowed outbound when direction=in")
	}
}
