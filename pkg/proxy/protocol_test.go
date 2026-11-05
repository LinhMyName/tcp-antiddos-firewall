package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

type mockConn struct {
	net.Conn
	remote net.Addr
	local  net.Addr
}

func (m *mockConn) RemoteAddr() net.Addr { return m.remote }
func (m *mockConn) LocalAddr() net.Addr  { return m.local }
func (m *mockConn) Close() error         { return nil }

func TestBuildProxyHeader_Off(t *testing.T) {
	header := BuildProxyHeader("off", nil, nil)
	if header != nil {
		t.Fatalf("expected nil for off, got %v", header)
	}
	header = BuildProxyHeader("", nil, nil)
	if header != nil {
		t.Fatalf("expected nil for empty, got %v", header)
	}
}

func TestBuildProxyHeader_V1(t *testing.T) {
	client := &mockConn{
		remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.195"), Port: 54321},
		local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9999},
	}
	backend := &mockConn{
		local: &net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 40000},
	}

	header := BuildProxyHeader("v1", client, backend)
	expected := "PROXY TCP4 203.0.113.195 198.51.100.1 54321 9999\r\n"
	if string(header) != expected {
		t.Fatalf("expected %q, got %q", expected, string(header))
	}
}

func TestBuildProxyHeader_V2(t *testing.T) {
	client := &mockConn{
		remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.195"), Port: 54321},
		local:  &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 9999},
	}
	backend := &mockConn{
		local: &net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 40000},
	}

	header := BuildProxyHeader("v2", client, backend)
	if len(header) != 28 {
		t.Fatalf("expected 28 bytes for IPv4 v2 header, got %d", len(header))
	}

	if !bytes.Equal(header[0:12], v2Signature) {
		t.Fatalf("signature mismatch")
	}

	if header[12] != 0x21 { // version 2, PROXY
		t.Fatalf("byte 12 expected 0x21, got 0x%02x", header[12])
	}
	if header[13] != 0x11 { // AF_INET, STREAM
		t.Fatalf("byte 13 expected 0x11, got 0x%02x", header[13])
	}

	addrLen := binary.BigEndian.Uint16(header[14:16])
	if addrLen != 12 {
		t.Fatalf("addrLen expected 12, got %d", addrLen)
	}

	srcIP := net.IP(header[16:20]).String()
	dstIP := net.IP(header[20:24]).String()
	srcPort := binary.BigEndian.Uint16(header[24:26])
	dstPort := binary.BigEndian.Uint16(header[26:28])

	if srcIP != "203.0.113.195" || dstIP != "198.51.100.1" || srcPort != 54321 || dstPort != 9999 {
		t.Fatalf("unmatched address fields: src=%s:%d, dst=%s:%d", srcIP, srcPort, dstIP, dstPort)
	}
}
