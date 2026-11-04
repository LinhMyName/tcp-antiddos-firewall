package signatures

import (
	"testing"
)

func TestSignatures(t *testing.T) {
	engine := New()

	tests := []struct {
		name      string
		payload   []byte
		wantMatch bool
		wantSig   string
	}{
		{
			name:      "Clean legitimate client handshake",
			payload:   []byte("LOGIN_GAME_CLIENT_V1\n"),
			wantMatch: false,
		},
		{
			name:      "SOCKS4 Proxy detection",
			payload:   []byte{0x04, 0x01, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04, 0x00},
			wantMatch: true,
			wantSig:   "SOCKS4_PROXY",
		},
		{
			name:      "SOCKS5 Proxy detection",
			payload:   []byte{0x05, 0x02, 0x00, 0x02},
			wantMatch: true,
			wantSig:   "SOCKS5_PROXY",
		},
		{
			name:      "HTTP CONNECT Proxy tunnel",
			payload:   []byte("CONNECT 1.2.3.4:443 HTTP/1.1\r\n\r\n"),
			wantMatch: true,
			wantSig:   "HTTP_CONNECT_PROXY",
		},
		{
			name:      "LOIC HTTP Flood",
			payload:   []byte("GET / HTTP/1.0\r\n\r\n"),
			wantMatch: true,
			wantSig:   "LOIC_HTTP_FLOOD",
		},
		{
			name:      "0xFF Protocol Flood",
			payload:   []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F},
			wantMatch: true,
			wantSig:   "PROTOCOL_0xFF_FLOOD",
		},
		{
			name:      "Null Byte Flood",
			payload:   make([]byte, 32),
			wantMatch: true,
			wantSig:   "NULL_BYTE_FLOOD",
		},
		{
			name:      "Uniform Byte Flood",
			payload:   []byte("AAAAAAAAAAAAAAAAAAAA"),
			wantMatch: true,
			wantSig:   "UNIFORM_BYTE_FLOOD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := engine.InspectFirstPacket(tt.payload)
			if res.Matched != tt.wantMatch {
				t.Fatalf("expected matched=%v, got %v", tt.wantMatch, res.Matched)
			}
			if tt.wantMatch && res.Signature != tt.wantSig {
				t.Fatalf("expected signature=%s, got %s", tt.wantSig, res.Signature)
			}
		})
	}
}
