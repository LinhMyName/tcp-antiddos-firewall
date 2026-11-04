package signatures

import (
	"bytes"
	"fmt"
	"math"
	"strings"
)

// ThreatLevel categorizes severity of signature match.
type ThreatLevel string

const (
	ThreatLow      ThreatLevel = "LOW"
	ThreatMedium   ThreatLevel = "MEDIUM"
	ThreatHigh     ThreatLevel = "HIGH"
	ThreatCritical ThreatLevel = "CRITICAL"
)

// MatchResult contains the detection result.
type MatchResult struct {
	Matched     bool
	Signature   string
	Description string
	Threat      ThreatLevel
	Penalty     int
}

// SignatureEngine analyzes initial TCP packet payloads for known attacks and proxy tunneling.
type SignatureEngine struct{}

// New creates a new SignatureEngine.
func New() *SignatureEngine {
	return &SignatureEngine{}
}

// InspectFirstPacket inspects the initial payload of a TCP connection.
// Whitelisted connections should skip this inspection.
func (e *SignatureEngine) InspectFirstPacket(payload []byte) MatchResult {
	if len(payload) == 0 {
		return MatchResult{}
	}

	// 1. SOCKS4 / SOCKS4a Proxy Detection (Critical: Proxy botnet / Socket ngoai)
	if payload[0] == 0x04 {
		if len(payload) >= 8 && payload[4] == 0 && payload[5] == 0 && payload[6] == 0 && payload[7] != 0 {
			return MatchResult{
				Matched:     true,
				Signature:   "SOCKS4A_PROXY",
				Description: "SOCKS4a proxy detected (socket ngoai)",
				Threat:      ThreatCritical,
				Penalty:     150,
			}
		}
		return MatchResult{
			Matched:     true,
			Signature:   "SOCKS4_PROXY",
			Description: "SOCKS4 proxy detected (socket ngoai)",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 2. SOCKS5 Proxy Detection (Critical: Proxy botnet / Socket ngoai)
	if payload[0] == 0x05 {
		if len(payload) >= 2 {
			numMethods := int(payload[1])
			if len(payload) >= 2+numMethods {
				return MatchResult{
					Matched:     true,
					Signature:   "SOCKS5_PROXY",
					Description: "SOCKS5 proxy handshake detected (socket ngoai)",
					Threat:      ThreatCritical,
					Penalty:     150,
				}
			}
		}
		return MatchResult{
			Matched:     true,
			Signature:   "SOCKS5_AUTH_PROXY",
			Description: "SOCKS5 authentication detected (socket ngoai)",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 3. HTTP CONNECT Proxy Tunneling
	if bytes.HasPrefix(payload, []byte("CONNECT ")) {
		return MatchResult{
			Matched:     true,
			Signature:   "HTTP_CONNECT_PROXY",
			Description: "HTTP CONNECT proxy detected (socket ngoai)",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 4. Shadowsocks Proxy Handshake
	if len(payload) >= 32 && (bytes.Contains(payload[:16], []byte{0x00, 0x00}) && bytes.Contains(payload, []byte{0x03})) {
		if payload[0] == 0x01 || payload[0] == 0x03 || payload[0] == 0x04 {
			return MatchResult{
				Matched:     true,
				Signature:   "SHADOWSOCKS_PROXY",
				Description: "Shadowsocks proxy pattern detected",
				Threat:      ThreatCritical,
				Penalty:     150,
			}
		}
	}

	// 5. 0xFF Protocol Flood (Game server query spoof / Half-life / Q3 engine exploit)
	if len(payload) >= 4 && payload[0] == 0xFF && payload[1] == 0xFF && payload[2] == 0xFF && payload[3] == 0xFF {
		return MatchResult{
			Matched:     true,
			Signature:   "PROTOCOL_0xFF_FLOOD",
			Description: "0xFF Out-of-band protocol flood",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 6. Null Byte Flood (all 0x00)
	if len(payload) >= 8 && isAllByte(payload, 0x00) {
		return MatchResult{
			Matched:     true,
			Signature:   "NULL_BYTE_FLOOD",
			Description: "Payload contains exclusively null bytes",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 7. Uniform Byte Flood (all bytes identical)
	if len(payload) >= 16 && isUniformBytes(payload) {
		return MatchResult{
			Matched:     true,
			Signature:   "UNIFORM_BYTE_FLOOD",
			Description: fmt.Sprintf("Uniform byte flood (byte=0x%02X)", payload[0]),
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 8. Single Byte Flood
	if len(payload) == 1 {
		return MatchResult{
			Matched:     true,
			Signature:   "SINGLE_BYTE_FLOOD",
			Description: "Single-byte fragment flood",
			Threat:      ThreatMedium,
			Penalty:     40,
		}
	}

	// 9. Character Repeat Flood (e.g. "XXXXXXXX" or "AAAAAAAA")
	if len(payload) >= 32 && isRepeatedChar(payload) {
		return MatchResult{
			Matched:     true,
			Signature:   "CHAR_REPEAT_FLOOD_X",
			Description: "Repeated character pattern flood",
			Threat:      ThreatHigh,
			Penalty:     80,
		}
	}

	// 10. LOIC HTTP Flood
	if bytes.Contains(payload, []byte("GET / HTTP/1.0\r\n\r\n")) || bytes.Contains(payload, []byte("Accept: */*\r\n\r\n")) {
		return MatchResult{
			Matched:     true,
			Signature:   "LOIC_HTTP_FLOOD",
			Description: "LOIC HTTP flood signature",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 11. HOIC Post Flood
	if bytes.Contains(payload, []byte("User-Agent: HOIC")) || bytes.Contains(payload, []byte("X-Forwarded-For: 127.0.0.1\r\nHost: ")) {
		return MatchResult{
			Matched:     true,
			Signature:   "HOIC_POST_FLOOD",
			Description: "HOIC HTTP flood signature",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 12. Slowloris Header Fragment
	if bytes.HasPrefix(payload, []byte("GET ")) || bytes.HasPrefix(payload, []byte("POST ")) {
		if !bytes.Contains(payload, []byte("\r\n\r\n")) && len(payload) < 64 {
			return MatchResult{
				Matched:     true,
				Signature:   "SLOWLORIS_FRAGMENT",
				Description: "Slowloris incomplete header fragment",
				Threat:      ThreatMedium,
				Penalty:     50,
			}
		}
	}

	// 13. R-U-Dead-Yet (RUDY) Slow POST
	if bytes.Contains(payload, []byte("Content-Type: application/x-www-form-urlencoded")) && bytes.Contains(payload, []byte("Content-Length: 1000")) {
		return MatchResult{
			Matched:     true,
			Signature:   "RUDY_SLOW_POST",
			Description: "RUDY slow POST attack detected",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 14. MHDDoS Attack Payload
	if bytes.Contains(payload, []byte("MHDDoS")) || bytes.Contains(payload, []byte("mhk-ddos")) {
		return MatchResult{
			Matched:     true,
			Signature:   "MHDDOS_PAYLOAD",
			Description: "MHDDoS botnet toolkit payload",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 15. GoldenEye Keep-Alive Abuse
	if bytes.Contains(payload, []byte("Keep-Alive: 115")) || bytes.Contains(payload, []byte("Cache-Control: no-cache\r\nKeep-Alive: 300")) {
		return MatchResult{
			Matched:     true,
			Signature:   "GOLDENEYE_KEEPALIVE",
			Description: "GoldenEye keep-alive exhaustion",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 16. Tor's Hammer
	if bytes.Contains(payload, []byte(".0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)")) && bytes.Contains(payload, []byte("POST ")) {
		return MatchResult{
			Matched:     true,
			Signature:   "TORSHAMMER_SLOW",
			Description: "Tor's Hammer DoS signature",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 17. Xerxes DoS
	if len(payload) >= 16 && bytes.HasPrefix(payload, []byte("\x00\x01\x02\x03\x04\x05\x06\x07")) {
		return MatchResult{
			Matched:     true,
			Signature:   "XERXES_DOS",
			Description: "Xerxes incremental byte flood",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 18. HTTP Pipeline Abuse
	payloadStr := string(payload)
	if strings.Count(payloadStr, "GET ") > 4 || strings.Count(payloadStr, "POST ") > 4 {
		return MatchResult{
			Matched:     true,
			Signature:   "HTTP_PIPELINE_ABUSE",
			Description: "Excessive pipelined HTTP requests",
			Threat:      ThreatHigh,
			Penalty:     80,
		}
	}

	// 19. Malformed HTTP (HTTP 1.1 without Host header)
	if (strings.HasPrefix(payloadStr, "GET ") || strings.HasPrefix(payloadStr, "POST ")) && strings.Contains(payloadStr, "HTTP/1.1") {
		if !strings.Contains(payloadStr, "Host:") && !strings.Contains(payloadStr, "host:") {
			return MatchResult{
				Matched:     true,
				Signature:   "MALFORMED_HTTP_NO_HOST",
				Description: "HTTP/1.1 request missing Host header",
				Threat:      ThreatMedium,
				Penalty:     50,
			}
		}
	}

	// 20. Hammer Head Flood
	if bytes.Contains(payload, []byte("HAMMER_HEAD")) || bytes.Contains(payload, []byte("T50-DDOS")) {
		return MatchResult{
			Matched:     true,
			Signature:   "HAMMER_HEAD_FLOOD",
			Description: "Hammer Head flood tool signature",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 21. Custom Tool Dead Signature
	if bytes.Contains(payload, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		return MatchResult{
			Matched:     true,
			Signature:   "CUSTOM_TOOL_DEAD",
			Description: "DeadBeef signature tool detected",
			Threat:      ThreatHigh,
			Penalty:     80,
		}
	}

	// 22. Memcached Amplification / Reflection
	if len(payload) >= 4 && (bytes.HasPrefix(payload, []byte("stats\r\n")) || bytes.HasPrefix(payload, []byte("\x00\x00\x00\x00\x00\x01\x00\x00"))) {
		return MatchResult{
			Matched:     true,
			Signature:   "MEMCACHED_REFLECTION",
			Description: "Memcached amplification / reflection attempt",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 23. DNS Amplification Reflection
	if len(payload) >= 12 && payload[2]&0x80 == 0 && bytes.Contains(payload, []byte("\x00\x00\xff\x00\x01")) {
		return MatchResult{
			Matched:     true,
			Signature:   "DNS_AMPLIFICATION",
			Description: "DNS ANY query amplification flood",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 24. NTP Amplification
	if len(payload) >= 4 && (payload[0] == 0x17 || payload[0] == 0x27) && payload[1] == 0x00 {
		return MatchResult{
			Matched:     true,
			Signature:   "NTP_AMPLIFICATION",
			Description: "NTP Monlist amplification flood",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 25. SSDP Reflection
	if bytes.Contains(payload, []byte("M-SEARCH * HTTP/1.1")) && bytes.Contains(payload, []byte("ssdp:discover")) {
		return MatchResult{
			Matched:     true,
			Signature:   "SSDP_REFLECTION",
			Description: "SSDP amplification reflection flood",
			Threat:      ThreatCritical,
			Penalty:     150,
		}
	}

	// 26. SYN-ACK Reflection
	if len(payload) >= 20 && payload[13]&0x12 == 0x12 { // SYN + ACK flags in raw segment
		return MatchResult{
			Matched:     true,
			Signature:   "SYNACK_REFLECTION",
			Description: "SYN-ACK reflection attack",
			Threat:      ThreatHigh,
			Penalty:     100,
		}
	}

	// 27. Low Entropy Flood (repetitive pattern / fill)
	if len(payload) >= 64 {
		entropy := calculateShannonEntropy(payload)
		if entropy < 0.3 {
			return MatchResult{
				Matched:     true,
				Signature:   "LOW_ENTROPY_FLOOD",
				Description: fmt.Sprintf("Low entropy flood (entropy=%.2f)", entropy),
				Threat:      ThreatHigh,
				Penalty:     90,
			}
		}
		// 28. High Entropy Random Flood (random junk flood without protocol structure)
		if entropy > 7.95 && len(payload) > 512 {
			return MatchResult{
				Matched:     true,
				Signature:   "HIGH_ENTROPY_RANDOM",
				Description: fmt.Sprintf("Synthetic high entropy random flood (entropy=%.2f)", entropy),
				Threat:      ThreatMedium,
				Penalty:     60,
			}
		}
	}

	return MatchResult{}
}

func calculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	entropy := 0.0
	total := float64(len(data))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func isAllByte(data []byte, target byte) bool {
	for _, b := range data {
		if b != target {
			return false
		}
	}
	return true
}

func isUniformBytes(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	first := data[0]
	for _, b := range data[1:] {
		if b != first {
			return false
		}
	}
	return true
}

func isRepeatedChar(data []byte) bool {
	first := data[0]
	same := 0
	for _, b := range data {
		if b == first {
			same++
		}
	}
	return float64(same)/float64(len(data)) > 0.9
}
