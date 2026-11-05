package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// PROXY protocol v2 12-byte constant header signature
var v2Signature = []byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

// BuildProxyHeader constructs a standard HAProxy PROXY Protocol header (v1 or v2).
// It prepends the real client source IP & port so backend servers know the true client origin.
func BuildProxyHeader(protoVersion string, clientConn net.Conn, backendConn net.Conn) []byte {
	switch strings.ToLower(strings.TrimSpace(protoVersion)) {
	case "v1", "1":
		return buildProxyV1(clientConn, backendConn)
	case "v2", "2":
		return buildProxyV2(clientConn, backendConn)
	default:
		return nil
	}
}

func getEndpoints(clientConn net.Conn, backendConn net.Conn) (*net.TCPAddr, *net.TCPAddr) {
	var srcTCP, dstTCP *net.TCPAddr

	if clientConn != nil {
		if addr, ok := clientConn.RemoteAddr().(*net.TCPAddr); ok {
			srcTCP = addr
		} else if clientConn.RemoteAddr() != nil {
			host, portStr, err := net.SplitHostPort(clientConn.RemoteAddr().String())
			if err == nil {
				var port int
				fmt.Sscanf(portStr, "%d", &port)
				srcTCP = &net.TCPAddr{IP: net.ParseIP(host), Port: port}
			}
		}

		if addr, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
			dstTCP = addr
		} else if clientConn.LocalAddr() != nil {
			host, portStr, err := net.SplitHostPort(clientConn.LocalAddr().String())
			if err == nil {
				var port int
				fmt.Sscanf(portStr, "%d", &port)
				dstTCP = &net.TCPAddr{IP: net.ParseIP(host), Port: port}
			}
		}
	}

	// If destination IP is wildcard (0.0.0.0 or ::), fallback to backend connection local IP
	if dstTCP == nil || dstTCP.IP == nil || dstTCP.IP.IsUnspecified() {
		if backendConn != nil {
			if bAddr, ok := backendConn.LocalAddr().(*net.TCPAddr); ok && bAddr.IP != nil && !bAddr.IP.IsUnspecified() {
				port := 0
				if dstTCP != nil {
					port = dstTCP.Port
				}
				dstTCP = &net.TCPAddr{IP: bAddr.IP, Port: port}
			}
		}
	}

	if srcTCP == nil || srcTCP.IP == nil {
		srcTCP = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	}
	if dstTCP == nil || dstTCP.IP == nil {
		dstTCP = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	}

	return srcTCP, dstTCP
}

// buildProxyV1 generates text format: PROXY TCP4/TCP6 <src_ip> <dst_ip> <src_port> <dst_port>\r\n
func buildProxyV1(clientConn net.Conn, backendConn net.Conn) []byte {
	srcTCP, dstTCP := getEndpoints(clientConn, backendConn)

	srcIPv4 := srcTCP.IP.To4()
	dstIPv4 := dstTCP.IP.To4()

	if srcIPv4 != nil && dstIPv4 != nil {
		return []byte(fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n",
			srcIPv4.String(), dstIPv4.String(), srcTCP.Port, dstTCP.Port))
	}

	srcIPv6 := srcTCP.IP.To16()
	dstIPv6 := dstTCP.IP.To16()
	if srcIPv6 != nil && dstIPv6 != nil {
		return []byte(fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n",
			srcIPv6.String(), dstIPv6.String(), srcTCP.Port, dstTCP.Port))
	}

	return []byte("PROXY UNKNOWN\r\n")
}

// buildProxyV2 generates binary format: 16 bytes header + address block
func buildProxyV2(clientConn net.Conn, backendConn net.Conn) []byte {
	srcTCP, dstTCP := getEndpoints(clientConn, backendConn)

	srcIPv4 := srcTCP.IP.To4()
	dstIPv4 := dstTCP.IP.To4()

	if srcIPv4 != nil && dstIPv4 != nil {
		// IPv4: 16 bytes header + 12 bytes address = 28 bytes
		buf := make([]byte, 28)
		copy(buf[0:12], v2Signature)
		buf[12] = 0x21 // version 2, PROXY command
		buf[13] = 0x11 // AF_INET (IPv4), STREAM (TCP)
		binary.BigEndian.PutUint16(buf[14:16], 12)

		copy(buf[16:20], srcIPv4)
		copy(buf[20:24], dstIPv4)
		binary.BigEndian.PutUint16(buf[24:26], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(buf[26:28], uint16(dstTCP.Port))
		return buf
	}

	srcIPv6 := srcTCP.IP.To16()
	dstIPv6 := dstTCP.IP.To16()
	if srcIPv6 != nil && dstIPv6 != nil {
		// IPv6: 16 bytes header + 36 bytes address = 52 bytes
		buf := make([]byte, 52)
		copy(buf[0:12], v2Signature)
		buf[12] = 0x21 // version 2, PROXY command
		buf[13] = 0x21 // AF_INET6 (IPv6), STREAM (TCP)
		binary.BigEndian.PutUint16(buf[14:16], 36)

		copy(buf[16:32], srcIPv6)
		copy(buf[32:48], dstIPv6)
		binary.BigEndian.PutUint16(buf[48:50], uint16(srcTCP.Port))
		binary.BigEndian.PutUint16(buf[50:52], uint16(dstTCP.Port))
		return buf
	}

	// Fallback to local / unknown
	buf := make([]byte, 16)
	copy(buf[0:12], v2Signature)
	buf[12] = 0x20 // version 2, LOCAL command
	buf[13] = 0x00 // UNSPEC, UNSPEC
	binary.BigEndian.PutUint16(buf[14:16], 0)
	return buf
}
