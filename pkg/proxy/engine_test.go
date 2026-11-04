package proxy

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"firewall/pkg/config"
)

func TestProxyEngineEndToEnd(t *testing.T) {
	// 1. Start mock game backend server
	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start backend mock: %v", err)
	}
	defer backendListener.Close()

	backendAddr := backendListener.Addr().(*net.TCPAddr)

	go func() {
		for {
			conn, err := backendListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					c.Write([]byte("ECHO: " + line))
				}
			}(conn)
		}
	}()

	// 2. Prepare firewall config
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.txt")
	wlFile := filepath.Join(tmpDir, "whitelist.txt")
	blFile := filepath.Join(tmpDir, "blacklist.txt")

	_ = os.WriteFile(wlFile, []byte("127.0.0.1\n"), 0644)
	_ = os.WriteFile(blFile, []byte(""), 0644)

	// Pick random free port for firewall
	testLn, _ := net.Listen("tcp", "127.0.0.1:0")
	fwPort := testLn.Addr().(*net.TCPAddr).Port
	testLn.Close()

	cfgContent := fmt.Sprintf(`
firewall_host=127.0.0.1
firewall_port=%d
backend_host=127.0.0.1
backend_port=%d
whitelist_file=%s
blacklist_file=%s
kernel_block_enabled=false
`, fwPort, backendAddr.Port, strings.ReplaceAll(wlFile, `\`, `/`), strings.ReplaceAll(blFile, `\`, `/`))

	_ = os.WriteFile(cfgFile, []byte(cfgContent), 0644)

	cfgMgr, err := config.NewManager(cfgFile)
	if err != nil {
		t.Fatalf("failed to load cfg: %v", err)
	}

	engine := NewEngine(cfgMgr)
	go func() {
		_ = engine.Start()
	}()
	defer engine.Stop()

	// Wait for engine to bind
	time.Sleep(100 * time.Millisecond)

	fwAddr := fmt.Sprintf("127.0.0.1:%d", fwPort)

	// Test 1: Clean client connection
	t.Run("Clean Client Connection", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("failed to connect to firewall: %v", err)
		}
		defer conn.Close()

		msg := "PLAYER_LOGIN_DATA\n"
		_, err = conn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}

		reader := bufio.NewReader(conn)
		reply, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}

		expected := "ECHO: " + msg
		if reply != expected {
			t.Fatalf("expected '%s', got '%s'", expected, reply)
		}
	})

	// Test 2: Attack signature blocked (SOCKS5 proxy attempt)
	t.Run("Attack SOCKS5 Signature Dropped", func(t *testing.T) {
		// First temporarily remove 127.0.0.1 from whitelist to test signature blocking
		_ = os.WriteFile(wlFile, []byte("10.99.99.99\n"), 0644)
		_ = engine.acl.ReloadWhitelist()

		conn, err := net.DialTimeout("tcp", fwAddr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer conn.Close()

		// Send SOCKS5 handshake (0x05 0x01 0x00)
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})

		// Read should fail because firewall drops and closes connection
		buf := make([]byte, 128)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = conn.Read(buf)
		if err == nil {
			t.Fatalf("expected connection to be closed by firewall on SOCKS5 payload")
		}

		// Restore whitelist
		_ = os.WriteFile(wlFile, []byte("127.0.0.1\n"), 0644)
		_ = engine.acl.ReloadWhitelist()
	})
}
