package scanner

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// ── parsePorts ─────────────────────────────────────────────────────────────────

func TestParsePorts_SinglePort(t *testing.T) {
	ports, err := parsePorts("80")
	if err != nil || len(ports) != 1 || ports[0] != 80 {
		t.Fatalf("expected [80], got %v, err: %v", ports, err)
	}
}

func TestParsePorts_Range(t *testing.T) {
	ports, err := parsePorts("22-25")
	if err != nil {
		t.Fatal(err)
	}
	want := []int{22, 23, 24, 25}
	for i, p := range want {
		if ports[i] != p {
			t.Fatalf("index %d: want %d got %d", i, p, ports[i])
		}
	}
}

func TestParsePorts_CommaSeparated(t *testing.T) {
	ports, err := parsePorts("22,80,443")
	if err != nil || len(ports) != 3 {
		t.Fatalf("unexpected result: %v err: %v", ports, err)
	}
}

func TestParsePorts_Mixed(t *testing.T) {
	ports, err := parsePorts("22,80-82,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 5 {
		t.Fatalf("expected 5 ports, got %d: %v", len(ports), ports)
	}
}

func TestParsePorts_Invalid(t *testing.T) {
	cases := []string{"abc", "0", "65536", "10-5", "-80", "80-"}
	for _, c := range cases {
		if _, err := parsePorts(c); err == nil {
			t.Errorf("expected error for input %q, got nil", c)
		}
	}
}

// ── scanPort ───────────────────────────────────────────────────────────────────

// startEchoServer spins up a temporary TCP server and returns its port.
func startEchoServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start echo server: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HELLO\r\n"))
			conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func TestScanPort_Open(t *testing.T) {
	port := startEchoServer(t)
	r := scanPort("127.0.0.1", port, 2*time.Second)
	if !r.Open {
		t.Fatalf("expected port %d to be open", port)
	}
	if r.Banner != "HELLO" {
		t.Fatalf("expected banner 'HELLO', got %q", r.Banner)
	}
}

func TestScanPort_Closed(t *testing.T) {
	// Port 1 requires root on Linux and is almost certainly closed in CI.
	r := scanPort("127.0.0.1", 1, 500*time.Millisecond)
	if r.Open {
		t.Skip("port 1 unexpectedly open — skipping")
	}
}
