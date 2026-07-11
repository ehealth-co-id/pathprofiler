//go:build linux

package actuate

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// mustStartResponder starts a responder on an OS-assigned ephemeral port and
// returns the conn (auto-closed via t.Cleanup) plus the bound port.
func mustStartResponder(t *testing.T) int {
	t.Helper()
	conn, err := StartColdProbeResponder(0, true)
	if err != nil {
		t.Fatalf("StartColdProbeResponder: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestColdProbeResponder_EchoesMatchingPayload(t *testing.T) {
	port := mustStartResponder(t)

	cli, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	if _, err := cli.Write([]byte(probePayload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("expected echo reply, got error: %v", err)
	}
	if string(buf[:n]) != probePayload {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], probePayload)
	}
}

func TestColdProbeResponder_IgnoresNonMatchingPayload(t *testing.T) {
	port := mustStartResponder(t)

	cli, err := net.Dial("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cli.Close()

	if _, err := cli.Write([]byte("not-the-probe-payload")); err != nil {
		t.Fatalf("write: %v", err)
	}

	cli.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 512)
	if _, err := cli.Read(buf); err == nil {
		t.Error("expected no reply for non-matching payload, got one")
	}
}

func TestColdProbeResponder_EndToEndWithProbeLegBurst(t *testing.T) {
	port := mustStartResponder(t)

	rtts, replied, err := ProbeLegBurst("lo", "127.0.0.1", port, 500*time.Millisecond, 5)
	if err != nil {
		t.Fatalf("ProbeLegBurst: %v", err)
	}
	if replied != 5 {
		t.Errorf("replied = %d, want 5 (all should succeed via real UDP echo, no ICMP dependency)", replied)
	}
	if len(rtts) != 5 {
		t.Errorf("len(rtts) = %d, want 5", len(rtts))
	}
}
