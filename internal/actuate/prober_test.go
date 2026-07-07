//go:build linux

package actuate

import (
	"net"
	"testing"
	"time"
)

func TestProbe_LocalhostEcho(t *testing.T) {
	// Start a UDP echo responder on a random port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer pc.Close()

	addr := pc.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 512)
		for {
			n, cli, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], cli)
		}
	}()

	result, err := ProbeNextHop("lo", addr.IP.String(), addr.Port, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeNextHop: %v", err)
	}

	if result.Lost {
		t.Errorf("expected not lost against echo responder")
	}
	if result.RTT <= 0 {
		t.Errorf("expected positive RTT, got %v", result.RTT)
	}
	if result.NextHopIP != addr.IP.String() {
		t.Errorf("NextHopIP: want %s, got %s", addr.IP.String(), result.NextHopIP)
	}
}

func TestProbe_ClosedPort_ReturnsECONNREFUSED(t *testing.T) {
	// Pick a high port that is very unlikely to be listening.
	result, err := ProbeNextHop("lo", "127.0.0.1", 65535, 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeNextHop: %v", err)
	}

	// ECONNREFUSED (ICMP port-unreachable) counts as a successful probe,
	// because we know the host is reachable and can measure RTT.
	if result.Lost {
		t.Errorf("expected not lost against closed port (ECONNREFUSED counts as success)")
	}
	if result.RTT <= 0 {
		t.Errorf("expected positive RTT for ECONNREFUSED, got %v", result.RTT)
	}
}