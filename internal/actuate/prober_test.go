//go:build linux

package actuate

import (
	"math"
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

	result, err := ProbeNextHop("lo", addr.IP.String(), addr.Port, 2*time.Second, 3)
	if err != nil {
		t.Fatalf("ProbeNextHop: %v", err)
	}

	if result.LossRate != 0.0 {
		t.Errorf("expected lossRate 0.0 against echo responder, got %f", result.LossRate)
	}
	if result.LossRateErr <= 0 {
		t.Errorf("expected positive LossRateErr (Wilson semi-width for k=0,N=3), got %f", result.LossRateErr)
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
	result, err := ProbeNextHop("lo", "127.0.0.1", 65535, 2*time.Second, 3)
	if err != nil {
		t.Fatalf("ProbeNextHop: %v", err)
	}

	// ECONNREFUSED (ICMP port-unreachable) counts as a successful probe,
	// because we know the host is reachable and can measure RTT.
	if result.LossRate != 0.0 {
		t.Errorf("expected lossRate 0.0 against closed port (each ECONNREFUSED counts), got %f", result.LossRate)
	}
	if result.RTT <= 0 {
		t.Errorf("expected positive RTT for ECONNREFUSED, got %v", result.RTT)
	}
}

func TestWilsonLossErr_KnownValues(t *testing.T) {
	tests := []struct {
		k, n int
		want float64
	}{
		{0, 5, 0.217}, // 0/5: can't measure <43% loss with N=5
		{1, 5, 0.294}, // 1/5: 20% measured, ±29% uncertainty
		{2, 5, 0.326}, // 2/5: continuous, no boundary artifact
		{3, 5, 0.326}, // 3/5: symmetric with 2/5
		{4, 5, 0.294}, // 4/5: symmetric with 1/5
		{5, 5, 0.000}, // all-lost: sentinel, error irrelevant
	}
	for _, tt := range tests {
		got := wilsonLossErr(tt.k, tt.n)
		if math.Abs(got-tt.want) > 0.002 {
			t.Errorf("wilsonLossErr(%d,%d)=%.3f, want %.3f", tt.k, tt.n, got, tt.want)
		}
	}
}