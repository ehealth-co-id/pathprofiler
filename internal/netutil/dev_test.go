package netutil

import (
	"errors"
	"testing"

	"pathprofiler/internal/ospf"
)

func TestResolveDevice_Normal(t *testing.T) {
	// "ip route get 192.168.200.1" output with a wg interface.
	const output = "192.168.200.1 dev wg0 src 192.168.200.5 uid 0 \n    cache"
	dev, err := parseDevice([]byte(output))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev != "wg0" {
		t.Fatalf("got %q, want wg0", dev)
	}
}

func TestResolveDevice_Local(t *testing.T) {
	// Output for a local address (note the <local> suffix on the cache line).
	const output = "local 192.168.100.5 dev lo src 192.168.100.5 uid 0 \n    cache <local>"
	dev, err := parseDevice([]byte(output))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev != "lo" {
		t.Fatalf("got %q, want lo", dev)
	}
}

func TestResolveDevice_Physical(t *testing.T) {
	// Output for a physical interface.
	const output = "192.168.100.6 dev ens21 src 192.168.100.5 uid 0 \n    cache"
	dev, err := parseDevice([]byte(output))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dev != "ens21" {
		t.Fatalf("got %q, want ens21", dev)
	}
}

func TestResolveDevice_NoDevToken(t *testing.T) {
	// Output that doesn't contain "dev".
	const output = "RTNETLINK answers: Network is unreachable"
	_, err := parseDevice([]byte(output))
	if err == nil {
		t.Fatal("expected error for missing 'dev' token, got nil")
	}
}

func TestResolveDevice_EmptyOutput(t *testing.T) {
	_, err := parseDevice([]byte(""))
	if err == nil {
		t.Fatal("expected error for empty output, got nil")
	}
}

func TestResolveDevice_InvalidIP(t *testing.T) {
	// ResolveDevice should reject invalid IPs before running the command.
	_, err := ResolveDevice("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

func TestResolveDevice_CommandError(t *testing.T) {
	// Inject a failing command.
	saved := ipRouteGetCmd
	ipRouteGetCmd = func(ip string) ([]byte, error) {
		return nil, errors.New("mock command failure")
	}
	defer func() { ipRouteGetCmd = saved }()

	_, err := ResolveDevice("192.168.1.1")
	if err == nil {
		t.Fatal("expected error from command, got nil")
	}
}

// ---------------------------------------------------------------------------
// ResolvePaths tests

func TestResolvePaths_UsesUnderlayWhenAvailable(t *testing.T) {
	underlay := ospf.Underlay{
		"10.255.0.3": {
			{Loopback: "10.255.0.3", Interface: "wg0", PhysicalNH: "192.168.200.3", Cost: 50},
			{Loopback: "10.255.0.3", Interface: "ens21", PhysicalNH: "192.168.200.3", Cost: 60},
		},
	}
	paths, err := ResolvePaths("10.255.0.3", underlay)
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths from underlay, got %d", len(paths))
	}
	if paths[0].Interface != "wg0" {
		t.Errorf("paths[0].Interface = %q, want wg0", paths[0].Interface)
	}
	if paths[1].Interface != "ens21" {
		t.Errorf("paths[1].Interface = %q, want ens21", paths[1].Interface)
	}
}

func TestResolvePaths_FallsBackToIPRouteGet(t *testing.T) {
	saved := ipRouteGetCmd
	ipRouteGetCmd = func(ip string) ([]byte, error) {
		return []byte("192.168.3.200 dev eth0 src 192.168.1.1 uid 0\n    cache"), nil
	}
	defer func() { ipRouteGetCmd = saved }()

	underlay := ospf.Underlay{
		"10.255.0.3": {{Loopback: "10.255.0.3", Interface: "wg0"}},
	}
	paths, err := ResolvePaths("192.168.3.200", underlay)
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path from fallback, got %d", len(paths))
	}
	if paths[0].Interface != "eth0" {
		t.Errorf("Interface = %q, want eth0", paths[0].Interface)
	}
	if paths[0].Loopback != "192.168.3.200" {
		t.Errorf("Loopback = %q, want 192.168.3.200", paths[0].Loopback)
	}
	if paths[0].PhysicalNH != "" {
		t.Errorf("PhysicalNH should be empty for fallback, got %q", paths[0].PhysicalNH)
	}
}

func TestResolvePaths_FallbackCommandError(t *testing.T) {
	saved := ipRouteGetCmd
	ipRouteGetCmd = func(ip string) ([]byte, error) {
		return nil, errors.New("mock failure")
	}
	defer func() { ipRouteGetCmd = saved }()

	_, err := ResolvePaths("192.168.3.200", nil)
	if err == nil {
		t.Fatal("expected error when fallback command fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// ResolveNexthop tests

func TestResolveNexthop_WithGateway(t *testing.T) {
	// "ip route get" output with a via gateway.
	const output = "192.168.1.100 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0\n    cache"
	nh, err := parseNexthop([]byte(output), "192.168.1.100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nh != "10.0.0.1" {
		t.Fatalf("got %q, want 10.0.0.1", nh)
	}
}

func TestResolveNexthop_DirectRoute(t *testing.T) {
	// Directly connected, no "via" token.
	const output = "192.168.200.1 dev wg0 src 192.168.200.5 uid 0\n    cache"
	nh, err := parseNexthop([]byte(output), "192.168.200.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nh != "192.168.200.1" {
		t.Fatalf("got %q, want 192.168.200.1", nh)
	}
}

func TestResolveNexthop_LocalRoute(t *testing.T) {
	// Local address.
	const output = "local 192.168.100.5 dev lo src 192.168.100.5 uid 0\n    cache <local>"
	nh, err := parseNexthop([]byte(output), "192.168.100.5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if nh != "192.168.100.5" {
		t.Fatalf("got %q, want 192.168.100.5", nh)
	}
}

func TestResolveNexthop_InvalidIP(t *testing.T) {
	_, err := ResolveNexthop("not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP, got nil")
	}
}

func TestResolveNexthop_CommandError(t *testing.T) {
	saved := ipRouteGetCmd
	ipRouteGetCmd = func(ip string) ([]byte, error) {
		return nil, errors.New("mock command failure")
	}
	defer func() { ipRouteGetCmd = saved }()

	_, err := ResolveNexthop("192.168.1.1")
	if err == nil {
		t.Fatal("expected error from command, got nil")
	}
}
