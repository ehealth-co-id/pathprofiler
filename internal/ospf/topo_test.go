package ospf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const (
	fixtureNeighbor = "sample_ospf_neighbor.json"
	fixtureRoute    = "sample_ospf_route.json"
)

func TestParseNeighbors(t *testing.T) {
	neighbors := parseNeighborFixture(t)

	tests := []struct {
		ip       string
		wantIface string
	}{
		{"192.168.200.3", "wg0"},
		{"192.168.200.4", "wg0"},
		{"192.168.200.6", "wg0"},
	}
	for _, tt := range tests {
		iface, ok := neighbors[tt.ip]
		if !ok {
			t.Errorf("neighbor %q not found", tt.ip)
			continue
		}
		if iface != tt.wantIface {
			t.Errorf("neighbor %q: interface = %q, want %q", tt.ip, iface, tt.wantIface)
		}
	}
}

func TestParseRoute_10_255_0_3(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, err := ParseRoute(routeData, "10.255.0.3")
	if err != nil {
		t.Fatalf("ParseRoute(10.255.0.3): %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	p := paths[0]
	if p.Interface != "wg0" {
		t.Errorf("Interface = %q, want wg0", p.Interface)
	}
	if p.GatewayIP != "192.168.200.3" {
		t.Errorf("GatewayIP = %q, want 192.168.200.3", p.GatewayIP)
	}
	if p.Cost != 60 {
		t.Errorf("Cost = %d, want 60", p.Cost)
	}
	if p.Loopback != "10.255.0.3" {
		t.Errorf("Loopback = %q, want 10.255.0.3", p.Loopback)
	}
}

func TestParseRoute_10_255_0_4(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, err := ParseRoute(routeData, "10.255.0.4")
	if err != nil {
		t.Fatalf("ParseRoute(10.255.0.4): %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].Interface != "wg0" {
		t.Errorf("Interface = %q, want wg0", paths[0].Interface)
	}
	if paths[0].GatewayIP != "192.168.200.4" {
		t.Errorf("GatewayIP = %q, want 192.168.200.4", paths[0].GatewayIP)
	}
	if paths[0].Cost != 60 {
		t.Errorf("Cost = %d, want 60", paths[0].Cost)
	}
}

func TestParseRoute_10_255_0_5_DirectlyAttached(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, err := ParseRoute(routeData, "10.255.0.5")
	if err != nil {
		t.Fatalf("ParseRoute(10.255.0.5): %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths (directly-attached, whitespace IP), got %d", len(paths))
	}
}

func TestParseRoute_10_255_0_6(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, err := ParseRoute(routeData, "10.255.0.6")
	if err != nil {
		t.Fatalf("ParseRoute(10.255.0.6): %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
	if paths[0].Interface != "ens21" {
		t.Errorf("Interface = %q, want ens21", paths[0].Interface)
	}
	if paths[0].GatewayIP != "192.168.100.6" {
		t.Errorf("GatewayIP = %q, want 192.168.100.6", paths[0].GatewayIP)
	}
	if paths[0].Cost != 20 {
		t.Errorf("Cost = %d, want 20", paths[0].Cost)
	}
}

func TestParseRoute_NotInUnderlay(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, err := ParseRoute(routeData, "192.168.3.200")
	if err != nil {
		t.Fatalf("ParseRoute(192.168.3.200): %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("expected 0 paths (not in underlay), got %d", len(paths))
	}
}

func TestParseRoute_AllowsBareIP(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, err := ParseRoute(routeData, "10.255.0.3")
	if err != nil {
		t.Fatalf("ParseRoute(10.255.0.3): %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(paths))
	}
}

func TestParseRoute_MalformedJSON(t *testing.T) {
	_, err := ParseRoute([]byte(`not-json`), "10.255.0.3")
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

func TestFetchTopo_BuildsFullUnderlay(t *testing.T) {
	// Inject vtysh to return route fixture.
	saved := runVtysh
	runVtysh = func(args ...string) ([]byte, error) {
		return readFixture(t, fixtureRoute), nil
	}
	defer func() { runVtysh = saved }()

	loopbacks := []string{"10.255.0.3", "10.255.0.4", "10.255.0.6"}
	topo, err := FetchTopo(loopbacks)
	if err != nil {
		t.Fatalf("FetchTopo: %v", err)
	}

	if len(topo) != 3 {
		t.Fatalf("expected 3 loopbacks in topo, got %d", len(topo))
	}
	if len(topo["10.255.0.3"]) != 1 {
		t.Errorf("10.255.0.3: expected 1 path, got %d", len(topo["10.255.0.3"]))
	}
	if len(topo["10.255.0.4"]) != 1 {
		t.Errorf("10.255.0.4: expected 1 path, got %d", len(topo["10.255.0.4"]))
	}
	if len(topo["10.255.0.6"]) != 1 {
		t.Errorf("10.255.0.6: expected 1 path, got %d", len(topo["10.255.0.6"]))
	}
}

func TestPathsTo(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths, _ := ParseRoute(routeData, "10.255.0.3")
	u := Underlay{"10.255.0.3": paths}

	got := u.PathsTo("10.255.0.3")
	if !reflect.DeepEqual(got, paths) {
		t.Errorf("PathsTo returned different slice")
	}

	empty := u.PathsTo("10.255.0.99")
	if len(empty) != 0 {
		t.Errorf("expected empty for missing loopback")
	}
}

func TestFetchTopo_VtyshError(t *testing.T) {
	runVtysh = func(args ...string) ([]byte, error) {
		return nil, os.ErrNotExist
	}
	defer func() { runVtysh = nil }()

	_, err := FetchTopo([]string{"10.255.0.3"})
	if err == nil {
		t.Fatal("expected error from vtysh failure, got nil")
	}
}

func TestLoopbackForGateway_Found(t *testing.T) {
	routeData := readFixture(t, fixtureRoute)
	paths3, _ := ParseRoute(routeData, "10.255.0.3")
	paths4, _ := ParseRoute(routeData, "10.255.0.4")
	u := Underlay{
		"10.255.0.3": paths3,
		"10.255.0.4": paths4,
	}

	loopback, err := u.LoopbackForGateway("192.168.200.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loopback != "10.255.0.3" {
		t.Errorf("LoopbackForGateway(192.168.200.3) = %q, want 10.255.0.3", loopback)
	}

	loopback, err = u.LoopbackForGateway("192.168.200.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loopback != "10.255.0.4" {
		t.Errorf("LoopbackForGateway(192.168.200.4) = %q, want 10.255.0.4", loopback)
	}
}

func TestLoopbackForGateway_NotFound(t *testing.T) {
	u := Underlay{
		"10.255.0.3": {{GatewayIP: "192.168.200.3"}},
	}
	loopback, err := u.LoopbackForGateway("192.168.99.99")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loopback != "" {
		t.Errorf("expected empty for unknown gateway IP, got %q", loopback)
	}
}

func TestLoopbackForGateway_AmbiguousReturnsError(t *testing.T) {
	// Two loopbacks reachable via the same gateway IP — violates uniqueness.
	u := Underlay{
		"10.255.0.3": {{GatewayIP: "192.168.200.3", Interface: "wg0"}},
		"10.255.0.4": {{GatewayIP: "192.168.200.3", Interface: "ens21"}},
	}
	loopback, err := u.LoopbackForGateway("192.168.200.3")
	if err == nil {
		t.Fatalf("expected error for ambiguous gateway IP, got loopback %q", loopback)
	}
	if loopback != "" {
		t.Errorf("expected empty loopback on error, got %q", loopback)
	}
}

// --- helpers --------------------------------------------------------------

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func parseNeighborFixture(t *testing.T) map[string]string {
	t.Helper()
	raw := readFixture(t, fixtureNeighbor)
	m, err := ParseNeighbors(raw)
	if err != nil {
		t.Fatalf("ParseNeighbors: %v", err)
	}
	return m
}