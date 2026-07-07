package actuate

import (
	"errors"
	"strings"
	"testing"
)

func TestSanitizeRouteMapName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"192.168.1.1", "192-168-1-1"},
		{"192.168.5.0/24", "192-168-5-0-24"},
		{"10.0.0.1", "10-0-0-1"},
		{"172.16.0.1/16", "172-16-0-1-16"},
		{"no-dots-or-slashes", "no-dots-or-slashes"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := sanitizeRouteMapName(tt.in)
			if got != tt.want {
				t.Errorf("sanitizeRouteMapName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSetNeighborTiers_Script(t *testing.T) {
	var captured string
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		captured = script
		return nil, nil
	}
	defer func() { runVtysh = orig }()

	u := NeighborTierUpdate{
		Neighbor: "192.168.100.6",
		Prefs: []PrefixPref{
			{Prefix: "192.168.5.0/24", LocalPref: 300},
			{Prefix: "192.168.6.0/24", LocalPref: 200},
		},
	}

	if err := SetNeighborTiers(u); err != nil {
		t.Fatalf("SetNeighborTiers: %v", err)
	}

	// Prefix-lists present.
	if !strings.Contains(captured, "ip prefix-list PATHPROFILER-SCOPE-192-168-5-0-24 permit 192.168.5.0/24") {
		t.Errorf("missing prefix-list for 192.168.5.0/24\ngot:\n%s", captured)
	}
	if !strings.Contains(captured, "ip prefix-list PATHPROFILER-SCOPE-192-168-6-0-24 permit 192.168.6.0/24") {
		t.Errorf("missing prefix-list for 192.168.6.0/24\ngot:\n%s", captured)
	}

	// Correct match clause (address, not route-source).
	if !strings.Contains(captured, "match ip address prefix-list PATHPROFILER-SCOPE-192-168-5-0-24") {
		t.Errorf("wrong match clause for prefix 192.168.5.0/24\ngot:\n%s", captured)
	}

	// Local-pref values.
	if !strings.Contains(captured, "set local-preference 300") {
		t.Errorf("missing set local-preference 300\ngot:\n%s", captured)
	}
	if !strings.Contains(captured, "set local-preference 200") {
		t.Errorf("missing set local-preference 200\ngot:\n%s", captured)
	}

	// Sequence numbers.
	if !strings.Contains(captured, "route-map PATHPROFILER-192-168-100-6 permit 10") {
		t.Errorf("missing seq 10\ngot:\n%s", captured)
	}
	if !strings.Contains(captured, "route-map PATHPROFILER-192-168-100-6 permit 20") {
		t.Errorf("missing seq 20\ngot:\n%s", captured)
	}

	// Catch-all at 65535.
	if !strings.Contains(captured, "route-map PATHPROFILER-192-168-100-6 permit 65535") {
		t.Errorf("missing catch-all seq 65535\ngot:\n%s", captured)
	}

	// Clear-then-re-add: route-map is deleted first so stale seqs can't persist.
	if !strings.Contains(captured, "no route-map PATHPROFILER-192-168-100-6") {
		t.Errorf("missing `no route-map` clear line\ngot:\n%s", captured)
	}

	// Exactly one neighbor attachment.
	neighborLine := "neighbor 192.168.100.6 route-map PATHPROFILER-192-168-100-6 in"
	if n := strings.Count(captured, neighborLine); n != 1 {
		t.Errorf("expected exactly 1 neighbor route-map attachment, got %d\ngot:\n%s", n, captured)
	}
}

func TestSetNeighborTiers_MultiplePrefixes(t *testing.T) {
	var captured string
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		captured = script
		return nil, nil
	}
	defer func() { runVtysh = orig }()

	u := NeighborTierUpdate{
		Neighbor: "10.0.0.1",
		Prefs: []PrefixPref{
			{Prefix: "172.16.0.0/16", LocalPref: 400},
			{Prefix: "192.168.0.0/16", LocalPref: 250},
		},
	}

	if err := SetNeighborTiers(u); err != nil {
		t.Fatalf("SetNeighborTiers: %v", err)
	}

	// Two non-catch-all sequences + one catch-all = 3 total permit lines.
	if n := strings.Count(captured, "route-map PATHPROFILER-10-0-0-1 permit "); n != 3 {
		t.Errorf("expected 3 route-map permit lines (2 real + catch-all), got %d\ngot:\n%s", n, captured)
	}

	// Clear-then-re-add: route-map is deleted first so stale seqs can't persist.
	if !strings.Contains(captured, "no route-map PATHPROFILER-10-0-0-1") {
		t.Errorf("missing `no route-map` clear line\ngot:\n%s", captured)
	}

	// Single neighbor attachment.
	neighborLine := "neighbor 10.0.0.1 route-map PATHPROFILER-10-0-0-1 in"
	if n := strings.Count(captured, neighborLine); n != 1 {
		t.Errorf("expected exactly 1 neighbor route-map attachment, got %d\ngot:\n%s", n, captured)
	}
}

func TestSetNeighborTiers_Empty(t *testing.T) {
	called := false
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		called = true
		return nil, nil
	}
	defer func() { runVtysh = orig }()

	u := NeighborTierUpdate{Neighbor: "10.0.0.1"}
	if err := SetNeighborTiers(u); err != nil {
		t.Fatalf("SetNeighborTiers: %v", err)
	}
	if called {
		t.Error("runVtysh should not be called for empty Prefs")
	}
}

func TestSetNeighborTiers_VtyshError(t *testing.T) {
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		return []byte("some output"), errors.New("vtysh: command not found")
	}
	defer func() { runVtysh = orig }()

	u := NeighborTierUpdate{
		Neighbor: "10.0.0.1",
		Prefs:    []PrefixPref{{Prefix: "192.168.1.0/24", LocalPref: 200}},
	}

	err := SetNeighborTiers(u)
	if err == nil {
		t.Fatal("expected error from SetNeighborTiers")
	}
	if !strings.Contains(err.Error(), "vtysh neighbor-tier update failed") {
		t.Errorf("error should wrap vtysh failure, got: %v", err)
	}
}

func TestRemoveNeighborTiers_Script(t *testing.T) {
	var captured string
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		captured = script
		return nil, nil
	}
	defer func() { runVtysh = orig }()

	if err := RemoveNeighborTiers("192.168.100.6"); err != nil {
		t.Fatalf("RemoveNeighborTiers: %v", err)
	}

	// Must detach route-map from neighbor.
	if !strings.Contains(captured, "no neighbor 192.168.100.6 route-map PATHPROFILER-192-168-100-6 in") {
		t.Errorf("missing `no neighbor ... route-map ... in`\ngot:\n%s", captured)
	}
	// Must delete the route-map itself.
	if !strings.Contains(captured, "no route-map PATHPROFILER-192-168-100-6") {
		t.Errorf("missing `no route-map PATHPROFILER-192-168-100-6`\ngot:\n%s", captured)
	}
	// Must be inside configure terminal.
	if !strings.Contains(captured, "configure terminal") {
		t.Errorf("missing configure terminal\ngot:\n%s", captured)
	}
}

func TestRemoveNeighborTiers_VtyshError(t *testing.T) {
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		return []byte("output"), errors.New("vtysh: command not found")
	}
	defer func() { runVtysh = orig }()

	err := RemoveNeighborTiers("10.0.0.1")
	if err == nil {
		t.Fatal("expected error from RemoveNeighborTiers")
	}
	if !strings.Contains(err.Error(), "vtysh remove neighbor tiers failed") {
		t.Errorf("error should wrap vtysh failure, got: %v", err)
	}
}

func TestStartup_BootstrapsAppliedNeighborsFromFRR(t *testing.T) {
	// Simulate FRR running-config output with two PATHPROFILER route-maps.
	config := `hostname router
router bgp 65000
 bgp router-id 192.168.200.5
 neighbor 192.168.100.6 remote-as 65000
 neighbor 192.168.100.6 route-map PATHPROFILER-192-168-100-6 in
 neighbor 192.168.200.3 remote-as 65000
 neighbor 192.168.200.3 route-map PATHPROFILER-192-168-200-3 in
 neighbor 192.168.200.4 remote-as 65000
 !
route-map PATHPROFILER-192-168-100-6 permit 10
 match ip address prefix-list PATHPROFILER-SCOPE-192-168-5-0-24
 set local-preference 300
exit
!
route-map PATHPROFILER-192-168-100-6 permit 65535
exit
!
route-map PATHPROFILER-192-168-200-3 permit 10
 match ip address prefix-list PATHPROFILER-SCOPE-192-168-6-0-24
 set local-preference 200
exit
!
route-map PATHPROFILER-192-168-200-3 permit 65535
exit
!
line vty`
	neighbors := ParseAppliedNeighbors(config)
	if len(neighbors) != 2 {
		t.Fatalf("expected 2 neighbors, got %d: %v", len(neighbors), neighbors)
	}
	if !neighbors["192.168.100.6"] {
		t.Error("expected 192.168.100.6 in applied neighbors")
	}
	if !neighbors["192.168.200.3"] {
		t.Error("expected 192.168.200.3 in applied neighbors")
	}
	// 192.168.200.4 has a neighbor statement but no route-map attachment — must not appear.
	if neighbors["192.168.200.4"] {
		t.Error("192.168.200.4 should not be in applied neighbors (no route-map attachment)")
	}
}

func TestParseAppliedNeighbors_Empty(t *testing.T) {
	neighbors := ParseAppliedNeighbors("")
	if len(neighbors) != 0 {
		t.Errorf("expected empty map, got %v", neighbors)
	}
}

func TestParseAppliedNeighbors_NoPathprofiler(t *testing.T) {
	config := `hostname router
router bgp 65000
 neighbor 192.168.100.6 remote-as 65000
 neighbor 192.168.100.6 route-map SOME-OTHER-MAP in`
	neighbors := ParseAppliedNeighbors(config)
	if len(neighbors) != 0 {
		t.Errorf("expected empty map for non-PATHPROFILER route-maps, got %v", neighbors)
	}
}

func TestListAppliedNeighbors_VtyshError(t *testing.T) {
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		return nil, errors.New("vtysh: command not found")
	}
	defer func() { runVtysh = orig }()

	_, err := ListAppliedNeighbors()
	if err == nil {
		t.Fatal("expected error from vtysh failure")
	}
}
