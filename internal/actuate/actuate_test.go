package actuate

import (
	"errors"
	"fmt"
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

// assertInPlaceRewrite checks the invariants SetNeighborTiers must hold:
//
//   - it deletes nothing: no `no route-map` and no detach. Deleting a
//     route-map still bound to a live session is a use-after-free in FRR
//     before 10.2.4 (upstream #19191), and even where it is safe it perturbs
//     the BGP table on every actuation (see SetNeighborTiers);
//   - the route-map spans a fixed slot set: at least minSlots sequences at
//     (k+1)*slotStep, plus the 65535 catch-all;
//   - assigned slots carry their prefix's list and local-preference; the rest
//     are inert (match PATHPROFILER-NEVER) so they cannot short-circuit
//     later slots;
//   - exactly one neighbor attachment.
//
// Regression guard for the bgpd crash loop and for the measured table
// perturbation.
func assertInPlaceRewrite(t *testing.T, script, neighbor, slug string, nPrefs int) {
	t.Helper()
	if i := strings.Index(script, "no route-map"); i >= 0 {
		t.Errorf("in-place rewrite must never delete a route-map (offset %d)\ngot:\n%s", i, script)
	}
	if strings.Contains(script, "no neighbor") {
		t.Errorf("in-place rewrite must not detach the binding\ngot:\n%s", script)
	}
	attach := "\n neighbor " + neighbor + " route-map " + slug + " in\n"
	if n := strings.Count(script, attach); n != 1 {
		t.Errorf("expected exactly 1 neighbor attachment, got %d\ngot:\n%s", n, script)
	}

	slots := minSlots
	if nPrefs > slots {
		slots = nPrefs
	}
	if n := strings.Count(script, "route-map "+slug+" permit "); n != slots+1 {
		t.Errorf("expected %d sequences (%d slots + catch-all), got %d\ngot:\n%s", slots+1, slots, n, script)
	}
	if !strings.Contains(script, "route-map "+slug+" permit 65535") {
		t.Errorf("missing catch-all sequence\ngot:\n%s", script)
	}
	if n := strings.Count(script, " match ip address prefix-list PATHPROFILER-SCOPE-"); n != nPrefs {
		t.Errorf("expected %d prefix matches, got %d\ngot:\n%s", nPrefs, n, script)
	}
	if n := strings.Count(script, " set local-preference "); n != nPrefs {
		t.Errorf("expected %d local-preference sets, got %d\ngot:\n%s", nPrefs, n, script)
	}
	if n := strings.Count(script, " match ip address prefix-list "+neverList); n != slots-nPrefs {
		t.Errorf("expected %d inert slots, got %d\ngot:\n%s", slots-nPrefs, n, script)
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

	// Prefix-lists present, with a fixed seq so repeated declarations
	// across neighbors/ticks don't pile up duplicate entries.
	if !strings.Contains(captured, "ip prefix-list PATHPROFILER-SCOPE-192-168-5-0-24 seq 5 permit 192.168.5.0/24") {
		t.Errorf("missing prefix-list for 192.168.5.0/24\ngot:\n%s", captured)
	}
	if !strings.Contains(captured, "ip prefix-list PATHPROFILER-SCOPE-192-168-6-0-24 seq 5 permit 192.168.6.0/24") {
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

	assertInPlaceRewrite(t, captured, "192.168.100.6", "PATHPROFILER-192-168-100-6", 2)
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

	assertInPlaceRewrite(t, captured, "10.0.0.1", "PATHPROFILER-10-0-0-1", 2)
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

	// Must detach route-map from neighbor inside `router bgp` context —
	// `no neighbor ... route-map ... in` is invalid at the top level of
	// configure terminal and vtysh exits 1 on it.
	if !strings.Contains(captured, "router bgp\n") {
		t.Errorf("missing `router bgp` context before `no neighbor ... route-map`\ngot:\n%s", captured)
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

func TestParseAppliedBindings_UsesActualMapName(t *testing.T) {
	// The bound map name is NOT PATHPROFILER-<slug of the neighbor>. The parser
	// must report the name that is actually in the config rather than
	// re-deriving it -- re-deriving is what let a lab run leave a map bound and
	// undeleted (found by replaying NormalizeApplied against real FRR).
	config := `router bgp 65000
 neighbor 192.168.100.6 route-map PATHPROFILER-LEGACY-A in
 neighbor 192.168.200.3 route-map PATHPROFILER-192-168-200-3 in
 neighbor 192.168.200.4 remote-as 65000`
	got := ParseAppliedBindings(config)
	if len(got) != 2 {
		t.Fatalf("expected 2 bindings, got %d: %v", len(got), got)
	}
	// Sorted by route-map name: PATHPROFILER-192-168-200-3 < PATHPROFILER-LEGACY-A.
	if got[0].Neighbor != "192.168.200.3" || got[0].RouteMap != "PATHPROFILER-192-168-200-3" {
		t.Errorf("unexpected first binding: %+v", got[0])
	}
	if got[1].Neighbor != "192.168.100.6" || got[1].RouteMap != "PATHPROFILER-LEGACY-A" {
		t.Errorf("unexpected second binding: %+v", got[1])
	}
}

func TestParseAppliedBindings_Empty(t *testing.T) {
	if got := ParseAppliedBindings(""); len(got) != 0 {
		t.Errorf("expected no bindings, got %v", got)
	}
}

func TestParseAppliedBindings_NoPathprofiler(t *testing.T) {
	config := `router bgp 65000
 neighbor 192.168.100.6 remote-as 65000
 neighbor 192.168.100.6 route-map SOME-OTHER-MAP in`
	if got := ParseAppliedBindings(config); len(got) != 0 {
		t.Errorf("expected no bindings for non-PATHPROFILER maps, got %v", got)
	}
}

func TestNormalizeApplied_DetachThenDeleteThenLists(t *testing.T) {
	var calls []string
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		calls = append(calls, script)
		if strings.Contains(script, "show running-config") {
			return []byte(`router bgp 65000
 neighbor 192.168.100.6 route-map PATHPROFILER-LEGACY-A in
 neighbor 192.168.200.3 route-map PATHPROFILER-LEGACY-B in
ip prefix-list PATHPROFILER-SCOPE-192-168-5-0-24 seq 5 permit 192.168.5.0/24
ip prefix-list PATHPROFILER-NEVER seq 5 permit 192.0.2.1/32
route-map PATHPROFILER-LEGACY-A permit 10
exit
route-map PATHPROFILER-ORPHAN permit 10
exit
`), nil
		}
		return nil, nil
	}
	defer func() { runVtysh = orig }()

	n, err := NormalizeApplied()
	if err != nil {
		t.Fatalf("NormalizeApplied: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 detached bindings, got %d", n)
	}
	script := calls[len(calls)-1]
	idx := func(s string) int { return strings.Index(script, s) }
	detach := idx("no neighbor 192.168.100.6 route-map PATHPROFILER-LEGACY-A in")
	del := idx("no route-map PATHPROFILER-LEGACY-A")
	list := idx("no ip prefix-list PATHPROFILER-SCOPE-192-168-5-0-24")
	if detach < 0 || del < 0 || list < 0 {
		t.Fatalf("normalize script is missing a step\ngot:\n%s", script)
	}
	if !(detach < del && del < list) {
		t.Errorf("order must be detach, then delete route-maps, then delete prefix-lists "+
			"(detach@%d delete@%d list@%d)\ngot:\n%s", detach, del, list, script)
	}
	if !strings.Contains(script, "no route-map PATHPROFILER-LEGACY-B") {
		t.Errorf("normalize must remove every bound route-map, by its actual name\ngot:\n%s", script)
	}
	if !strings.Contains(script, "no ip prefix-list PATHPROFILER-NEVER") {
		t.Errorf("normalize must collect the never-match list too\ngot:\n%s", script)
	}
	// An unbound orphan map (removal detached the binding but the map delete
	// failed, or a hand-made map) must be deleted as well.
	if !strings.Contains(script, "no route-map PATHPROFILER-ORPHAN") {
		t.Errorf("normalize must delete unbound orphan route-maps\ngot:\n%s", script)
	}
}

func TestNormalizeApplied_NoOpWhenNothingApplied(t *testing.T) {
	calls := 0
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		calls++
		return []byte("hostname r\nline vty\n"), nil
	}
	defer func() { runVtysh = orig }()

	n, err := NormalizeApplied()
	if err != nil {
		t.Fatalf("NormalizeApplied: %v", err)
	}
	if n != 0 || calls != 1 {
		t.Errorf("expected a no-op (n=0, exactly 1 vtysh call), got n=%d calls=%d", n, calls)
	}
}

func TestNormalizeApplied_VtyshError(t *testing.T) {
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		return nil, errors.New("vtysh: command not found")
	}
	defer func() { runVtysh = orig }()

	if _, err := NormalizeApplied(); err == nil {
		t.Fatal("expected error from vtysh failure")
	}
}

func TestParseAppliedPrefixLists(t *testing.T) {
	config := `ip prefix-list PATHPROFILER-SCOPE-192-168-5-0-24 seq 5 permit 192.168.5.0/24
ip prefix-list PATHPROFILER-NEVER seq 5 permit 192.0.2.1/32
ip prefix-list OTHER-LIST seq 5 permit 10.0.0.0/8
ip prefix-list PATHPROFILER-SCOPE-10-0-0-0-24 seq 5 permit 10.0.0.0/24`
	got := ParseAppliedPrefixLists(config)
	want := []string{
		"PATHPROFILER-NEVER",
		"PATHPROFILER-SCOPE-10-0-0-0-24",
		"PATHPROFILER-SCOPE-192-168-5-0-24",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSetNeighborTiers_SlotCountIsGrowOnly(t *testing.T) {
	var captured string
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) { captured = script; return nil, nil }
	defer func() { runVtysh = orig }()

	wide := NeighborTierUpdate{Neighbor: "10.0.0.9"}
	for i := range minSlots + 5 {
		wide.Prefs = append(wide.Prefs, PrefixPref{
			Prefix:    fmt.Sprintf("10.70.%d.0/24", i),
			LocalPref: 200,
		})
	}
	if err := SetNeighborTiers(wide); err != nil {
		t.Fatalf("SetNeighborTiers(wide): %v", err)
	}
	nWide := strings.Count(captured, "route-map PATHPROFILER-10-0-0-9 permit ")
	if nWide != minSlots+6 { // (minSlots+5) slots + catch-all
		t.Errorf("a %d-prefix update should emit %d sequences, got %d", minSlots+5, minSlots+6, nWide)
	}

	// A shrinking prefix set must not shrink the slot set: that would require
	// deleting sequences, which is exactly what this design never does.
	narrow := NeighborTierUpdate{Neighbor: "10.0.0.9", Prefs: wide.Prefs[:1]}
	if err := SetNeighborTiers(narrow); err != nil {
		t.Fatalf("SetNeighborTiers(narrow): %v", err)
	}
	if n := strings.Count(captured, "route-map PATHPROFILER-10-0-0-9 permit "); n != nWide {
		t.Errorf("slot count must be grow-only: %d then %d", nWide, n)
	}
	if strings.Contains(captured, "no route-map") {
		t.Errorf("shrinking the prefix set must not delete anything\ngot:\n%s", captured)
	}
	if n := strings.Count(captured, " match ip address prefix-list "+neverList); n != minSlots+4 {
		t.Errorf("expected %d inert slots after the shrink, got %d\ngot:\n%s", minSlots+4, n, captured)
	}
}
