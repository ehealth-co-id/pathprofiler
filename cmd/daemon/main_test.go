//go:build linux

package main

import (
	"net"
	"testing"

	"pathprofiler/internal/actuate"
)

// F5 trip-wire: asserts current byte-order behavior of uint32ToIPStr.
// A future BPF-side fix (bpf_ntohl restore in the BPF writer) will make
// this test fail, signaling the conversion needs updating.
func TestUint32ToIPStr_RoundTrip(t *testing.T) {
	input := uint32(0x0aff0006)
	s := uint32ToIPStr(input)
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("ParseIP(%q) failed", s)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		t.Fatal("not an IPv4")
	}
	back := uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
	if back != input {
		t.Fatalf("round-trip: 0x%08x -> %s -> 0x%08x", input, s, back)
	}
}

const topTier = 300

func TestSyncAppliedActiveMirror_GainsTopTier(t *testing.T) {
	activeNeighbor := map[string]string{}
	activeComposite := map[string]float64{}
	candidateComposite := map[string]map[string]float64{
		"192.168.5.0/24": {"10.255.0.4": 4200},
	}
	u := actuate.NeighborTierUpdate{
		Neighbor: "10.255.0.4",
		Prefs:    []actuate.PrefixPref{{Prefix: "192.168.5.0/24", LocalPref: topTier}},
	}

	syncAppliedActiveMirror(activeNeighbor, activeComposite, candidateComposite, u, topTier)

	if activeNeighbor["192.168.5.0/24"] != "10.255.0.4" {
		t.Errorf("want active neighbor 10.255.0.4, got %q", activeNeighbor["192.168.5.0/24"])
	}
	if activeComposite["192.168.5.0/24"] != 4200 {
		t.Errorf("want active composite 4200, got %v", activeComposite["192.168.5.0/24"])
	}
}

func TestSyncAppliedActiveMirror_DemotedClearsEntry(t *testing.T) {
	activeNeighbor := map[string]string{"192.168.5.0/24": "10.255.0.4"}
	activeComposite := map[string]float64{"192.168.5.0/24": 4200}
	// Two candidates -- otherwise the sole-candidate rule would mark this
	// neighbor active regardless of tier, which is a different case (see
	// TestSyncAppliedActiveMirror_SoleCandidateGainsMirrorAtDefaultTier).
	candidateComposite := map[string]map[string]float64{
		"192.168.5.0/24": {"10.255.0.4": 9000, "10.255.0.6": 4200},
	}
	// Same neighbor, but this tick's applied update demotes it off top tier.
	u := actuate.NeighborTierUpdate{
		Neighbor: "10.255.0.4",
		Prefs:    []actuate.PrefixPref{{Prefix: "192.168.5.0/24", LocalPref: 100}},
	}

	syncAppliedActiveMirror(activeNeighbor, activeComposite, candidateComposite, u, topTier)

	if _, ok := activeNeighbor["192.168.5.0/24"]; ok {
		t.Errorf("want mirror entry cleared, still has %q", activeNeighbor["192.168.5.0/24"])
	}
	if _, ok := activeComposite["192.168.5.0/24"]; ok {
		t.Errorf("want composite entry cleared, still has %v", activeComposite["192.168.5.0/24"])
	}
}

// TestSyncAppliedActiveMirror_SoleCandidateGainsMirrorAtDefaultTier covers
// the single-path prefix case: RankByTier always assigns defaultTier (never
// topTier) when a prefix has exactly one candidate, but that candidate is
// still unambiguously the active path once applied.
func TestSyncAppliedActiveMirror_SoleCandidateGainsMirrorAtDefaultTier(t *testing.T) {
	activeNeighbor := map[string]string{}
	activeComposite := map[string]float64{}
	const defaultTier = 100
	candidateComposite := map[string]map[string]float64{
		"192.168.250.250/32": {"192.168.3.200": 465},
	}
	u := actuate.NeighborTierUpdate{
		Neighbor: "192.168.3.200",
		Prefs:    []actuate.PrefixPref{{Prefix: "192.168.250.250/32", LocalPref: defaultTier}},
	}

	syncAppliedActiveMirror(activeNeighbor, activeComposite, candidateComposite, u, topTier)

	if activeNeighbor["192.168.250.250/32"] != "192.168.3.200" {
		t.Errorf("want sole candidate marked active, got %q", activeNeighbor["192.168.250.250/32"])
	}
	if activeComposite["192.168.250.250/32"] != 465 {
		t.Errorf("want active composite 465, got %v", activeComposite["192.168.250.250/32"])
	}
}

func TestSyncAppliedActiveMirror_OtherNeighborLeavesMirrorUntouched(t *testing.T) {
	activeNeighbor := map[string]string{"192.168.5.0/24": "10.255.0.4"}
	activeComposite := map[string]float64{"192.168.5.0/24": 4200}
	candidateComposite := map[string]map[string]float64{
		"192.168.5.0/24": {"10.255.0.4": 4200, "10.255.0.6": 9000},
	}
	// A different neighbor's update gets applied this tick, at a non-top tier
	// for the same prefix -- the recorded active neighbor (10.255.0.4) didn't
	// have its own update touched, so it must remain the mirror's answer.
	u := actuate.NeighborTierUpdate{
		Neighbor: "10.255.0.6",
		Prefs:    []actuate.PrefixPref{{Prefix: "192.168.5.0/24", LocalPref: 100}},
	}

	syncAppliedActiveMirror(activeNeighbor, activeComposite, candidateComposite, u, topTier)

	if activeNeighbor["192.168.5.0/24"] != "10.255.0.4" {
		t.Errorf("want active neighbor to remain 10.255.0.4, got %q", activeNeighbor["192.168.5.0/24"])
	}
	if activeComposite["192.168.5.0/24"] != 4200 {
		t.Errorf("want active composite to remain 4200, got %v", activeComposite["192.168.5.0/24"])
	}
}
