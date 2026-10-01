//go:build linux

package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"strings"
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

// TestFormatTickSummary_HasEveryKey pins the summary's field set: the summary
// is the daemon's primary observability line, so a counter silently dropped
// from it is a regression.
func TestFormatTickSummary_HasEveryKey(t *testing.T) {
	got := formatTickSummary(tickCounters{})
	for _, key := range []string{
		"scope=", "underlay=", "transit=", "ema=", "retrans=", "legs=",
		"decided=", "updates=", "applied=", "suppressed=", "skip=", "dropped=",
	} {
		if !strings.Contains(got, key) {
			t.Errorf("tick summary is missing %q: %s", key, got)
		}
	}
}

// TestEmitTickSummary_ChangeOnlyWithHeartbeat is the density contract: an
// unchanged tick must not log (that is the verbosity this replaced), a changed
// tick must log immediately, and a quiet loop still emits a heartbeat so a
// stalled daemon is visible.
func TestEmitTickSummary_ChangeOnlyWithHeartbeat(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	countLines := func() int { return strings.Count(buf.String(), "tick ") }

	var prevBody string
	var lastEmitTick uint64
	base := tickCounters{Tick: 1, Prefixes: 2, Paths: 2, UnderlayIfaces: 1, ProbeLegs: 2}

	emitTickSummary(&prevBody, &lastEmitTick, base)
	if n := countLines(); n != 1 {
		t.Fatalf("first tick must emit, got %d line(s): %s", n, buf.String())
	}

	// Identical counters: silent up to (not including) the heartbeat.
	for tick := uint64(2); tick <= summaryHeartbeatTicks; tick++ {
		c := base
		c.Tick = tick
		emitTickSummary(&prevBody, &lastEmitTick, c)
	}
	if n := countLines(); n != 1 {
		t.Errorf("unchanged ticks 2..%d must stay silent, got %d line(s): %s",
			summaryHeartbeatTicks, n, buf.String())
	}

	// Heartbeat.
	c := base
	c.Tick = summaryHeartbeatTicks + 1
	emitTickSummary(&prevBody, &lastEmitTick, c)
	if n := countLines(); n != 2 {
		t.Errorf("tick %d should heartbeat, got %d line(s): %s", c.Tick, n, buf.String())
	}

	// Any changed counter emits immediately.
	c = base
	c.Tick = summaryHeartbeatTicks + 2
	c.NewRetransmits = 3
	emitTickSummary(&prevBody, &lastEmitTick, c)
	if n := countLines(); n != 3 {
		t.Errorf("changed counters must emit, got %d line(s): %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "retrans=3") {
		t.Errorf("changed value missing from output: %s", buf.String())
	}
}
