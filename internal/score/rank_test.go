package score

import (
	"math"
	"testing"
	"time"

	"pathprofiler/internal/actuate"
)

// ---------------------------------------------------------------------------
// RankByTier tests
// ---------------------------------------------------------------------------

func TestRankByTier_ThreePaths(t *testing.T) {
	const (
		topTier  = 300
		midTier  = 200
		defTier  = 100
		prefix   = "192.168.5.0/24"
	)
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 5000, Confidence: 1.0},
		{NextHopIP: 3, Neighbor: "10.0.0.3", EgressRTTUs: 9000, Confidence: 1.0},
	}
	for i := range paths {
		paths[i].Composite = composite(paths[i], DefaultWeights)
	}

	updates := RankByTier(paths, prefix, topTier, midTier, defTier)
	if len(updates) != 3 {
		t.Fatalf("expected 3 neighbor updates, got %d", len(updates))
	}

	// Build lookup: neighbor -> localPref.
	lookup := make(map[string]int)
	for _, u := range updates {
		if len(u.Prefs) != 1 || u.Prefs[0].Prefix != prefix {
			t.Fatalf("unexpected prefix list for neighbor %s: %v", u.Neighbor, u.Prefs)
		}
		lookup[u.Neighbor] = u.Prefs[0].LocalPref
	}

	if lookup["10.0.0.1"] != topTier {
		t.Errorf("neighbor 10.0.0.1: want tier %d, got %d", topTier, lookup["10.0.0.1"])
	}
	if lookup["10.0.0.2"] != midTier {
		t.Errorf("neighbor 10.0.0.2: want tier %d, got %d", midTier, lookup["10.0.0.2"])
	}
	if lookup["10.0.0.3"] != defTier {
		t.Errorf("neighbor 10.0.0.3: want tier %d, got %d", defTier, lookup["10.0.0.3"])
	}
}

func TestRankByTier_TwoPaths(t *testing.T) {
	const (
		topTier = 300
		midTier = 200
		defTier = 100
		prefix  = "10.0.0.0/8"
	)
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 5000, Confidence: 1.0},
	}
	for i := range paths {
		paths[i].Composite = composite(paths[i], DefaultWeights)
	}

	updates := RankByTier(paths, prefix, topTier, midTier, defTier)
	if len(updates) != 2 {
		t.Fatalf("expected 2 neighbor updates, got %d", len(updates))
	}

	lookup := make(map[string]int)
	for _, u := range updates {
		lookup[u.Neighbor] = u.Prefs[0].LocalPref
	}

	if lookup["10.0.0.1"] != topTier {
		t.Errorf("neighbor 10.0.0.1: want tier %d, got %d", topTier, lookup["10.0.0.1"])
	}
	if lookup["10.0.0.2"] != midTier {
		t.Errorf("neighbor 10.0.0.2: want tier %d, got %d", midTier, lookup["10.0.0.2"])
	}
}

func TestRankByTier_SinglePath_EmitsDefault(t *testing.T) {
	// Finding 2 critical test: single-path prefix emits defaultTier, not nil.
	const (
		topTier = 300
		midTier = 200
		defTier = 100
		prefix  = "172.16.0.0/16"
	)
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 1.0, Composite: 1000},
	}

	updates := RankByTier(paths, prefix, topTier, midTier, defTier)
	if len(updates) != 1 {
		t.Fatalf("expected 1 neighbor update for single path, got %d", len(updates))
	}
	if updates[0].Neighbor != "10.0.0.1" {
		t.Errorf("neighbor: want 10.0.0.1, got %s", updates[0].Neighbor)
	}
	if len(updates[0].Prefs) != 1 {
		t.Fatalf("expected 1 pref, got %d", len(updates[0].Prefs))
	}
	if updates[0].Prefs[0].Prefix != prefix {
		t.Errorf("prefix: want %s, got %s", prefix, updates[0].Prefs[0].Prefix)
	}
	if updates[0].Prefs[0].LocalPref != defTier {
		t.Errorf("single path should emit defaultTier %d, got %d", defTier, updates[0].Prefs[0].LocalPref)
	}
}

func TestRankByTier_LowConfidenceBest(t *testing.T) {
	// Best path has low confidence -> gets defaultTier, not topTier.
	// 2nd path has high confidence -> gets midTier (not promoted to top).
	const (
		topTier = 300
		midTier = 200
		defTier = 100
		prefix  = "10.0.0.0/8"
	)
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 0.3},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 5000, Confidence: 1.0},
	}
	for i := range paths {
		paths[i].Composite = composite(paths[i], DefaultWeights)
	}

	updates := RankByTier(paths, prefix, topTier, midTier, defTier)
	lookup := make(map[string]int)
	for _, u := range updates {
		lookup[u.Neighbor] = u.Prefs[0].LocalPref
	}

	if lookup["10.0.0.1"] != defTier {
		t.Errorf("low-confidence best should get defaultTier %d, got %d", defTier, lookup["10.0.0.1"])
	}
	if lookup["10.0.0.2"] != midTier {
		t.Errorf("2nd-best should get midTier %d, got %d", midTier, lookup["10.0.0.2"])
	}
}

func TestRankByTier_DeterministicTieBreak(t *testing.T) {
	// Two paths with equal Composite -> stable order by NextHopIP.
	paths := []PathCost{
		{NextHopIP: 5, Neighbor: "10.0.0.5", EgressRTTUs: 1000, Composite: 1000, Confidence: 1.0},
		{NextHopIP: 3, Neighbor: "10.0.0.3", EgressRTTUs: 1000, Composite: 1000, Confidence: 1.0},
	}

	updates := RankByTier(paths, "10.0.0.0/8", 300, 200, 100)
	lookup := make(map[string]int)
	for _, u := range updates {
		lookup[u.Neighbor] = u.Prefs[0].LocalPref
	}

	// NextHopIP 3 < 5, so 10.0.0.3 is "best" and 10.0.0.5 is "2nd".
	if lookup["10.0.0.3"] != 300 {
		t.Errorf("tie-break: neighbor with NextHopIP=3 should be topTier, got %d", lookup["10.0.0.3"])
	}
	if lookup["10.0.0.5"] != 200 {
		t.Errorf("tie-break: neighbor with NextHopIP=5 should be midTier, got %d", lookup["10.0.0.5"])
	}
}

func TestRankByTier_SkipsEmptyNeighbor(t *testing.T) {
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "", EgressRTTUs: 1000, Composite: 1000, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 5000, Composite: 5000, Confidence: 1.0},
	}

	updates := RankByTier(paths, "10.0.0.0/8", 300, 200, 100)
	if len(updates) != 1 {
		t.Fatalf("expected 1 update (empty neighbor skipped), got %d", len(updates))
	}
	if updates[0].Neighbor != "10.0.0.2" {
		t.Errorf("neighbor: want 10.0.0.2, got %s", updates[0].Neighbor)
	}
}

func TestRankByTier_Empty(t *testing.T) {
	updates := RankByTier(nil, "10.0.0.0/8", 300, 200, 100)
	if updates != nil {
		t.Errorf("expected nil for empty paths, got %v", updates)
	}
}

// ---------------------------------------------------------------------------
// CollapseByNeighbor tests (Finding 1 -- critical missing tests)
// ---------------------------------------------------------------------------

func TestCollapseByNeighbor_SameNeighborMultiplePaths(t *testing.T) {
	// Finding 1 critical test: two paths with same Neighbor, different
	// NextHopIP/Composite -> collapsed into ONE PathCost with averaged metrics.
	paths := []PathCost{
		{
			NextHopIP:       1,
			Neighbor:        "10.0.0.1",
			EgressRTTUs:     1000,
			EgressLossRate:  0.01,
			IngressJitterUs: 100,
			IngressGapRate:  0.005,
			Composite:       1000,
			Confidence:      0.8,
		},
		{
			NextHopIP:       2,
			Neighbor:        "10.0.0.1",
			EgressRTTUs:     3000,
			EgressLossRate:  0.03,
			IngressJitterUs: 300,
			IngressGapRate:  0.015,
			Composite:       3000,
			Confidence:      0.6,
		},
	}

	collapsed := CollapseByNeighbor(paths)
	if len(collapsed) != 1 {
		t.Fatalf("expected 1 collapsed path, got %d", len(collapsed))
	}
	c := collapsed[0]

	if c.Neighbor != "10.0.0.1" {
		t.Errorf("neighbor: want 10.0.0.1, got %s", c.Neighbor)
	}
	if c.NextHopIP != 0 {
		t.Errorf("NextHopIP should be 0 after collapse, got %d", c.NextHopIP)
	}

	// Averaged metrics: (1000+3000)/2=2000, (0.01+0.03)/2=0.02, etc.
	if c.EgressRTTUs != 2000 {
		t.Errorf("EgressRTTUs: want 2000, got %f", c.EgressRTTUs)
	}
	if c.EgressLossRate != 0.02 {
		t.Errorf("EgressLossRate: want 0.02, got %f", c.EgressLossRate)
	}
	if c.IngressJitterUs != 200 {
		t.Errorf("IngressJitterUs: want 200, got %f", c.IngressJitterUs)
	}
	if c.IngressGapRate != 0.01 {
		t.Errorf("IngressGapRate: want 0.01, got %f", c.IngressGapRate)
	}

	// Max confidence.
	if c.Confidence != 0.8 {
		t.Errorf("Confidence: want 0.8, got %f", c.Confidence)
	}

	// Composite recomputed, NOT averaged from inputs.
	wantComposite := composite(c, DefaultWeights)
	if c.Composite != wantComposite {
		t.Errorf("Composite: want %f (recomputed), got %f", wantComposite, c.Composite)
	}
}

func TestCollapseByNeighbor_DistinctNeighbors(t *testing.T) {
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Composite: 1000, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 5000, Composite: 5000, Confidence: 1.0},
	}

	collapsed := CollapseByNeighbor(paths)
	if len(collapsed) != 2 {
		t.Fatalf("expected 2 collapsed paths (distinct neighbors pass through), got %d", len(collapsed))
	}
}

func TestCollapseByNeighbor_SinglePath(t *testing.T) {
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Composite: 1000, Confidence: 1.0},
	}

	collapsed := CollapseByNeighbor(paths)
	if len(collapsed) != 1 {
		t.Fatalf("expected 1 collapsed path, got %d", len(collapsed))
	}
	if collapsed[0].NextHopIP != 1 {
		t.Errorf("single path should pass through unchanged, NextHopIP: want 1, got %d", collapsed[0].NextHopIP)
	}
}

func TestCollapseByNeighbor_MaxConfidence(t *testing.T) {
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 0.8},
		{NextHopIP: 2, Neighbor: "10.0.0.1", EgressRTTUs: 3000, Confidence: 0.3},
	}

	collapsed := CollapseByNeighbor(paths)
	if len(collapsed) != 1 {
		t.Fatalf("expected 1 collapsed path, got %d", len(collapsed))
	}
	if collapsed[0].Confidence != 0.8 {
		t.Errorf("Confidence: want max=0.8, got %f", collapsed[0].Confidence)
	}
}

func TestCollapseByNeighbor_RecomputesComposite(t *testing.T) {
	// Collapsed Composite must equal composite(collapsed, DefaultWeights),
	// NOT the average of input Composite values.
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, EgressLossRate: 0.1, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.1", EgressRTTUs: 3000, EgressLossRate: 0.02, Confidence: 1.0},
	}

	collapsed := CollapseByNeighbor(paths)
	if len(collapsed) != 1 {
		t.Fatalf("expected 1 collapsed path, got %d", len(collapsed))
	}

	c := collapsed[0]
	wantComposite := composite(c, DefaultWeights)
	if c.Composite != wantComposite {
		t.Errorf("Composite should equal composite(collapsed, weights): want %f, got %f", wantComposite, c.Composite)
	}

	// Verify Composite is recomputed from the averaged metrics using
	// DefaultWeights, not inherited from input. With DefaultWeights the
	// formula is linear so composite(average) == average(composite) --
	// that's fine, the important invariant is that Composite reflects the
	// averaged metric values, not a copy from any single input path.
	wantFromMetrics := DefaultWeights.EgressRTT*c.EgressRTTUs +
		DefaultWeights.EgressLoss*c.EgressLossRate +
		DefaultWeights.IngressJitter*c.IngressJitterUs +
		DefaultWeights.IngressGap*c.IngressGapRate
	if c.Composite != wantFromMetrics {
		t.Errorf("Composite should be recomputed from averaged metrics: want %f, got %f", wantFromMetrics, c.Composite)
	}
}

// ---------------------------------------------------------------------------
// FromProbeResult + golden equivalence tests (Finding 3)
// ---------------------------------------------------------------------------

func TestFromProbeResult_Lost(t *testing.T) {
	pc := FromProbeResult(100, 0, true)

	if pc.EgressLossRate != 1.0 {
		t.Errorf("EgressLossRate: want 1.0, got %f", pc.EgressLossRate)
	}
	if pc.EgressRTTUs != 0 {
		t.Errorf("EgressRTTUs: want 0, got %f", pc.EgressRTTUs)
	}
	if pc.Confidence != 1.0 {
		t.Errorf("Confidence: want 1.0, got %f", pc.Confidence)
	}
	if pc.NextHopIP != 100 {
		t.Errorf("NextHopIP: want 100, got %d", pc.NextHopIP)
	}

	// Lost probes carry a sentinel composite to never outrank a measured path.
	if pc.Composite != lostProbeComposite {
		t.Errorf("Composite: want %f (lostProbeComposite), got %f", float64(lostProbeComposite), pc.Composite)
	}
}

func TestFromProbeResult_WithRTT(t *testing.T) {
	rtt := 5 * time.Millisecond
	pc := FromProbeResult(200, rtt, false)

	if pc.EgressRTTUs != 5000 {
		t.Errorf("EgressRTTUs: want 5000, got %f", pc.EgressRTTUs)
	}
	if pc.EgressLossRate != 0 {
		t.Errorf("EgressLossRate: want 0, got %f", pc.EgressLossRate)
	}
	if pc.Confidence != 1.0 {
		t.Errorf("Confidence: want 1.0, got %f", pc.Confidence)
	}

	// Composite = 1.0 * 5000 (RTT term only).
	wantComposite := DefaultWeights.EgressRTT * 5000
	if math.Abs(pc.Composite-wantComposite) > 1e-9 {
		t.Errorf("Composite: want %f, got %f", wantComposite, pc.Composite)
	}
}

func TestFromProbeResult_GoldenEquivalenceWithCompute(t *testing.T) {
	// Finding 3 critical test: feed Compute() with RTT-only inputs (zero
	// ingress, zero loss) and FromProbeResult with the same RTT; assert
	// Composite values are equal. Catches formula drift between the two paths.
	rttUs := uint64(5000) // 5ms

	// Compute with only RTT samples, everything else zero.
	computed := Compute(
		100,
		rttUs*10, 10, // srttUsSum, srttSamples (avg = 5000us)
		0, 0, // retransDelta, bytesAckedDelta
		0, 0, 0, 0, 0, // all ingress zero
		DefaultWeights,
	)

	// FromProbeResult with same RTT.
	probed := FromProbeResult(100, 5*time.Millisecond, false)

	if math.Abs(computed.Composite-probed.Composite) > 1e-9 {
		t.Errorf("golden equivalence: Compute Composite=%f != FromProbeResult Composite=%f", computed.Composite, probed.Composite)
	}
	if computed.EgressRTTUs != probed.EgressRTTUs {
		t.Errorf("golden equivalence: EgressRTTUs differ: Compute=%f, FromProbeResult=%f", computed.EgressRTTUs, probed.EgressRTTUs)
	}
}

// ---------------------------------------------------------------------------
// GroupByNeighbor tests
// ---------------------------------------------------------------------------

func TestGroupByNeighbor_TwoPrefixesSharedNeighbor(t *testing.T) {
	prefix1 := []actuate.NeighborTierUpdate{
		{Neighbor: "10.255.0.3", Prefs: []actuate.PrefixPref{
			{Prefix: "192.168.5.0/24", LocalPref: 300},
		}},
	}
	prefix2 := []actuate.NeighborTierUpdate{
		{Neighbor: "10.255.0.3", Prefs: []actuate.PrefixPref{
			{Prefix: "192.168.6.0/24", LocalPref: 200},
		}},
	}

	merged := GroupByNeighbor([][]actuate.NeighborTierUpdate{prefix1, prefix2})
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged update, got %d", len(merged))
	}
	if merged[0].Neighbor != "10.255.0.3" {
		t.Errorf("neighbor: want 10.255.0.3, got %s", merged[0].Neighbor)
	}
	if len(merged[0].Prefs) != 2 {
		t.Fatalf("expected 2 prefs after merge, got %d", len(merged[0].Prefs))
	}

	// Check both prefixes are present.
	prefMap := make(map[string]int)
	for _, p := range merged[0].Prefs {
		prefMap[p.Prefix] = p.LocalPref
	}
	if prefMap["192.168.5.0/24"] != 300 {
		t.Errorf("192.168.5.0/24: want 300, got %d", prefMap["192.168.5.0/24"])
	}
	if prefMap["192.168.6.0/24"] != 200 {
		t.Errorf("192.168.6.0/24: want 200, got %d", prefMap["192.168.6.0/24"])
	}
}

func TestGroupByNeighbor_DistinctNeighbors(t *testing.T) {
	prefix1 := []actuate.NeighborTierUpdate{
		{Neighbor: "10.255.0.3", Prefs: []actuate.PrefixPref{
			{Prefix: "192.168.5.0/24", LocalPref: 300},
		}},
	}
	prefix2 := []actuate.NeighborTierUpdate{
		{Neighbor: "10.255.0.4", Prefs: []actuate.PrefixPref{
			{Prefix: "192.168.6.0/24", LocalPref: 200},
		}},
	}

	merged := GroupByNeighbor([][]actuate.NeighborTierUpdate{prefix1, prefix2})
	if len(merged) != 2 {
		t.Fatalf("expected 2 separate updates, got %d", len(merged))
	}

	lookup := make(map[string]int)
	for _, u := range merged {
		lookup[u.Neighbor] = u.Prefs[0].LocalPref
	}
	if lookup["10.255.0.3"] != 300 {
		t.Errorf("10.255.0.3: want 300, got %d", lookup["10.255.0.3"])
	}
	if lookup["10.255.0.4"] != 200 {
		t.Errorf("10.255.0.4: want 200, got %d", lookup["10.255.0.4"])
	}
}

func TestRankByTier_AllLost_EmitsDefaultForAll(t *testing.T) {
	const (
		topTier  = 300
		midTier  = 200
		defTier  = 100
		prefix   = "10.0.0.0/8"
	)
	// Three lost-probe paths: all have sentinel composite, no passive data.
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressLossRate: 1.0, Composite: lostProbeComposite, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressLossRate: 1.0, Composite: lostProbeComposite, Confidence: 1.0},
		{NextHopIP: 3, Neighbor: "10.0.0.3", EgressLossRate: 1.0, Composite: lostProbeComposite, Confidence: 1.0},
	}

	updates := RankByTier(paths, prefix, topTier, midTier, defTier)
	if len(updates) != 3 {
		t.Fatalf("expected 3 neighbor updates, got %d", len(updates))
	}

	for _, u := range updates {
		if len(u.Prefs) != 1 {
			t.Fatalf("neighbor %s: expected 1 pref, got %d", u.Neighbor, len(u.Prefs))
		}
		if u.Prefs[0].LocalPref != defTier {
			t.Errorf("neighbor %s: want defaultTier %d, got %d", u.Neighbor, defTier, u.Prefs[0].LocalPref)
		}
	}
}

func TestRankByTier_LostNeverBeatsMeasured(t *testing.T) {
	const (
		topTier  = 300
		midTier  = 200
		defTier  = 100
		prefix   = "10.0.0.0/8"
	)
	// One lost probe (sentinel) vs one measured path with poor RTT.
	lost := PathCost{
		NextHopIP: 1, Neighbor: "10.0.0.1",
		EgressLossRate: 1.0, Composite: lostProbeComposite, Confidence: 1.0,
	}
	measured := PathCost{
		NextHopIP: 2, Neighbor: "10.0.0.2",
		EgressRTTUs: 10000, // 10ms -> composite = 10000
		Confidence:  1.0,
	}
	measured.Composite = composite(measured, DefaultWeights)

	updates := RankByTier([]PathCost{lost, measured}, prefix, topTier, midTier, defTier)
	lookup := make(map[string]int)
	for _, u := range updates {
		lookup[u.Neighbor] = u.Prefs[0].LocalPref
	}

	if lookup["10.0.0.2"] != topTier {
		t.Errorf("measured path should get topTier %d, got %d", topTier, lookup["10.0.0.2"])
	}
	// Lost gets defaultTier (or midTier if the measured path gets top and
	// there are only 2 candidates — RankByTier assigns midTier to the
	// 2nd-ranked path. Either is fine as long as the measured path wins.
	if lookup["10.0.0.1"] == topTier {
		t.Errorf("lost probe got topTier, should never outrank measured path")
	}
}
