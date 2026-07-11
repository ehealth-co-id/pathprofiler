package score

import (
	"math"
	"testing"

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

	result := RankByTier(paths, prefix, topTier, midTier, defTier)
	if len(result) != 3 {
		t.Fatalf("got %d updates, want 3", len(result))
	}
	for _, u := range result {
		switch u.Neighbor {
		case "10.0.0.1":
			if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != topTier {
				t.Errorf("best path: got pref=%v, want %d", u.Prefs, topTier)
			}
		case "10.0.0.2":
			if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != midTier {
				t.Errorf("2nd path: got pref=%v, want %d", u.Prefs, midTier)
			}
		case "10.0.0.3":
			if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != defTier {
				t.Errorf("3rd path: got pref=%v, want %d", u.Prefs, defTier)
			}
		default:
			t.Errorf("unexpected neighbor %q", u.Neighbor)
		}
	}
}

func TestRankByTier_SinglePath(t *testing.T) {
	paths := []PathCost{
		{Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 1.0},
	}
	paths[0].Composite = composite(paths[0], DefaultWeights)

	result := RankByTier(paths, "192.168.5.0/24", 300, 200, 100)
	if len(result) != 1 {
		t.Fatalf("got %d updates, want 1", len(result))
	}
	// Single-path prefix must emit defaultTier, not nil — see RankByTier doc.
	if result[0].Prefs[0].LocalPref != 100 {
		t.Fatalf("single path got pref=%d, want 100 (defaultTier)", result[0].Prefs[0].LocalPref)
	}
}

func TestRankByTier_LowConfidence(t *testing.T) {
	// Confidence < 0.5 forces defaultTier for the best path.
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Confidence: 0.3},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 5000, Confidence: 0.3},
	}
	for i := range paths {
		paths[i].Composite = composite(paths[i], DefaultWeights)
	}

	result := RankByTier(paths, "192.168.5.0/24", 300, 200, 100)
	if len(result) != 2 {
		t.Fatalf("got %d updates, want 2", len(result))
	}
	for _, u := range result {
		if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != 100 {
			t.Errorf("low-confidence neighbor %s: got pref=%v, want default=100", u.Neighbor, u.Prefs)
		}
	}
}

func TestRankByTier_AllLost(t *testing.T) {
	// All candidates are lost probes → everyone pins to defaultTier.
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", Composite: lostProbeComposite, EgressLossRate: 1.0, Confidence: 0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", Composite: lostProbeComposite, EgressLossRate: 1.0, Confidence: 0},
	}
	result := RankByTier(paths, "192.168.5.0/24", 300, 200, 100)
	if len(result) != 2 {
		t.Fatalf("got %d updates, want 2", len(result))
	}
	for _, u := range result {
		if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != 100 {
			t.Errorf("all-lost neighbor %s: got pref=%v, want default=100", u.Neighbor, u.Prefs)
		}
	}
}

func TestRankByTier_CompositeUncertainty(t *testing.T) {
	// Two paths whose composite intervals overlap → they should get the same tier.
	paths := []PathCost{
		{NextHopIP: 1, Neighbor: "10.0.0.1", EgressRTTUs: 1000, Composite: 1000, CompositeErr: 200, Confidence: 1.0},
		{NextHopIP: 2, Neighbor: "10.0.0.2", EgressRTTUs: 1100, Composite: 1100, CompositeErr: 200, Confidence: 1.0},
	}
	result := RankByTier(paths, "192.168.5.0/24", 300, 200, 100)
	if len(result) != 2 {
		t.Fatalf("got %d updates, want 2", len(result))
	}
	// The overlap guard caps but does not promote — B stays at midTier (200)
	// because the guard only prevents worse-ranked paths from exceeding
	// the better-ranked path's tier, not the reverse.
	for _, u := range result {
		switch u.Neighbor {
		case "10.0.0.1":
			if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != 300 {
				t.Errorf("overlap best %s: got pref=%v, want top=300", u.Neighbor, u.Prefs)
			}
		case "10.0.0.2":
			if len(u.Prefs) != 1 || u.Prefs[0].LocalPref != 200 {
				t.Errorf("overlap 2nd %s: got pref=%v, want mid=200", u.Neighbor, u.Prefs)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// ConfidenceFromSamples tests
// ---------------------------------------------------------------------------

func TestConfidenceFromSamples(t *testing.T) {
	tests := []struct {
		samples  uint64
		expected float64
	}{
		{0, 0.0},
		{1, 0.2},
		{2, 0.4},
		{3, 0.6},
		{4, 0.8},
		{5, 1.0},
		{10, 1.0},
		{100, 1.0},
	}
	for _, tt := range tests {
		got := ConfidenceFromSamples(tt.samples)
		if math.Abs(got-tt.expected) > 1e-9 {
			t.Errorf("ConfidenceFromSamples(%d) = %f, want %f", tt.samples, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// CollapseByNeighbor tests
// ---------------------------------------------------------------------------

func TestCollapseByNeighbor_AverageConfidence(t *testing.T) {
	paths := []PathCost{
		{Neighbor: "10.0.0.1", EgressRTTUs: 1000, EgressLossRate: 0.01, Confidence: 1.0},
		{Neighbor: "10.0.0.1", EgressRTTUs: 2000, EgressLossRate: 0.02, Confidence: 1.0},
	}
	for i := range paths {
		paths[i].Composite = composite(paths[i], DefaultWeights)
	}
	result := CollapseByNeighbor(paths)
	if len(result) != 1 {
		t.Fatalf("got %d collapsed entries, want 1", len(result))
	}
	// RTT averaged, composite recomputed
	avgRTT := (1000.0 + 2000.0) / 2.0
	if math.Abs(result[0].EgressRTTUs-avgRTT) > 1e-6 {
		t.Errorf("collapsed RTT = %f, want %f", result[0].EgressRTTUs, avgRTT)
	}
}

// ---------------------------------------------------------------------------
// GroupByNeighbor tests
// ---------------------------------------------------------------------------

func TestGroupByNeighbor_MergesPrefixes(t *testing.T) {
	perPrefix := [][]actuate.NeighborTierUpdate{
		{
			{Neighbor: "10.0.0.1", Prefs: []actuate.PrefixPref{{Prefix: "192.168.1.0/24", LocalPref: 300}}},
		},
		{
			{Neighbor: "10.0.0.1", Prefs: []actuate.PrefixPref{{Prefix: "192.168.2.0/24", LocalPref: 100}}},
			{Neighbor: "10.0.0.2", Prefs: []actuate.PrefixPref{{Prefix: "192.168.1.0/24", LocalPref: 200}}},
		},
	}
	result := GroupByNeighbor(perPrefix)
	if len(result) != 2 {
		t.Fatalf("got %d grouped updates, want 2", len(result))
	}
	for _, u := range result {
		switch u.Neighbor {
		case "10.0.0.1":
			if len(u.Prefs) != 2 {
				t.Errorf("neighbor 10.0.0.1: got %d prefs, want 2", len(u.Prefs))
			}
		case "10.0.0.2":
			if len(u.Prefs) != 1 {
				t.Errorf("neighbor 10.0.0.2: got %d prefs, want 1", len(u.Prefs))
			}
		default:
			t.Errorf("unexpected neighbor %q", u.Neighbor)
		}
	}
}

// ---------------------------------------------------------------------------
// compositeIntervalsOverlap tests
// ---------------------------------------------------------------------------

func TestCompositeIntervalsOverlap(t *testing.T) {
	a := PathCost{Composite: 1000, CompositeErr: 200} // [800, 1200]
	b := PathCost{Composite: 1100, CompositeErr: 200} // [900, 1300]
	if !compositeIntervalsOverlap(a, b) {
		t.Error("expected overlap")
	}
	// Non-overlapping: [1000, 1400] vs [2000, 2400]
	c := PathCost{Composite: 1200, CompositeErr: 200}
	d := PathCost{Composite: 2200, CompositeErr: 200}
	if compositeIntervalsOverlap(c, d) {
		t.Error("expected no overlap")
	}
	// Zero error → no overlap (passive path vs cold probe semantics)
	e := PathCost{Composite: 1000, CompositeErr: 0}
	f := PathCost{Composite: 1100, CompositeErr: 0}
	if compositeIntervalsOverlap(e, f) {
		t.Error("expected no overlap for zero-err paths")
	}
}