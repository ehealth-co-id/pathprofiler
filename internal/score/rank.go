package score

import (
	"sort"

	"pathprofiler/internal/actuate"
)

// CollapseByNeighbor pre-aggregates multiple PathCost entries that share the
// same Neighbor for one prefix into a single PathCost per neighbor. This is
// the necessary step before RankByTier when cold-path probing is active:
// OSPF-ECMP produces N synthetic PathCosts per (neighbor, prefix), one per
// underlay interface, all carrying the same BGP neighbor. Without collapse,
// a map keyed by Neighbor silently drops all but one.
//
// Aggregation: average EgressRTTUs, EgressLossRate, IngressJitterUs,
// IngressGapRate across the group; take max Confidence; recompute Composite
// via composite(). NextHopIP set to 0 (collapsed -- the actuation unit is the
// BGP neighbor/loopback, not the physical next-hop).
//
// Per the master plan (Phase 7, "Open question"): "for v1 we average -- log the
// per-path probe results but actuate per loopback." This is that averaging,
// owned and tested here rather than orphaned.
func CollapseByNeighbor(paths []PathCost) []PathCost {
	if len(paths) == 0 {
		return nil
	}

	type group struct {
		paths []PathCost
		n     int
	}

	byNeighbor := make(map[string]*group)
	var order []string // preserve insertion order for determinism

	for _, p := range paths {
		if p.Neighbor == "" {
			continue
		}
		g, ok := byNeighbor[p.Neighbor]
		if !ok {
			g = &group{}
			byNeighbor[p.Neighbor] = g
			order = append(order, p.Neighbor)
		}
		g.paths = append(g.paths, p)
		g.n++
	}

	result := make([]PathCost, 0, len(order))
	for _, nb := range order {
		g := byNeighbor[nb]
		paths := g.paths

		// ponytail: cold probe and passive path under same neighbor are different
		// legs (F1 gate in main.go); if that gate weakens, this skip hides a
		// genuinely complementary measurement.
		hasUntainted := false
		for _, p := range paths {
			if p.Confidence > 0 {
				hasUntainted = true
				break
			}
		}
		if hasUntainted {
			filtered := make([]PathCost, 0, len(paths))
			for _, p := range paths {
				if p.Confidence > 0 {
					filtered = append(filtered, p)
				}
			}
			paths = filtered
		}

		if len(paths) == 1 {
			result = append(result, paths[0])
			continue
		}

		var rtt, loss, jitter, gap, conf float64
		for _, p := range paths {
			rtt += p.EgressRTTUs
			loss += p.EgressLossRate
			jitter += p.IngressJitterUs
			gap += p.IngressGapRate
			if p.Confidence > conf {
				conf = p.Confidence
			}
		}
		n := float64(len(paths))
		collapsed := PathCost{
			Neighbor:        nb,
			EgressRTTUs:     rtt / n,
			EgressLossRate:  loss / n,
			IngressJitterUs: jitter / n,
			IngressGapRate:  gap / n,
			Confidence:      conf,
		}
		collapsed.Composite = composite(collapsed, DefaultWeights)
		result = append(result, collapsed)
	}

	return result
}

// RankByTier ranks paths for one prefix by Composite (lower = better) and
// assigns tiers: best -> topTier, 2nd -> midTier, rest -> defaultTier.
// Paths with Confidence < 0.5 are still ranked but never promoted above
// default (a noisy cold probe can't become the top-tier path).
//
// SINGLE-PATH PREFIXES EMIT defaultTier (not nil). This is a deliberate
// deviation from the original plan's "return nil for single-path" rule:
// returning nil leaves the neighbor's previously-applied tier (e.g. topTier
// from a prior tick when it had 2 competing paths) stale in FRR indefinitely,
// because GroupByNeighbor omits nil-returning prefixes and SetNeighborTiers
// only rewrites seqs present in the update. Emitting defaultTier for
// single-path prefixes ensures the route-map is rewritten with the correct
// (default) local-pref every tick. Combined with SetNeighborTiers's
// stateless clear-then-re-add, stale seqs cannot persist across ticks.
//
// Skips paths with empty Neighbor (defensive; Phase 2 filters them).
// Returns []actuate.NeighborTierUpdate: one per distinct neighbor in the
// ranked prefix.
//
// Caller should call CollapseByNeighbor first if cold-path probes are present
// (multiple paths per neighbor).
func RankByTier(paths []PathCost, prefix string,
	topTier, midTier, defaultTier int) []actuate.NeighborTierUpdate {

	filtered := make([]PathCost, 0, len(paths))
	for _, p := range paths {
		if p.Neighbor != "" {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == 0 {
		return nil
	}

	// All-lost guard: every candidate is a lost probe (no passive data to
	// rank against). Pin everyone to defaultTier so we don't churn BGP on
	// noise by picking an arbitrary winner via tie-break.
	allLost := true
	for _, p := range filtered {
		if p.EgressLossRate < 1.0 || p.EgressRTTUs > 0 || p.IngressJitterUs > 0 || p.IngressGapRate > 0 {
			allLost = false
			break
		}
	}
	if allLost {
		result := make([]actuate.NeighborTierUpdate, 0, len(filtered))
		for _, p := range filtered {
			result = append(result, actuate.NeighborTierUpdate{
				Neighbor: p.Neighbor,
				Prefs:    []actuate.PrefixPref{{Prefix: prefix, LocalPref: defaultTier}},
			})
		}
		return result
	}

	// ponytail: deterministic tie-break by NextHopIP -- test-friendly,
	// no real-world ranking consequence.
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Composite != filtered[j].Composite {
			return filtered[i].Composite < filtered[j].Composite
		}
		return filtered[i].NextHopIP < filtered[j].NextHopIP
	})

	type tiered struct {
		neighbor string
		pref     actuate.PrefixPref
	}
	var tieredPaths []tiered

	if len(filtered) == 1 {
		tieredPaths = append(tieredPaths, tiered{
			neighbor: filtered[0].Neighbor,
			pref:     actuate.PrefixPref{Prefix: prefix, LocalPref: defaultTier},
		})
	} else {
		// Monotonicity: a worse-ranked path must never receive a higher
		// local-pref than a better-ranked one. BGP picks the highest
		// local-pref, so without this invariant a low-confidence best path
		// demoted to defaultTier (100) would lose to a 2nd-best cold
		// probe promoted to midTier (200) -- tier inversion. We compute
		// the tier each rank would get, then clamp it to <= the tier
		// actually assigned to the rank above. If the best is demoted,
		// every subsequent path is capped at defaultTier too.
		prevTier := topTier // ranks can only go down from here
		for i, p := range filtered {
			var tierByRank int
			switch {
			case i == 0:
				if p.Confidence >= 0.5 {
					tierByRank = topTier
				} else {
					tierByRank = defaultTier
				}
			case i == 1:
				if p.Confidence >= 0.5 {
					tierByRank = midTier
				} else {
					tierByRank = defaultTier
				}
			default:
				tierByRank = defaultTier
			}
			if tierByRank > prevTier {
				tierByRank = prevTier
			}
			prevTier = tierByRank
			tieredPaths = append(tieredPaths, tiered{
				neighbor: p.Neighbor,
				pref:     actuate.PrefixPref{Prefix: prefix, LocalPref: tierByRank},
			})
		}
	}

	byNeighbor := make(map[string][]actuate.PrefixPref)
	var nbOrder []string
	for _, t := range tieredPaths {
		if _, exists := byNeighbor[t.neighbor]; !exists {
			nbOrder = append(nbOrder, t.neighbor)
		}
		byNeighbor[t.neighbor] = append(byNeighbor[t.neighbor], t.pref)
	}

	result := make([]actuate.NeighborTierUpdate, 0, len(nbOrder))
	for _, nb := range nbOrder {
		result = append(result, actuate.NeighborTierUpdate{
			Neighbor: nb,
			Prefs:    byNeighbor[nb],
		})
	}
	return result
}

// GroupByNeighbor merges per-prefix NeighborTierUpdate lists into one
// update per neighbor across all prefixes. Each neighbor's route-map is
// rewritten atomically by SetNeighborTiers, so grouping matches the
// actuation unit.
func GroupByNeighbor(perPrefix [][]actuate.NeighborTierUpdate) []actuate.NeighborTierUpdate {
	byNeighbor := make(map[string][]actuate.PrefixPref)
	var nbOrder []string

	for _, updates := range perPrefix {
		for _, u := range updates {
			if _, exists := byNeighbor[u.Neighbor]; !exists {
				nbOrder = append(nbOrder, u.Neighbor)
			}
			byNeighbor[u.Neighbor] = append(byNeighbor[u.Neighbor], u.Prefs...)
		}
	}

	result := make([]actuate.NeighborTierUpdate, 0, len(nbOrder))
	for _, nb := range nbOrder {
		result = append(result, actuate.NeighborTierUpdate{
			Neighbor: nb,
			Prefs:    byNeighbor[nb],
		})
	}
	return result
}
