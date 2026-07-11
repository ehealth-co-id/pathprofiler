//go:build linux

// pathprofiler-daemon: userspace control loop for the hybrid dual-plane
// path profiler. Polls the BPF maps, deltas the raw counters, scores each
// candidate next-hop, and actuates via FRR route-maps with hysteresis.
package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"sort"
	"time"

	"pathprofiler/internal/actuate"
	"pathprofiler/internal/bgp"
	"pathprofiler/internal/config"
	"pathprofiler/internal/loader"
	"pathprofiler/internal/maps"
	"pathprofiler/internal/metrics"
	"pathprofiler/internal/netutil"
	"pathprofiler/internal/ospf"
	"pathprofiler/internal/score"
)

func main() {
	pollInterval := flag.Duration("poll", 2*time.Second, "map polling interval")
	minDwell := flag.Duration("min-dwell", 30*time.Second, "minimum time between actuations per neighbor")
	minMarginPct := flag.Float64("min-margin", 0.20, "required composite-cost improvement to switch, as a fraction")
	configPath := flag.String("config", "/etc/pathprofiler.yaml", "path to YAML config file")
	probeIntervalSec := flag.Int("probe-interval", 0, "cold-probe and topology-refresh interval in seconds (overrides YAML; 0 = use YAML)")
	probePort := flag.Int("probe-port", 0, "UDP port for cold-path probes (overrides YAML; 0 = use YAML)")
	probeTimeoutSec := flag.Int("probe-timeout", 0, "cold-probe timeout in seconds (overrides YAML; 0 = use YAML)")
	probeCount := flag.Int("probe-count", 0, "number of probes per burst (overrides YAML; 0 = use YAML)")
	probeCountMax := flag.Int("probe-count-max", 0, "maximum accumulated probes for adaptive SPRT (overrides YAML; 0 = use YAML)")
	probeDelta := flag.Float64("probe-delta", 0, "indifference band in loss-rate units (overrides YAML; 0 = use YAML)")
	probeAlpha := flag.Float64("probe-alpha", 0, "SPRT Type-I error rate (overrides YAML; 0 = use YAML)")
	probeBeta := flag.Float64("probe-beta", 0, "SPRT Type-II error rate (overrides YAML; 0 = use YAML)")
	probeEMAHalfLifeSec := flag.Int("probe-ema-half-life", 0, "half-life in seconds for accumulated cold-probe SPRT evidence across ticks (overrides YAML; 0 = use YAML)")
	probeTimeoutMultiplierFlag := flag.Float64("probe-timeout-multiplier", 0, "adaptive per-probe timeout = multiplier * RTT baseline (overrides YAML; 0 = use YAML)")
	probeMinTimeoutMsFlag := flag.Int("probe-min-timeout-ms", 0, "floor for the adaptive per-probe timeout, in milliseconds (overrides YAML; 0 = use YAML)")
	transitEMAHalfLife := flag.Duration("transit-ema-half-life", 5*time.Minute, "EMA half-life for transit loss-rate smoothing")
	verbose := flag.Bool("verbose", false, "log per-path cold-probe detail")
	flag.Parse()
	// ponytail: --min-margin is no longer used in the tier-based design
	// (RankByTier replaces ShouldSwitch), but kept for CLI compatibility.
	_ = minMarginPct

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// CLI overrides for probe settings: 0 means "use YAML".
	probeInterval := time.Duration(cfg.Probe.IntervalSeconds) * time.Second
	if *probeIntervalSec > 0 {
		probeInterval = time.Duration(*probeIntervalSec) * time.Second
	}
	probePortVal := cfg.Probe.Port
	if *probePort > 0 {
		probePortVal = *probePort
	}
	probeTimeout := time.Duration(cfg.Probe.TimeoutSeconds) * time.Second
	if *probeTimeoutSec > 0 {
		probeTimeout = time.Duration(*probeTimeoutSec) * time.Second
	}

	// CLI overrides for adaptive probe config: non-zero / non-default means "use CLI".
	adaptiveMinN := cfg.Probe.MinCount
	if *probeCount > 0 {
		adaptiveMinN = *probeCount
	}
	adaptiveMaxN := cfg.Probe.MaxCount
	if *probeCountMax > 0 {
		adaptiveMaxN = *probeCountMax
	}
	adaptiveDelta := cfg.Probe.Delta
	if *probeDelta > 0 {
		adaptiveDelta = *probeDelta
	}
	adaptiveAlpha := cfg.Probe.Alpha
	if *probeAlpha > 0 {
		adaptiveAlpha = *probeAlpha
	}
	adaptiveBeta := cfg.Probe.Beta
	if *probeBeta > 0 {
		adaptiveBeta = *probeBeta
	}
	probeEMAHalfLife := time.Duration(cfg.Probe.EMAHalfLifeSeconds) * time.Second
	if *probeEMAHalfLifeSec > 0 {
		probeEMAHalfLife = time.Duration(*probeEMAHalfLifeSec) * time.Second
	}
	probeTimeoutMultiplier := cfg.Probe.TimeoutRTTMultiplier
	if *probeTimeoutMultiplierFlag > 0 {
		probeTimeoutMultiplier = *probeTimeoutMultiplierFlag
	}
	probeMinTimeout := time.Duration(cfg.Probe.MinTimeoutMs) * time.Millisecond
	if *probeMinTimeoutMsFlag > 0 {
		probeMinTimeout = time.Duration(*probeMinTimeoutMsFlag) * time.Millisecond
	}

	// --- BPF loader: load programs, pin maps, attach to kernel ---
	// Load does NOT attach XDP -- that's deferred to AttachXDP so it can
	// be retried when gateway interfaces become available (FRR may not be
	// ready at startup).
	bpfLoader, err := loader.Load()
	if err != nil {
		log.Fatalf("load bpf: %v", err)
	}
	defer bpfLoader.Close()

	// Best-effort XDP attachment at startup. If vtysh isn't ready yet,
	// this fails gracefully and the main loop retries once underlay
	// data is available.
	startupIfaces, err := discoverGatewayIfaces()
	if err != nil {
		log.Printf("discover gateway ifaces for XDP (non-fatal, will retry): %v", err)
	} else {
		bpfLoader.AttachXDP(startupIfaces)
	}

	reader, err := maps.Open()
	if err != nil {
		log.Fatalf("open maps: %v", err)
	}
	defer reader.Close()

	// F4: dampener keyed per-neighbor (forced by Phase 5's neighbor-atomic
	// actuation). Trade-off: sibling prefixes sharing a BGP peer are coupled
	// -- prefix A's legitimate change on neighbor X is suppressed if prefix B
	// on X flapped recently. Accept because partial route-map rewrite isn't
	// possible with FRR's one-route-map-per-neighbor-per-direction model.
	dampener := actuate.NewDampener(*minDwell)

	// F3: bootstrap appliedNeighbors from FRR's actual state, not empty.
	// Without this, a daemon restart orphans every route-map the prior
	// process applied, and Drained -> Absent cleanup silently stops working.
	appliedNeighbors, err := actuate.ListAppliedNeighbors()
	if err != nil {
		log.Printf("bootstrap applied neighbors (non-fatal): %v", err)
		appliedNeighbors = make(map[string]bool)
	}

	prevTransit := make(map[maps.PathKey]maps.TransitStats)
	transitEMA := metrics.NewEMAStore(10*time.Second, *transitEMAHalfLife)

	var cachedRIB map[string][]bgp.Path
	var cachedUnderlay ospf.Underlay
	lastTopoFetch := time.Time{} // zero forces first fetch
	xdpRetried := false          // track whether we've retried XDP after startup
	tcAttached := false          // track whether TC egress programs have been attached
	tcDoneStaleCleanup := false  // track whether stale TC detach ran on first topo refresh
	firstTopoRefresh := true     // tripwire: log dst_to_nexthop count after first populate

	// appliedActiveComposite/appliedActiveNeighbor mirror, per prefix, the
	// neighbor last confirmed to hold top tier (cfg.Tiers.Local) in FRR's
	// live route-maps -- confirmed meaning a dampener-allowed, successfully
	// applied actuate.SetNeighborTiers call, not just this tick's raw
	// ranking. Written only in step 7 (actuation), read in step 4
	// (cold-probe) as this tick's SPRT baseline. Because the mirror only
	// changes when the dampener actually lets an update through, its
	// identity is rate-limited by --min-dwell instead of flapping with
	// every tick's EMA noise or a tier-flip that never actually made it
	// into FRR.
	appliedActiveComposite := make(map[string]float64)
	appliedActiveNeighbor := make(map[string]string)

	// probeAccumulators carries decayed SPRT evidence per (prefix, iface,
	// next-hop) leg across ticks -- see actuate.ProbeAccumulator. Not pruned
	// when a leg disappears; bounded by the number of distinct legs ever
	// seen, negligible in practice (same convention as appliedActiveComposite).
	probeAccumulators := make(map[actuate.ProbeKey]*actuate.ProbeAccumulator)

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()

	for range ticker.C {
		// --- 1. Topology refresh (slow cadence) ---
		if time.Since(lastTopoFetch) >= probeInterval {
			rib, err := bgp.FetchRIB()
			if err != nil {
				log.Printf("fetch BGP RIB (keeping stale cache): %v", err)
			} else {
				cachedRIB = rib
			}
			loopbacks := collectLoopbacks(cachedRIB)
			underlay, err := ospf.FetchTopo(loopbacks)
			if err != nil {
				log.Printf("fetch OSPF topo (keeping stale cache): %v", err)
			} else {
				cachedUnderlay = underlay
			}
			lastTopoFetch = time.Now()

			// --- Retry XDP attachment once underlay is available ---
			if !xdpRetried && len(cachedUnderlay) > 0 {
				xdpRetried = true
				ifaces := ifacesFromUnderlay(cachedUnderlay)
				if len(ifaces) > 0 {
					bpfLoader.AttachXDP(ifaces)
				}
			}

			// --- Detach stale TC programs from prior runs before first attach ---
			if !tcDoneStaleCleanup && len(cachedUnderlay) > 0 {
				tcDoneStaleCleanup = true
				tcIfaces := uniqueTcIfaces(cachedUnderlay)
				loader.DetachStaleTC(tcIfaces)
			}

			// --- Retry TC attach once underlay is available ---
			if !tcAttached && len(cachedUnderlay) > 0 {
				tcIfaces := uniqueTcIfaces(cachedUnderlay)
				if len(tcIfaces) > 0 {
					if err := bpfLoader.AttachTC(tcIfaces); err != nil {
						log.Printf("TC attach (retrying next tick): %v", err)
						// Do NOT set tcAttached=true here — failure must retry.
					} else {
						tcAttached = true
						log.Printf("TC attached to %d interfaces: %v", len(tcIfaces), tcIfaces)
					}
				}
			}

			// --- Populate dst_to_nexthop for BPF programs ---
			inScopeRefresh := bgp.InScope(cachedRIB, cfg.Scope.Prefixes)
			populateDstToNexthopFromRIB(reader, inScopeRefresh)

			// Tripwire: log entry count after first populate.
			if firstTopoRefresh {
				firstTopoRefresh = false
				log.Printf("dst_to_nexthop populated: %d entries (prefixes=%d)", dstToNexthopEntryCount, len(inScopeRefresh))
				if dstToNexthopEntryCount == 0 || dstToNexthopEntryCount < len(inScopeRefresh) {
					log.Printf("dst_to_nexthop: population may be incomplete — check ip route get for in-scope prefixes")
				}
			}
		}

		if len(cachedRIB) == 0 {
			continue // no RIB data yet
		}

		inScope := bgp.InScope(cachedRIB, cfg.Scope.Prefixes)

		// --- 2. Transit loss pipeline ---
		transitNow, err := reader.AllTransit()
		if err != nil {
			log.Printf("read transit map: %v", err)
			continue
		}

		transitDeltas := make(map[maps.PathKey]metrics.TransitDelta)
		for pk, cur := range transitNow {
			prev := prevTransit[pk]
			transitDeltas[pk] = metrics.TransitDelta{
				Segments:    diff(cur.Segments, prev.Segments),
				Retransmits: diff(cur.Retransmits, prev.Retransmits),
			}
		}
		transitEMA.Update(time.Now(), *pollInterval, transitDeltas)
		emaSnapshot := transitEMA.Snapshot()
		log.Printf("transit map: %d entries, ema snapshot: %d paths", len(transitNow), len(emaSnapshot))
		prevTransit = transitNow

		// Tripwire: if dst_to_nexthop misses are dropping everything.
		dd, ddErr := reader.DebugDropped()
		if ddErr == nil && dd > 0 && len(transitNow) == 0 {
			log.Printf("transit: all packets dropped (dst_to_nexthop miss) — debug_dropped=%d", dd)
		}

		// Verbose: log transit diagnostic every tick regardless of entries.
		if *verbose {
			dd, ddErr := reader.DebugDropped()
			ddVal := uint64(0)
			if ddErr == nil {
				ddVal = dd
			}
			log.Printf("[verbose] transit diag: map_entries=%d ema_paths=%d debug_dropped=%d interface_count=%d",
				len(transitNow), len(emaSnapshot), ddVal, len(cachedUnderlay))
			if len(transitNow) > 0 {
				for pk, st := range transitNow {
					log.Printf("[verbose] transit entry: nh=%s dst_subnet=%s seg=%d retrans=%d last_update_ago=%s",
						uint32ToIPStr(pk.NextHopIP), uint32ToIPStr(pk.DstSubnet),
						st.Segments, st.Retransmits,
						time.Since(time.Unix(0, int64(st.LastUpdateNs))).Round(time.Second))
				}
			}
		}

		// Log transit debug counters for dst_to_nexthop misses.
		if len(transitNow) > 0 {
			for pk, st := range transitNow {
				if st.Retransmits > 0 {
					log.Printf("transit raw: nh=%s dst_subnet=%s seg=%d retrans=%d",
						uint32ToIPStr(pk.NextHopIP), uint32ToIPStr(pk.DstSubnet),
						st.Segments, st.Retransmits)
				}
			}
		}

		// --- 4. Cold-path probes ---
		// activeComposite is seeded from appliedActiveComposite (the neighbor
		// last confirmed applied at top tier for this prefix, as of the
		// previous tick's actuation step), so the SPRT has a real baseline
		// from the second tick onward. Falls back to +Inf (fixed minN burst,
		// OutcomeUndecided) on the first tick for a prefix, or once a prefix
		// loses its confirmed-active neighbor, since there's nothing yet to
		// compare against.

		coldByPrefix := make(map[string][]score.PathCost)
		{
			totalPaths := 0
			for _, pp := range inScope {
				totalPaths += len(pp)
			}
			log.Printf("cold probe: scanning %d prefixes, %d BGP paths", len(inScope), totalPaths)
		}
		for prefix, paths := range inScope {
			activeComposite, hasBaseline := appliedActiveComposite[prefix]
			activeNeighbor := appliedActiveNeighbor[prefix]
			if !hasBaseline {
				activeComposite = math.Inf(1)
			}
			for _, p := range paths {
				physPaths, rpErr := netutil.ResolvePaths(p.NextHop, cachedUnderlay)
				if rpErr != nil {
					log.Printf("probe %s (neighbor %s, prefix %s): resolve paths: %v", p.NextHop, p.Neighbor, prefix, rpErr)
				}
				for _, pp := range physPaths {
					if *verbose {
						log.Printf("[verbose] probing prefix=%s neighbor=%s nexthop=%s iface=%s gateway=%s",
							prefix, p.Neighbor, p.NextHop, pp.Interface, pp.GatewayIP)
					}
					key := actuate.ProbeKey{Prefix: prefix, Iface: pp.Interface, NextHop: p.NextHop}
					acc := probeAccumulators[key]
					if acc == nil {
						acc = &actuate.ProbeAccumulator{}
						probeAccumulators[key] = acc
					}
					r, outcome, err := actuate.ProbeNextHopAccumulating(pp.Interface, p.NextHop, probePortVal,
						probeTimeout, adaptiveMinN, adaptiveMaxN, acc, time.Now(), probeEMAHalfLife,
						probeTimeoutMultiplier, probeMinTimeout, activeComposite,
						adaptiveDelta, adaptiveAlpha, adaptiveBeta, score.DefaultWeights.EgressLoss)
					if err != nil {
						log.Printf("probe %s via %s: %v", p.NextHop, pp.Interface, err)
						continue
					}
					synthetic := score.FromProbeResult(ipStrToUint32(p.NextHop), r.RTT, r.LossRate, r.LossRateErr)
					synthetic.Neighbor = p.Neighbor
					coldByPrefix[prefix] = append(coldByPrefix[prefix], synthetic)
					baselineStr := "none (no active path for this prefix yet)"
					if hasBaseline {
						baselineStr = fmt.Sprintf("%.0f vs active neighbor %s", activeComposite, activeNeighbor)
					}
					log.Printf("cold probe %s via %s (iface %s): rtt=%v lossRate=%.2f err=±%.3f probes=%d/%d (cumulative) outcome=%s baseline=%s",
						p.Neighbor, p.NextHop, pp.Interface, r.RTT, r.LossRate, r.LossRateErr, r.ProbeCount, adaptiveMaxN, outcome, baselineStr)
				}
			}
		}

		// --- 5. Transit override + visibility log ---
		// Real forwarded-traffic loss replaces the synthetic probe loss rate
		// on matching (prefix, loopback) entries. Confidence is bumped from
		// transit segment count so RankByTier's Confidence>=0.5 gate can
		// promote the neighbor above defaultTier.
		transitSeen := make(map[string]bool)
		// F6: skip-reason counters so the "NO Confidence>0" warning below can
		// name which gate dropped every ema entry, instead of that having to
		// be re-diagnosed by hand from raw logs each time it fires.
		var skippedZeroWindow, skippedNoPrefix, skippedAmbiguousNH, skippedNoColdMatch int
		for pk, ema := range emaSnapshot {
			if ema.WindowSegments == 0 {
				skippedZeroWindow++
				continue
			}
			prefix := bgp.PrefixForSubnet(inScope, uint32ToIPStr(pk.DstSubnet))
			if prefix == "" {
				skippedNoPrefix++
				continue
			}
			nextHopStr := uint32ToIPStr(pk.NextHopIP)
			logKey := nextHopStr + ":" + prefix
			nhToMatch := pk.NextHopIP
			if cachedUnderlay != nil {
				if lb, err := cachedUnderlay.LoopbackForGateway(nextHopStr); err != nil {
					log.Printf("transit override: ambiguous NH %s: %v — skipping", nextHopStr, err)
					skippedAmbiguousNH++
					continue
				} else if lb != "" {
					nhToMatch = ipStrToUint32(lb)
				}
			}
			if !transitSeen[logKey] {
				transitSeen[logKey] = true
				log.Printf("transit nexthop=%s prefix=%s seg=%d ema_loss=%.4f err=±%.4f",
					nextHopStr, prefix, ema.WindowSegments, ema.EMALossRate, ema.EMALossRateErr)
			}
			matched := false
			for i := range coldByPrefix[prefix] {
				if coldByPrefix[prefix][i].NextHopIP == nhToMatch {
					matched = true
					pc := &coldByPrefix[prefix][i]
					pc.EgressLossRate = ema.EMALossRate
					pc.CompositeErr = score.DefaultWeights.EgressLoss * ema.EMALossRateErr
					if ema.EMALossRate > 0 || ema.WindowSegments >= 5 {
						pc.Confidence = score.ConfidenceFromSamples(ema.WindowSegments)
					}
					pc.RecomputeComposite(score.DefaultWeights)
				}
			}
			if !matched {
				skippedNoColdMatch++
			}
		}

		// Self-check: warn if no entry has Confidence>0 after transit override.
		hasConfidence := false
		for _, entries := range coldByPrefix {
			for _, pc := range entries {
				if pc.Confidence > 0 {
					hasConfidence = true
					break
				}
			}
			if hasConfidence {
				break
			}
		}
		if len(coldByPrefix) > 0 && !hasConfidence {
			log.Printf("transit override: NO cold-probe entry has Confidence>0 — "+
				"transit data may not be flowing (check TC attachment) "+
				"[ema_paths=%d zeroWindow=%d noPrefix=%d ambiguousNH=%d noColdMatch=%d]",
				len(emaSnapshot), skippedZeroWindow, skippedNoPrefix, skippedAmbiguousNH, skippedNoColdMatch)
		}

		// --- 6. Rank per prefix -> group by neighbor ---
		// candidateComposite records every candidate's Composite for this
		// tick, keyed by prefix then neighbor, so step 7 can look up "what
		// was this neighbor's composite for this prefix, this tick" once it
		// knows which update actually got applied -- without re-deriving it.
		candidateComposite := make(map[string]map[string]float64)
		var perPrefixUpdates [][]actuate.NeighborTierUpdate
		for prefix := range inScope {
			candidates := coldByPrefix[prefix]
			candidates = score.CollapseByNeighbor(candidates)
			candidateComposite[prefix] = make(map[string]float64, len(candidates))
			for _, c := range candidates {
				candidateComposite[prefix][c.Neighbor] = c.Composite
			}
			updates := score.RankByTier(candidates, prefix,
				cfg.Tiers.Local, cfg.Tiers.Dedicated, cfg.Tiers.Default)
			if len(updates) > 0 {
				perPrefixUpdates = append(perPrefixUpdates, updates)
			}
		}
		updates := score.GroupByNeighbor(perPrefixUpdates)

		// --- 7. Actuate per neighbor ---
		thisTickNeighbors := make(map[string]bool)
		for _, u := range updates {
			thisTickNeighbors[u.Neighbor] = true
			if !dampener.Allow(u.Neighbor) {
				log.Printf("neighbor %s: tier change suppressed by dampener", u.Neighbor)
				continue
			}
			if err := actuate.SetNeighborTiers(u); err != nil {
				log.Printf("neighbor %s: set tiers failed: %v", u.Neighbor, err)
				continue
			}
			dampener.Record(u.Neighbor)
			log.Printf("neighbor %s: applied %d prefix tiers", u.Neighbor, len(u.Prefs))

			syncAppliedActiveMirror(appliedActiveNeighbor, appliedActiveComposite,
				candidateComposite, u, cfg.Tiers.Local)
		}

		// --- 8. Cleanup (Drained -> Absent) ---
		for nb := range appliedNeighbors {
			if !thisTickNeighbors[nb] {
				if err := actuate.RemoveNeighborTiers(nb); err != nil {
					log.Printf("cleanup neighbor %s: %v", nb, err)
				} else {
					log.Printf("neighbor %s: removed (drained)", nb)
				}
			}
		}
		appliedNeighbors = thisTickNeighbors
	}
}

// populateDstToNexthopFromRIB iterates in-scope BGP prefixes and writes one
// LPM trie entry per prefix into dst_to_nexthop. For each prefix, the
// daemon resolves the next-hop for a representative IP in the prefix
// (network address + 1, e.g. 10.255.0.1 for 10.255.0.0/24). The LPM trie
// lookup with prefixlen=32 in BPF matches any destination in the prefix.
//
// This decouples dst_to_nexthop population from having any passive egress
// data — it works from the RIB alone, fixing the bootstrap deadlock where
// transit traffic can never populate the map because the map is needed for
// transit traffic to produce data.
var dstToNexthopEntryCount int

func populateDstToNexthopFromRIB(reader *maps.Reader, inScope map[string][]bgp.Path) {
	if reader.DstToNexthop() == nil {
		return
	}
	count := 0
	for prefix := range inScope {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		// Pick the first usable host address in the prefix as the
		// representative. ip route get <this_ip> resolves the
		// kernel's next-hop for the prefix, and the LPM trie
		// covers all destinations within it.
		rep := ipNet.IP.Mask(ipNet.Mask)
		if len(rep) != 4 {
			continue
		}
		rep3 := make(net.IP, 4)
		copy(rep3, rep)
		rep3[3]++ // first usable host
		repStr := rep3.String()

		nh, err := netutil.ResolveNexthop(repStr)
		if err != nil {
			log.Printf("populate dst_to_nexthop[%s]: resolve nexthop: %v", repStr, err)
			continue
		}
		nextHopU32 := ipStrToUint32(nh)
		daddr := uint32(rep3[0]) | uint32(rep3[1])<<8 | uint32(rep3[2])<<16 | uint32(rep3[3])<<24
		ones, _ := ipNet.Mask.Size()
		if err := reader.UpdateDstToNexthop(uint32(ones), daddr, nextHopU32); err != nil {
			log.Printf("populate dst_to_nexthop[%s/%d]: %v", repStr, ones, err)
			continue
		}
		count++
	}
	dstToNexthopEntryCount = count
}

// ifacesFromUnderlay extracts the deduplicated set of (interface, gateway-IP)
// pairs from OSPF underlay data for XDP attachment.
func ifacesFromUnderlay(underlay ospf.Underlay) []loader.IfaceAttach {
	seen := make(map[string]bool)
	var result []loader.IfaceAttach
	for _, paths := range underlay {
		for _, pp := range paths {
			key := pp.Interface + ":" + pp.GatewayIP
			if seen[key] {
				continue
			}
			seen[key] = true
			ip := net.ParseIP(pp.GatewayIP).To4()
			if ip == nil {
				continue
			}
			result = append(result, loader.IfaceAttach{
				Iface:     pp.Interface,
				GatewayIP: uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]),
			})
		}
	}
	return result
}

// uniqueTcIfaces extracts the deduplicated set of interface names from OSPF
// underlay data, for TC egress program attachment.
func uniqueTcIfaces(underlay ospf.Underlay) []string {
	seen := make(map[string]bool)
	var result []string
	for _, paths := range underlay {
		for _, pp := range paths {
			if !seen[pp.Interface] {
				seen[pp.Interface] = true
				result = append(result, pp.Interface)
			}
		}
	}
	return result
}

// collectLoopbacks extracts the distinct BGP next-hop IPs from the RIB.
func collectLoopbacks(rib map[string][]bgp.Path) []string {
	seen := make(map[string]bool)
	var result []string
	for _, paths := range rib {
		for _, p := range paths {
			if !seen[p.NextHop] {
				seen[p.NextHop] = true
				result = append(result, p.NextHop)
			}
		}
	}
	sort.Strings(result)
	return result
}

// discoverGatewayIfaces fetches the BGP RIB and OSPF underlay to find
// which physical interfaces face gateway next-hops and their IPs. Returns
// the deduplicated set of (interface, gateway-IP) pairs. The daemon needs
// these to attach XDP to the right interfaces and populate iface_gateway_map.
func discoverGatewayIfaces() ([]loader.IfaceAttach, error) {
	rib, err := bgp.FetchRIB()
	if err != nil {
		return nil, fmt.Errorf("fetch BGP RIB: %w", err)
	}
	loopbacks := collectLoopbacks(rib)
	underlay, err := ospf.FetchTopo(loopbacks)
	if err != nil {
		return nil, fmt.Errorf("fetch OSPF topo: %w", err)
	}

	ifaces := ifacesFromUnderlay(underlay)
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("no OSPF underlay paths found")
	}
	return ifaces, nil
}

func diff(cur, prev uint64) uint64 {
	if cur < prev {
		return 0 // counter reset (LRU eviction/reload) -- treat as no delta this tick, not negative
	}
	return cur - prev
}

// syncAppliedActiveMirror updates appliedActiveNeighbor/appliedActiveComposite
// for every prefix touched by u, an actuate.NeighborTierUpdate that was just
// confirmed applied (dampener-allowed, SetNeighborTiers succeeded). A prefix
// gains a mirror entry for u.Neighbor when u assigns it topTier, or when
// u.Neighbor is that prefix's only candidate this tick -- RankByTier
// deliberately assigns single-path prefixes defaultTier, never topTier (see
// rank.go), but a sole candidate is unambiguously "the active path" even at
// defaultTier, since there's nothing else it could be. If u assigns a prefix
// some other tier and u.Neighbor was the previously-recorded active neighbor
// for that prefix, the entry is cleared rather than left pointing at a
// neighbor that just got demoted. Prefixes u doesn't mention, or where the
// recorded active neighbor is some other neighbor entirely, are left
// untouched -- FRR's route-map for those didn't change this tick.
func syncAppliedActiveMirror(appliedActiveNeighbor map[string]string, appliedActiveComposite map[string]float64,
	candidateComposite map[string]map[string]float64, u actuate.NeighborTierUpdate, topTier int) {
	for _, pp := range u.Prefs {
		soleCandidate := len(candidateComposite[pp.Prefix]) == 1
		if pp.LocalPref == topTier || soleCandidate {
			appliedActiveNeighbor[pp.Prefix] = u.Neighbor
			appliedActiveComposite[pp.Prefix] = candidateComposite[pp.Prefix][u.Neighbor]
		} else if appliedActiveNeighbor[pp.Prefix] == u.Neighbor {
			delete(appliedActiveNeighbor, pp.Prefix)
			delete(appliedActiveComposite, pp.Prefix)
		}
	}
}

// uint32ToIPStr converts the uint32 stored in BPF path_key to a dotted-quad.
// ponytail: assumes host byte order per bpf/common.h:9.
// F5 trip-wire: TestUint32ToIPStr_RoundTrip asserts current behavior; a future
// BPF-side fix will make this test fail, signaling the conversion needs updating.
func uint32ToIPStr(v uint32) string {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String()
}

// ipStrToUint32 is the inverse, used to build FromProbeResult's nextHop arg.
func ipStrToUint32(s string) uint32 {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
