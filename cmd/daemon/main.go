//go:build linux

// pathprofiler-daemon: userspace control loop for the hybrid dual-plane
// path profiler. Polls the BPF maps, deltas the raw counters, scores each
// candidate next-hop, and actuates via FRR route-maps with hysteresis.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"time"

	"pathprofiler/internal/actuate"
	"pathprofiler/internal/bgp"
	"pathprofiler/internal/config"
	"pathprofiler/internal/loader"
	"pathprofiler/internal/maps"
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

	prevEgress := make(map[maps.PathKey]maps.EgressStats)
	prevIngress := make(map[uint32]maps.IngressStats)

	var cachedRIB map[string][]bgp.Path
	var cachedUnderlay ospf.Underlay
	lastTopoFetch := time.Time{} // zero forces first fetch
	xdpRetried := false          // track whether we've retried XDP after startup

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

			// --- Populate dst_to_nexthop for BPF sockops ---
			populateDstToNexthop(reader, prevEgress)
		}

		if len(cachedRIB) == 0 {
			continue // no RIB data yet
		}

		inScope := bgp.InScope(cachedRIB, cfg.Scope.Prefixes)

		// --- 2. Passive scores from BPF maps ---
		egressNow, err := reader.AllEgress()
		if err != nil {
			log.Printf("read egress map: %v", err)
			continue
		}
		ingressNow, err := reader.AllIngress()
		if err != nil {
			log.Printf("read ingress map: %v", err)
			continue
		}

		passiveByPrefix := make(map[string][]score.PathCost)
		passiveLegs := make(map[string]bool) // F1: "neighbor:interface" keys

		for pk, cur := range egressNow {
			prev := prevEgress[pk]

			srttSamplesDelta := diff(cur.SrttSamples, prev.SrttSamples)
			srttSumDelta := diff(cur.SrttUsSum, prev.SrttUsSum)
			retransDelta := diff(cur.Retransmits, prev.Retransmits)
			bytesDelta := diff(cur.BytesAcked, prev.BytesAcked)

			ing := ingressNow[pk.NextHopIP]
			prevIng := prevIngress[pk.NextHopIP]
			iatSamplesDelta := diff(ing.IatSamples, prevIng.IatSamples)
			iatSumDelta := diff(ing.IatSumNs, prevIng.IatSumNs)
			iatSqDelta := diff(ing.IatSqSumNs, prevIng.IatSqSumNs)
			gapsDelta := diff(ing.SeqGaps, prevIng.SeqGaps)
			packetsDelta := diff(ing.Packets, prevIng.Packets)

			c := score.Compute(pk.NextHopIP,
				srttSumDelta, srttSamplesDelta, retransDelta, bytesDelta,
				iatSumDelta, iatSqDelta, iatSamplesDelta, gapsDelta, packetsDelta,
				score.DefaultWeights)

			nhStr := uint32ToIPStr(pk.NextHopIP)
			subnetStr := uint32ToIPStr(pk.DstSubnet)

			prefix := bgp.PrefixForSubnet(inScope, subnetStr)
			if prefix == "" {
				continue
			}

			neighbor, resolvedIface := findNeighborForPath(inScope, prefix, nhStr, cachedUnderlay)
			if neighbor == "" {
				continue
			}
			c.Neighbor = neighbor
			passiveByPrefix[prefix] = append(passiveByPrefix[prefix], c)

			// F1 per-leg tracking.
			if resolvedIface != "" {
				passiveLegs[neighbor+":"+resolvedIface] = true
			} else {
				// BPF returned loopback directly — kernel did ECMP
				// resolution below the loopback; conservatively mark
				// all legs as having traffic to avoid over-probing
				// (strictly cheaper failure mode per F1).
				if paths := cachedUnderlay.PathsTo(nhStr); len(paths) > 0 {
					for _, pp := range paths {
						passiveLegs[neighbor+":"+pp.Interface] = true
					}
				}
			}
		}

		prevEgress = egressNow
		prevIngress = ingressNow

		// --- 3. Cold-path probes (F1: per-leg gate) ---
		coldByPrefix := make(map[string][]score.PathCost)
		for prefix, paths := range inScope {
			for _, p := range paths {
				physPaths, _ := netutil.ResolvePaths(p.NextHop, cachedUnderlay)
				for _, pp := range physPaths {
					// F1: gate per-leg — skip if this specific leg has
					// live traffic, regardless of sibling-leg status.
					if !gateColdProbeLeg(p.Neighbor, pp.Interface, passiveLegs) {
						continue
					}
					r, err := actuate.ProbeNextHop(pp.Interface, p.NextHop, probePortVal, probeTimeout)
					if err != nil {
						log.Printf("probe %s via %s: %v", p.NextHop, pp.Interface, err)
						continue
					}
					synthetic := score.FromProbeResult(ipStrToUint32(p.NextHop), r.RTT, r.Lost)
					synthetic.Neighbor = p.Neighbor
					coldByPrefix[prefix] = append(coldByPrefix[prefix], synthetic)
					log.Printf("cold probe %s via %s (iface %s): rtt=%v lost=%v",
						p.Neighbor, p.NextHop, pp.Interface, r.RTT, r.Lost)
				}
			}
		}

		// --- 4. Rank per prefix -> group by neighbor ---
		var perPrefixUpdates [][]actuate.NeighborTierUpdate
		for prefix := range inScope {
			candidates := passiveByPrefix[prefix]
			candidates = append(candidates, coldByPrefix[prefix]...)
			candidates = score.CollapseByNeighbor(candidates)
			updates := score.RankByTier(candidates, prefix,
				cfg.Tiers.Local, cfg.Tiers.Dedicated, cfg.Tiers.Default)
			if len(updates) > 0 {
				perPrefixUpdates = append(perPrefixUpdates, updates)
			}
		}
		updates := score.GroupByNeighbor(perPrefixUpdates)

		// --- 5. Actuate per neighbor ---
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
		}

		// --- 6. Cleanup (Drained -> Absent) ---
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

// populateDstToNexthop sweeps passive egress destinations and populates the
// dst_to_nexthop BPF map via `ip route get`. Runs at probeInterval cadence
// (alongside topology refresh) because route changes are slow.
func populateDstToNexthop(reader *maps.Reader, egressNow map[maps.PathKey]maps.EgressStats) {
	if reader.DstToNexthop() == nil {
		return // map not available (older daemon or first boot)
	}
	// Dedupe destination IPs from passive egress keys.
	seen := make(map[uint32]bool)
	for pk := range egressNow {
		seen[pk.DstSubnet] = true // ponytail: use /24 subnet, not full IP, to keep sweep small
	}
	for dst := range seen {
		dstStr := uint32ToIPStr(dst)
		nh, err := netutil.ResolveNexthop(dstStr)
		if err != nil {
			continue
		}
		nhU32 := ipStrToUint32(nh)
		if err := reader.UpdateDstToNexthop(dst, nhU32); err != nil {
			log.Printf("populate dst_to_nexthop[%s]: %v", dstStr, err)
		}
	}
}

// ifacesFromUnderlay extracts the deduplicated set of (interface, gateway-IP)
// pairs from OSPF underlay data for XDP attachment.
func ifacesFromUnderlay(underlay ospf.Underlay) []loader.IfaceAttach {
	seen := make(map[string]bool)
	var result []loader.IfaceAttach
	for _, paths := range underlay {
		for _, pp := range paths {
			key := pp.Interface + ":" + pp.PhysicalNH
			if seen[key] {
				continue
			}
			seen[key] = true
			ip := net.ParseIP(pp.PhysicalNH).To4()
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

// findNeighborForPath resolves a passive egress key's next-hop to a BGP
// neighbor. Returns (neighbor, resolvedInterface). If BPF returned the
// loopback directly, resolvedInterface is "" (caller conservatively marks
// all legs). If BPF returned a physical OSPF NH, resolvedInterface is set
// to the specific PhysicalPath.Interface.
func findNeighborForPath(inScope map[string][]bgp.Path, prefix, nhStr string, underlay ospf.Underlay) (neighbor, resolvedIface string) {
	// Direct match: BPF next-hop is a BGP loopback in the RIB.
	for _, p := range inScope[prefix] {
		if p.NextHop == nhStr {
			return p.Neighbor, ""
		}
	}

	// F2: BPF returned a physical OSPF NH — reverse lookup to find the loopback.
	loopback, err := underlay.LoopbackForPhysicalNH(nhStr)
	if err != nil {
		log.Printf("resolve physical NH %s: %v (skipping)", nhStr, err)
		return "", ""
	}
	if loopback == "" {
		return "", ""
	}

	for _, p := range inScope[prefix] {
		if p.NextHop == loopback {
			// Find the PhysicalPath whose PhysicalNH matches.
			for _, pp := range underlay.PathsTo(loopback) {
				if pp.PhysicalNH == nhStr {
					return p.Neighbor, pp.Interface
				}
			}
			return p.Neighbor, ""
		}
	}
	return "", ""
}

// gateColdProbeLeg returns true if this specific physical leg should be
// cold-probed (i.e., it does NOT have passive traffic). Extracted for
// testability (F1).
func gateColdProbeLeg(neighbor, iface string, passiveLegs map[string]bool) bool {
	return !passiveLegs[neighbor+":"+iface]
}

func diff(cur, prev uint64) uint64 {
	if cur < prev {
		return 0 // counter reset (LRU eviction/reload) -- treat as no delta this tick, not negative
	}
	return cur - prev
}

// uint32ToIPStr converts the uint32 stored in BPF path_key to a dotted-quad.
// ponytail: assumes host byte order per bpf/common.h:9, but egress_sockops.bpf.c:81
// stores network order on some kernels -- known gap, centralized here so the
// fix is one swap. Ceiling: wrong order on affected kernels; upgrade path is
// bpf_ntohl at the BPF writer or a swap here.
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
