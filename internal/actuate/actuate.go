// Package actuate applies routing decisions. Two mechanisms, matching the
// plan's Phase 4:
//   - Local ECMP weight changes via `ip route replace ... nexthop weight`.
//   - BGP Local-Pref/MED changes via FRR.
//
// DESIGN CHANGE from the plan: the plan called for FRR's "northbound
// gRPC/YANG API". Modern FRR's northbound story (mgmtd + YANG) is real but
// immature for ad-hoc per-prefix attribute pokes from an external daemon --
// tooling and docs for this specific use case are thin, and getting it wrong
// risks a malformed transaction wedging mgmtd. vtysh scripting is uglier but
// well-trodden and its failure modes (bad command syntax) are safe and
// visible immediately, vs a partially-applied YANG transaction. Documenting
// this as a known tradeoff: revisit gRPC/YANG once FRR's northbound API
// matures, not implementing around an assumption that it's production-ready
// today.
package actuate

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// PrefixPref is one (destination prefix, local-pref) pair for a neighbor.
type PrefixPref struct {
	Prefix    string // e.g. "192.168.5.0/24"
	LocalPref int
}

// NeighborTierUpdate groups all prefix-scoped local-pref changes for one
// BGP neighbor in one tick. This is the unit the daemon applies: one
// neighbor = one route-map = one vtysh session. Phase 6's RankByTier
// must produce []NeighborTierUpdate (not []TierUpdate per prefix).
type NeighborTierUpdate struct {
	Neighbor string
	Prefs    []PrefixPref
}

// runVtysh executes a vtysh script. Package-level var so tests can swap it.
var runVtysh = func(script string) ([]byte, error) {
	return exec.Command("vtysh", "-c", script).CombinedOutput()
}

type Dampener struct {
	lastSwitch map[string]time.Time // keyed by "neighbor-IP" (one entry per BGP peer)
	minDwell   time.Duration
}

func NewDampener(minDwell time.Duration) *Dampener {
	return &Dampener{lastSwitch: make(map[string]time.Time), minDwell: minDwell}
}

func (d *Dampener) Allow(routeID string) bool {
	last, ok := d.lastSwitch[routeID]
	if !ok {
		return true
	}
	return time.Since(last) >= d.minDwell
}

func (d *Dampener) Record(routeID string) {
	d.lastSwitch[routeID] = time.Now()
}

// SetECMPWeights applies `ip route replace <dst> nexthop via <nh1> weight <w1> nexthop via <nh2> weight <w2>`.
// Weights are integers 1-255 per iproute2 semantics; caller is responsible
// for normalizing composite path costs into that range (inverse-cost
// weighting: lower cost -> higher weight).
func SetECMPWeights(dstCIDR string, nextHops []string, weights []int) error {
	if len(nextHops) != len(weights) {
		return fmt.Errorf("nextHops/weights length mismatch")
	}
	args := []string{"route", "replace", dstCIDR}
	for i, nh := range nextHops {
		args = append(args, "nexthop", "via", nh, "weight", fmt.Sprintf("%d", weights[i]))
	}
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace failed: %w, output: %s", err, string(out))
	}
	return nil
}

// Fixed-slot route-map layout (see SetNeighborTiers).
const (
	slotStep      = 10                   // slot k (0-based) uses sequence number (k+1)*slotStep
	minSlots      = 32                   // slot-count floor; grows with the prefix set, never shrinks
	catchAllSeq   = 65535                // final pass-through sequence
	neverList     = "PATHPROFILER-NEVER" // prefix-list matched by unassigned slots
	neverListSeq  = 5
	neverListCIDR = "192.0.2.1/32" // RFC 5737 documentation range: cannot occur as a real prefix here
)

var (
	slotMu     sync.Mutex
	slotCounts = map[string]int{} // route-map name -> grow-only slot count
)

// slotsFor returns the route-map's slot count: at least minSlots, at least
// needed, and never smaller than a previous call for the same route-map.
// Grow-only because shrinking the slot set would require deleting sequences,
// which is exactly what this design must never do while the map is bound.
func slotsFor(name string, needed int) int {
	slotMu.Lock()
	defer slotMu.Unlock()
	n := slotCounts[name]
	if needed > n {
		n = needed
	}
	if n < minSlots {
		n = minSlots
	}
	slotCounts[name] = n
	return n
}

// SetNeighborTiers sets local-pref for multiple destination prefixes on one
// neighbor in a single vtysh config session. Generates ONE route-map named
// PATHPROFILER-<neighbor-slug> whose sequences ("slots") are a fixed,
// grow-only set:
//   - slot k (sequence (k+1)*slotStep) carries
//     `match ip address prefix-list PATHPROFILER-SCOPE-<prefix-slug>` +
//     `set local-preference <pref>` when a prefix is assigned to it;
//   - an unassigned slot matches PATHPROFILER-NEVER, a prefix-list that cannot
//     match real traffic, so the slot is inert and evaluation falls through;
//   - `permit 65535` with no match/set lets out-of-scope prefixes pass through
//     unmodified (without it the route-map's implicit final deny would
//     blackhole them).
//
// The route-map is rewritten IN PLACE: this function deletes nothing.
// Deleting a route-map -- or one of its sequences -- while it is still bound
// to a live BGP session is a use-after-free on FRR builds before 10.2.4
// (upstream #19191, "Do not try to reuse freed route-maps"); reproduced here
// as a SIGSEGV in route_map_apply_ext from bgp_update when an inbound UPDATE
// lands between the delete and the re-add. Detaching the binding before
// deleting avoids the crash but still perturbs the BGP table on every
// actuation (measured 440 table-version bumps per 60 detach/delete/re-add
// rewrites, vs 0 in place). Re-declaring a sequence *replaces* its match/set
// clauses (verified on FRR 10.2.3 and 10.6.2), so rewriting every slot leaves
// FRR exactly at this tick's decision without any deletion.
//
// Empty updates -> no-op (return nil, no subprocess).
// Legacy state left by an older daemon is cleared once at startup by
// NormalizeApplied. Deliberately does NOT `write memory` (see package doc).
func SetNeighborTiers(u NeighborTierUpdate) error {
	if len(u.Prefs) == 0 {
		return nil
	}

	name := "PATHPROFILER-" + sanitizeRouteMapName(u.Neighbor)
	slots := slotsFor(name, len(u.Prefs))

	var b strings.Builder

	b.WriteString("configure terminal\n")

	// Declare prefix-lists for each in-scope prefix. Fixed seq 5: this list
	// is shared across every neighbor route-map that matches the same scope
	// prefix, so each neighbor's SetNeighborTiers call re-declares it every
	// tick. Without an explicit seq, FRR auto-assigns the next free one on
	// each re-declaration instead of recognizing an identical entry already
	// exists, piling up duplicate seq 5/10/15/... entries with identical
	// content. Pinning seq 5 makes the re-declaration idempotent.
	for _, pp := range u.Prefs {
		prefixSlug := sanitizeRouteMapName(pp.Prefix)
		fmt.Fprintf(&b, "ip prefix-list PATHPROFILER-SCOPE-%s seq 5 permit %s\n", prefixSlug, pp.Prefix)
	}
	// The never-match list used by unassigned slots (idempotent, pinned seq).
	fmt.Fprintf(&b, "ip prefix-list %s seq %d permit %s\n", neverList, neverListSeq, neverListCIDR)

	// Rewrite every slot in place. Slot count is monotone, so a shrinking
	// prefix set turns trailing slots inert instead of deleting them.
	for k := 0; k < slots; k++ {
		fmt.Fprintf(&b, "route-map %s permit %d\n", name, (k+1)*slotStep)
		if k < len(u.Prefs) {
			prefixSlug := sanitizeRouteMapName(u.Prefs[k].Prefix)
			fmt.Fprintf(&b, " match ip address prefix-list PATHPROFILER-SCOPE-%s\n", prefixSlug)
			fmt.Fprintf(&b, " set local-preference %d\n", u.Prefs[k].LocalPref)
		} else {
			fmt.Fprintf(&b, " match ip address prefix-list %s\n", neverList)
		}
		b.WriteString("exit\n")
	}

	// Catch-all: permit without match/set so out-of-scope prefixes pass through.
	fmt.Fprintf(&b, "route-map %s permit %d\n", name, catchAllSeq)
	b.WriteString("exit\n")

	// Re-assert the inbound binding: idempotent when already bound, and it
	// self-heals a binding lost for any reason. Never detach-and-delete here.
	b.WriteString("router bgp\n")
	fmt.Fprintf(&b, " neighbor %s route-map %s in\n", u.Neighbor, name)
	b.WriteString("exit\n")
	b.WriteString("exit\n")

	out, err := runVtysh(b.String())
	if err != nil {
		return fmt.Errorf("vtysh neighbor-tier update failed: %w, output: %s", err, string(out))
	}
	return nil
}

// sanitizeRouteMapName replaces characters invalid in FRR route-map / prefix-list names.
// ponytail: O(n) over short IP strings, ceiling irrelevant.
func sanitizeRouteMapName(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch c {
		case '.', '/':
			out = append(out, '-')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// Disable removes probe reliance for a path after middlebox-induced
// probe/live divergence is detected (the plan's residual-uncertainty
// mitigation) -- falls back to egress-only (sock_ops) scoring for that
// next-hop until re-enabled.
type ProbeState struct {
	Disabled map[uint32]bool
}

// RemoveNeighborTiers removes the per-neighbor route-map and detaches it
// from the BGP neighbor. Owns the Drained -> Absent transition that Phase 5
// explicitly deferred to Phase 7. Emits:
//
//	`no neighbor <ip> route-map PATHPROFILER-<slug> in`
//	`no route-map PATHPROFILER-<slug>`
//
// Deliberately does NOT `write memory` (see package doc).
func RemoveNeighborTiers(neighbor string) error {
	slug := sanitizeRouteMapName(neighbor)
	var b strings.Builder
	b.WriteString("configure terminal\n")
	// `no neighbor ... route-map ... in` is only valid inside `router bgp`,
	// not at the top level of configure terminal (contrast the plain
	// `neighbor ... route-map ... in` form used elsewhere — that one also
	// belongs in router bgp; SetNeighborTiers enters it for the same
	// reason). Issuing it at the top level makes vtysh exit 1 on the
	// command, so the subsequent `no route-map` never runs.
	b.WriteString("router bgp\n")
	fmt.Fprintf(&b, "no neighbor %s route-map PATHPROFILER-%s in\n", neighbor, slug)
	b.WriteString("exit\n")
	fmt.Fprintf(&b, "no route-map PATHPROFILER-%s\n", slug)
	b.WriteString("exit\n")
	_, err := runVtysh(b.String())
	if err != nil {
		return fmt.Errorf("vtysh remove neighbor tiers failed: %w", err)
	}
	return nil
}

func (p *ProbeState) DisableProbing(nextHop uint32) {
	if p.Disabled == nil {
		p.Disabled = make(map[uint32]bool)
	}
	p.Disabled[nextHop] = true
}

func (p *ProbeState) IsProbingDisabled(nextHop uint32) bool {
	return p.Disabled != nil && p.Disabled[nextHop]
}

// AppliedBinding is one `neighbor <ip> route-map <name> in` attachment found
// in a running-config.
type AppliedBinding struct {
	Neighbor string
	RouteMap string
}

// ParseAppliedBindings parses "show running-config" output for PATHPROFILER-*
// route-map neighbor attachments. It returns the *actual* route-map name from
// each binding rather than re-deriving it from the neighbor address: a map
// created by a differently-named/older daemon (or by hand) would otherwise be
// left bound and undeleted by NormalizeApplied. Sorted by route-map name for
// deterministic scripts.
func ParseAppliedBindings(config string) []AppliedBinding {
	var out []AppliedBinding
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		// Match: "neighbor X.X.X.X route-map PATHPROFILER-<...> in"
		if !strings.HasPrefix(line, "neighbor ") {
			continue
		}
		fields := strings.Fields(line)
		// neighbor <ip> route-map <name> in
		if len(fields) < 5 || fields[2] != "route-map" || fields[4] != "in" {
			continue
		}
		if !strings.HasPrefix(fields[3], "PATHPROFILER-") {
			continue
		}
		if net.ParseIP(fields[1]) == nil {
			continue
		}
		out = append(out, AppliedBinding{Neighbor: fields[1], RouteMap: fields[3]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RouteMap < out[j].RouteMap })
	return out
}

// ParseAppliedRouteMaps returns the names of every PATHPROFILER-* route-map
// *defined* in a running-config (bound or not). NormalizeApplied deletes these
// in addition to whatever is bound: an unbound orphan (for example one left
// behind when a removal detached the binding but failed to delete the map)
// would otherwise linger forever. Sorted and de-duplicated.
func ParseAppliedRouteMaps(config string) []string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		// Match: "route-map PATHPROFILER-<...> permit|deny <seq>"
		if len(fields) < 4 || fields[0] != "route-map" {
			continue
		}
		if name := fields[1]; strings.HasPrefix(name, "PATHPROFILER-") {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ParseAppliedPrefixLists returns the names of the PATHPROFILER-* prefix-lists
// present in a running-config, so NormalizeApplied can garbage-collect them.
// Sorted for deterministic output.
func ParseAppliedPrefixLists(config string) []string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		// Match: "ip prefix-list PATHPROFILER-<...> seq N permit ..."
		if len(fields) < 3 || fields[0] != "ip" || fields[1] != "prefix-list" {
			continue
		}
		// Only lists this daemon owns.
		if name := fields[2]; name == neverList || strings.HasPrefix(name, "PATHPROFILER-SCOPE-") {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// NormalizeApplied removes every route-map and prefix-list this daemon owns,
// once at startup, so the in-place slot rewrite starts from a clean slate: a
// previous process may have left sequences from an older layout (for example
// more slots than the current prefix set needs, whose stale match/set clauses
// an in-place rewrite would never touch). Returns the number of bindings
// detached.
//
// Order matters and mirrors the removal path: detach every binding, delete the
// by-then-unbound route-maps, and only then delete the prefix-lists. Nothing is
// ever deleted while something still references it, because deleting a
// route-map that a live session is applying is a use-after-free in FRR (see
// SetNeighborTiers).
func NormalizeApplied() (int, error) {
	out, err := runVtysh("show running-config")
	if err != nil {
		return 0, fmt.Errorf("actuate: vtysh show running-config: %w", err)
	}
	cfg := string(out)
	bindings := ParseAppliedBindings(cfg)
	lists := ParseAppliedPrefixLists(cfg)
	// Every PATHPROFILER-* map must go: the bound ones (detached first) plus
	// any unbound orphan left behind by a partial removal.
	names := make(map[string]bool)
	for _, n := range ParseAppliedRouteMaps(cfg) {
		names[n] = true
	}
	for _, bd := range bindings {
		names[bd.RouteMap] = true
	}
	if len(names) == 0 && len(lists) == 0 {
		return 0, nil
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)

	var b strings.Builder
	b.WriteString("configure terminal\n")
	// 1. Detach every binding first, using the map name actually in the
	// config (not one re-derived from the neighbor address).
	b.WriteString("router bgp\n")
	for _, bd := range bindings {
		fmt.Fprintf(&b, " no neighbor %s route-map %s in\n", bd.Neighbor, bd.RouteMap)
	}
	b.WriteString("exit\n")
	// 2. Delete every owned route-map, bound or not, now that nothing is bound.
	for _, name := range ordered {
		fmt.Fprintf(&b, "no route-map %s\n", name)
	}
	// 3. Delete the prefix-lists last: nothing references them any more.
	for _, name := range lists {
		fmt.Fprintf(&b, "no ip prefix-list %s\n", name)
	}
	b.WriteString("exit\n")

	if _, err := runVtysh(b.String()); err != nil {
		return 0, fmt.Errorf("actuate: vtysh normalize applied: %w", err)
	}

	slotMu.Lock()
	slotCounts = map[string]int{} // slot layout restarts from the clean slate
	slotMu.Unlock()

	return len(bindings), nil
}
