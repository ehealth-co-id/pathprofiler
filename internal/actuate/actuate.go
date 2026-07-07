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
	"strings"
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
	lastSwitch map[string]time.Time // keyed by "subnet->interface" or similar route identity
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

// SetNeighborTiers sets local-pref for multiple destination prefixes on one
// neighbor in a single vtysh config session. Generates ONE route-map named
// PATHPROFILER-<neighbor-slug> with:
//   - one permit seq per (prefix, localpref) pair, each with
//     `match ip address prefix-list PATHPROFILER-SCOPE-<prefix-slug>` +
//     `set local-preference <pref>`
//   - a final catch-all `permit 65535` with no match/set, so out-of-scope
//     prefixes from the same neighbor pass through unmodified (without this,
//     the route-map's implicit final deny would blackhole them).
//
// The neighbor's `route-map ... in` is attached exactly once.
// Empty updates -> no-op (return nil, no subprocess).
// Deliberately does NOT `write memory` (see package doc).
func SetNeighborTiers(u NeighborTierUpdate) error {
	if len(u.Prefs) == 0 {
		return nil
	}

	neighborSlug := sanitizeRouteMapName(u.Neighbor)
	var b strings.Builder

	b.WriteString("configure terminal\n")

	// Clear any prior route-map for this neighbor so stale seqs (from prefixes
	// that dropped out, or tiers that changed) don't persist. FRR's
	// `no route-map NAME` deletes all sequences; we re-add below. This makes
	// SetNeighborTiers stateless -- each call fully rewrites the neighbor's
	// route-map, matching the neighbor-atomic actuation unit.
	fmt.Fprintf(&b, "no route-map PATHPROFILER-%s\n", neighborSlug)

	// Declare prefix-lists for each in-scope prefix.
	for _, pp := range u.Prefs {
		prefixSlug := sanitizeRouteMapName(pp.Prefix)
		fmt.Fprintf(&b, "ip prefix-list PATHPROFILER-SCOPE-%s permit %s\n", prefixSlug, pp.Prefix)
	}

	// Build the per-neighbor route-map: one permit seq per prefix, plus
	// catch-all at seq 65535.
	for i, pp := range u.Prefs {
		seq := (i + 1) * 10 // 10, 20, 30, ...
		prefixSlug := sanitizeRouteMapName(pp.Prefix)
		fmt.Fprintf(&b, "route-map PATHPROFILER-%s permit %d\n", neighborSlug, seq)
		fmt.Fprintf(&b, " match ip address prefix-list PATHPROFILER-SCOPE-%s\n", prefixSlug)
		fmt.Fprintf(&b, " set local-preference %d\n", pp.LocalPref)
		b.WriteString("exit\n")
	}
	// Catch-all: permit without match/set so out-of-scope prefixes pass through.
	fmt.Fprintf(&b, "route-map PATHPROFILER-%s permit 65535\n", neighborSlug)
	b.WriteString("exit\n")

	// Attach the route-map inbound on the neighbor (exactly once).
	fmt.Fprintf(&b, "router bgp\n neighbor %s route-map PATHPROFILER-%s in\nexit\n", u.Neighbor, neighborSlug)
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
	fmt.Fprintf(&b, "no neighbor %s route-map PATHPROFILER-%s in\n", neighbor, slug)
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

// ListAppliedNeighbors queries FRR's running config for existing
// PATHPROFILER-* route-maps and returns the set of neighbors they are
// attached to. Used at daemon startup (Finding 3) to seed appliedNeighbors
// from FRR's actual state, so Drained -> Absent cleanup works across
// daemon restarts. Without this, a restart orphans every route-map the
// prior process applied.
func ListAppliedNeighbors() (map[string]bool, error) {
	out, err := runVtysh("show running-config")
	if err != nil {
		return nil, fmt.Errorf("actuate: vtysh show running-config: %w", err)
	}
	return ParseAppliedNeighbors(string(out)), nil
}

// ParseAppliedNeighbors parses "show running-config" output for
// PATHPROFILER-* route-map neighbor attachments and returns the set
// of neighbor IPs they are attached to.
func ParseAppliedNeighbors(config string) map[string]bool {
	result := make(map[string]bool)
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		// Match: " neighbor X.X.X.X route-map PATHPROFILER-<slug> in"
		if !strings.HasPrefix(line, "neighbor ") {
			continue
		}
		if !strings.Contains(line, "route-map PATHPROFILER-") {
			continue
		}
		if !strings.HasSuffix(line, " in") {
			continue
		}
		// Extract neighbor IP: " neighbor <ip> route-map ..."
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		neighbor := fields[1]
		// Validate it looks like an IP (basic check).
		if net.ParseIP(neighbor) == nil {
			continue
		}
		result[neighbor] = true
	}
	return result
}
