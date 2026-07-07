package ospf

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// PhysicalPath is one way to reach a BGP loopback via the OSPF underlay.
type PhysicalPath struct {
	Loopback   string // BGP next-hop, e.g. "10.255.0.3"
	Interface  string // e.g. "wg0" or "ens21"
	PhysicalNH string // OSPF next-hop, e.g. "192.168.200.3"
	Cost       int    // OSPF cost
}

// Underlay maps each BGP loopback to its candidate physical paths.
// One loopback may have multiple entries if OSPF ECMPs across interfaces.
type Underlay map[string][]PhysicalPath // key: loopback IP

// runVtysh is injectable for tests. Real calls exec.Command("vtysh", args...).
var runVtysh = func(args ...string) ([]byte, error) {
	return exec.Command("vtysh", args...).CombinedOutput()
}

// --------------------------------------------------------------------------
// JSON decode helpers (FRR 10.x schema — real vtysh output)

// neighborWrapper matches the outer {"neighbors": {...}} envelope.
type neighborWrapper struct {
	Neighbors map[string][]neighborEntry `json:"neighbors"`
}

type neighborEntry struct {
	IfaceName    string `json:"ifaceName"`    // "wg0:192.168.200.5"
	IfaceAddress string `json:"ifaceAddress"` // "192.168.200.3"
}

// routeEntry represents one OSPF route in "show ip ospf route json".
type routeEntry struct {
	RouteType string    `json:"routeType"`
	Cost      int       `json:"cost"`
	Nexthops  []nhEntry `json:"nexthops"`
}

type nhEntry struct {
	IP  string `json:"ip"`  // whitespace-only means directly-attached
	Via string `json:"via"` // interface name, e.g. "wg0"
}

// --------------------------------------------------------------------------

// ParseNeighbors parses "show ip ospf neighbor json" output and returns a map
// of neighbor IP -> interface name.
// Real FRR schema: {"neighbors": {"<ip>": [{"ifaceName":"wg0:...",
// "ifaceAddress":"192.168.200.3", ...}]}}
func ParseNeighbors(jsonBytes []byte) (map[string]string, error) {
	var wrapper neighborWrapper
	if err := json.Unmarshal(jsonBytes, &wrapper); err != nil {
		return nil, fmt.Errorf("ospf: decode neighbors: %w", err)
	}

	result := make(map[string]string, len(wrapper.Neighbors))
	for ip, entries := range wrapper.Neighbors {
		for _, e := range entries {
			iface := extractIface(e.IfaceName)
			if iface != "" {
				result[ip] = iface
			}
		}
	}
	return result, nil
}

// ParseRoute parses "show ip ospf route json" output for a specific BGP
// loopback and returns the list of physical paths to reach it.
// Real FRR schema: {"<prefix>/32": {"routeType":"N", "cost":60,
// "nexthops":[{"ip":"192.168.200.3", "via":"wg0"}]}}
// Nexthops with empty/whitespace-only IP are directly-attached routes
// (e.g. the router's own loopback) and are skipped.
func ParseRoute(jsonBytes []byte, loopback string) ([]PhysicalPath, error) {
	var routes map[string]routeEntry
	if err := json.Unmarshal(jsonBytes, &routes); err != nil {
		return nil, fmt.Errorf("ospf: decode route JSON: %w", err)
	}

	key := loopback
	if !strings.HasSuffix(loopback, "/32") {
		key += "/32"
	}

	entry, ok := routes[key]
	if !ok {
		return nil, nil // not in underlay
	}

	var paths []PhysicalPath
	for _, nh := range entry.Nexthops {
		if strings.TrimSpace(nh.IP) == "" {
			continue // directly-attached route, not a remote path
		}
		paths = append(paths, PhysicalPath{
			Loopback:   loopback,
			Interface:  nh.Via,
			PhysicalNH: nh.IP,
			Cost:       entry.Cost,
		})
	}
	return paths, nil
}

// FetchTopo runs the vtysh command and returns the full underlay for the
// given BGP loopbacks.
func FetchTopo(loopbacks []string) (Underlay, error) {
	routeOut, err := runVtysh("-c", "show ip ospf route json")
	if err != nil {
		return nil, fmt.Errorf("ospf: vtysh route: %w\noutput: %s", err, string(routeOut))
	}

	topo := make(Underlay, len(loopbacks))
	for _, lb := range loopbacks {
		paths, err := ParseRoute(routeOut, lb)
		if err != nil {
			return nil, fmt.Errorf("ospf: parse route for %s: %w\nraw vtysh output:\n%s", lb, err, string(routeOut))
		}
		topo[lb] = paths
	}
	return topo, nil
}

// PathsTo returns the physical paths for a given BGP loopback.
func (u Underlay) PathsTo(loopback string) []PhysicalPath {
	return u[loopback]
}

// LoopbackForPhysicalNH returns the BGP loopback that routes through physIP
// as its OSPF next-hop. This is the reverse of PhysicalPath.PhysicalNH.
//
// Precondition: physIP must uniquely identify a single loopback in the
// underlay. This holds in the current deployment (192.168.200.X maps 1:1
// to 10.255.0.X) but is NOT a general guarantee — a transit topology
// where two loopbacks share a first-hop router would violate it.
//
// On ambiguity (multiple loopbacks reachable via the same physical NH),
// returns ("", error) rather than silently picking one — a future
// topology change should surface as a visible failure, not misattributed
// passive traffic. (Finding 2.)
func (u Underlay) LoopbackForPhysicalNH(physIP string) (string, error) {
	var found []string
	for loopback, paths := range u {
		for _, pp := range paths {
			if pp.PhysicalNH == physIP {
				found = append(found, loopback)
				break // one match per loopback is enough
			}
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("ospf: physical NH %s maps to multiple loopbacks %v (uniqueness precondition violated)", physIP, found)
	}
}

// extractIface strips the IP suffix from an ifaceName like "wg0:192.168.200.5".
// Returns "" on empty input.
func extractIface(ifaceName string) string {
	if ifaceName == "" {
		return ""
	}
	before, _, _ := strings.Cut(ifaceName, ":")
	return before
}