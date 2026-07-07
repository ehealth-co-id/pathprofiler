package bgp

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
)

// Path represents one BGP path for a prefix from the RIB.
type Path struct {
	Prefix   string // "192.168.5.0/24"
	NextHop  string // "192.168.100.6"; "0.0.0.0" means locally originated
	Neighbor string // advertising peer IP (== NextHop for iBGP next-hop-self)
	LocPrf   int
	Best     bool
	Metric   int
	Origin   string // "i" / "e" / "?"
}

// runVtysh is injectable for tests. Real calls exec.Command("vtysh", args...).
var runVtysh = func(args ...string) ([]byte, error) {
	return exec.Command("vtysh", args...).CombinedOutput()
}

// --- JSON decode helpers (FRR 10.x schema) --------------------------------

type ribRoutes struct {
	Routes map[string]json.RawMessage `json:"routes"`
}

type pathEntry struct {
	Valid    bool      `json:"valid"`
	Bestpath bool      `json:"bestpath"`
	LocPrf   int       `json:"locPrf"`
	Metric   int       `json:"metric"`
	Origin   string    `json:"origin"`
	PeerID   string    `json:"peerId"`
	Nexthops []nexthop `json:"nexthops"`
}

type nexthop struct {
	IP string `json:"ip"`
}

// --------------------------------------------------------------------------

// ParseRIB parses FRR's "show ip bgp json" output.
// FRR JSON schema (10.x): {"routes": {"<prefix>": [{"valid": true,
// "bestPath": true, "locPrf": 200, "metric": 0, "nexthops": [{"ip": "..."}],
// "peer": {"peerId": "..."}, ...}]}}
// Paths with next-hop "0.0.0.0" (locally originated) are skipped.
func ParseRIB(jsonBytes []byte) (map[string][]Path, error) {
	var wrapper ribRoutes
	if err := json.Unmarshal(jsonBytes, &wrapper); err != nil {
		return nil, fmt.Errorf("bgp: decode RIB wrapper: %w", err)
	}
	if wrapper.Routes == nil {
		return nil, fmt.Errorf("bgp: RIB JSON missing 'routes' key")
	}

	result := make(map[string][]Path, len(wrapper.Routes))

	for prefix, raw := range wrapper.Routes {
		var entries []pathEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("bgp: decode prefix %q paths: %w", prefix, err)
		}

		for _, e := range entries {
			if !e.Valid {
				continue
			}

			nextHop := "0.0.0.0"
			if len(e.Nexthops) > 0 {
				nextHop = e.Nexthops[0].IP
			}

			// Skip locally originated routes (no real next-hop).
			if nextHop == "0.0.0.0" {
				continue
			}

			neighbor := e.PeerID
			if neighbor == "" || neighbor == "(unspec)" {
				neighbor = nextHop
			}

			result[prefix] = append(result[prefix], Path{
				Prefix:   prefix,
				NextHop:  nextHop,
				Neighbor: neighbor,
				LocPrf:   e.LocPrf,
				Best:     e.Bestpath,
				Metric:   e.Metric,
				Origin:   e.Origin,
			})
		}
	}

	return result, nil
}

// FetchRIB runs "vtysh -c \"show ip bgp json\"" and returns parsed paths.
func FetchRIB() (map[string][]Path, error) {
	out, err := runVtysh("-c", "show ip bgp json")
	if err != nil {
		return nil, fmt.Errorf("bgp: vtysh: %w\noutput: %s", err, string(out))
	}
	rib, err := ParseRIB(out)
	if err != nil {
		// vtysh can return error text (e.g. "% bgpd is not running") with
		// exit status 0, so a non-nil runVtysh error is not the only failure
		// mode. Surface the raw output to make those cases diagnosable.
		return nil, fmt.Errorf("bgp: parse RIB: %w\nraw vtysh output:\n%s", err, string(out))
	}
	return rib, nil
}

// PrefixForSubnet returns the longest-prefix RIB entry whose *net.IPNet
// contains subnetIP. Used by the daemon to join BPF passive stats (keyed by
// dst_subnet, a /24 masked from the destination) to the RIB prefix they
// belong to. Returns "" if no RIB prefix matches.
func PrefixForSubnet(rib map[string][]Path, subnetIP string) string {
	ip := net.ParseIP(subnetIP)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}

	best := ""
	bestLen := -1
	for prefix := range rib {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip4) {
			ones, _ := ipNet.Mask.Size()
			if ones > bestLen {
				best = prefix
				bestLen = ones
			}
		}
	}
	return best
}

// InScope filters rib to prefixes contained by any of the scope CIDRs.
// Empty scope means all prefixes are in scope.
func InScope(rib map[string][]Path, scope []string) map[string][]Path {
	if len(scope) == 0 {
		return rib
	}

	// Parse scope CIDRs.
	var scopeNets []*net.IPNet
	for _, s := range scope {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			continue // caller is expected to validate first
		}
		scopeNets = append(scopeNets, n)
	}

	result := make(map[string][]Path)
	for prefix, paths := range rib {
		_, ipNet, err := net.ParseCIDR(prefix)
		if err != nil {
			continue
		}
		for _, sn := range scopeNets {
			if sn.Contains(ipNet.IP) {
				result[prefix] = paths
				break
			}
		}
	}
	return result
}