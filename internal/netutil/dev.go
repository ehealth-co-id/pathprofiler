package netutil

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"pathprofiler/internal/ospf"
)

// ipRouteGetCmd is injectable for tests. Real runs exec.Command("ip", "route", "get", ip).
var ipRouteGetCmd = func(ip string) ([]byte, error) {
	return exec.Command("ip", "route", "get", ip).CombinedOutput()
}

// ResolveDevice returns the egress interface the kernel would use to reach
// nextHopIP, by parsing "ip route get <ip>" output. Example output:
//
//	"192.168.200.1 dev wg0 src 192.168.200.5 uid 0 \n    cache"
//
// Returns "wg0". Errors if the IP is invalid, the command fails, or output
// has no "dev" token.
func ResolveDevice(nextHopIP string) (string, error) {
	if net.ParseIP(nextHopIP) == nil {
		return "", fmt.Errorf("netutil: invalid IP %q", nextHopIP)
	}
	out, err := ipRouteGetCmd(nextHopIP)
	if err != nil {
		return "", fmt.Errorf("netutil: ip route get %s: %w", nextHopIP, err)
	}
	return parseDevice(out)
}

// ResolveNexthop returns the gateway IP the kernel would use to reach dstIP,
// by parsing "ip route get <ip>" output. If the destination is directly
// connected (no "via" token), returns dstIP itself. Example output with
// gateway:
//
//	"192.168.1.100 via 10.0.0.1 dev eth0 src 10.0.0.2 uid 0\n    cache"
//
// Returns "10.0.0.1". Direct route example:
//
//	"192.168.200.1 dev wg0 src 192.168.200.5 uid 0\n    cache"
//
// Returns "192.168.200.1" (destination is the nexthop).
func ResolveNexthop(dstIP string) (string, error) {
	if net.ParseIP(dstIP) == nil {
		return "", fmt.Errorf("netutil: invalid IP %q", dstIP)
	}
	out, err := ipRouteGetCmd(dstIP)
	if err != nil {
		return "", fmt.Errorf("netutil: ip route get %s: %w", dstIP, err)
	}
	return parseNexthop(out, dstIP)
}

// parseNexthop extracts the gateway from "ip route get" output.
func parseNexthop(out []byte, dstIP string) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "cache" || strings.HasPrefix(line, "cache ") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
		// No "via" token -- destination is directly connected.
		return dstIP, nil
	}
	return dstIP, nil
}

// parseDevice extracts the device name from "ip route get" output.
func parseDevice(out []byte) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "cache" || strings.HasPrefix(line, "cache ") {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) {
				return fields[i+1], nil
			}
		}
		return "", fmt.Errorf("netutil: no 'dev' token in line: %q", line)
	}
	return "", fmt.Errorf("netutil: empty output")
}

// ResolvePaths returns the physical paths to reach a BGP next-hop, using
// the OSPF underlay if the loopback is present, else falling back to a
// single-path result from ResolveDevice. This is the function the daemon
// loop actually calls.
func ResolvePaths(loopback string, underlay ospf.Underlay) ([]ospf.PhysicalPath, error) {
	if paths := underlay.PathsTo(loopback); len(paths) > 0 {
		return paths, nil
	}
	dev, err := ResolveDevice(loopback)
	if err != nil {
		return nil, fmt.Errorf("netutil: resolve path for %s: %w", loopback, err)
	}
	return []ospf.PhysicalPath{{
		Loopback:  loopback,
		Interface: dev,
	}}, nil
}
