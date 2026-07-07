//go:build linux

// Cold-path prober. Original plan (Phase 3) wanted kernel-crafted probes
// hashed to land in the same ECMP bucket as live traffic. That requires
// knowing the upstream router's hash function and seed, which is not
// observable from the sending host in the general case -- so it was
// dropped (see top-level critique). This replaces it with explicit,
// deterministic next-hop selection: bind the probe socket to the specific
// interface/next-hop under test, bypassing ECMP entirely.
//
// Tradeoff being made explicitly: we lose "exact ECMP bucket" fidelity for
// probes, but gain determinism. To catch cases where that gap matters (a
// specific ECMP bucket is bad while the next-hop overall is fine), cross-
// validate probe RTT against passive per-flow egress RTT (from
// egress_sockops) on the same next-hop whenever live traffic exists; if
// they diverge beyond a threshold, that's the middlebox/bucket-divergence
// signal from the plan's residual-uncertainty section, and probing for
// that path should be flagged low-confidence via actuate.ProbeState.
package actuate

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

type ProbeResult struct {
	NextHopIP string
	RTT       time.Duration
	Lost      bool
}

// ProbeNextHop sends a single UDP probe out a specific interface (binding
// via SO_BINDTODEVICE, which requires CAP_NET_RAW) and waits for a
// reply-or-timeout. Caller loops this on an interval per candidate
// next-hop that currently has no live traffic (the cold-path case).
func ProbeNextHop(iface string, dstIP string, dstPort int, timeout time.Duration) (ProbeResult, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.BindToDevice(fd, iface); err != nil {
		return ProbeResult{}, fmt.Errorf("SO_BINDTODEVICE %s (needs CAP_NET_RAW): %w", iface, err)
	}

	// DSCP/TOS should mirror the live traffic class this next-hop normally
	// carries, so the probe experiences the same QoS queue on the ISP edge
	// -- this preserves the plan's QoS-fidelity intent even without hash
	// matching. Set via IP_TOS; the actual value should come from config
	// per traffic class, hardcoded here as a placeholder (0x00 = best-effort).
	const placeholderTOS = 0x00
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, placeholderTOS); err != nil {
		return ProbeResult{}, fmt.Errorf("IP_TOS: %w", err)
	}

	addr := syscall.SockaddrInet4{Port: dstPort}
	ip := net.ParseIP(dstIP).To4()
	if ip == nil {
		return ProbeResult{}, fmt.Errorf("invalid dst ip %s", dstIP)
	}
	copy(addr.Addr[:], ip)

	// Connect so Linux delivers ICMP errors synchronously as ECONNREFUSED
	// on Recvfrom, instead of queueing them on the error queue where a
	// plain Recvfrom never sees them. This is the traceroute idiom:
	// unconnected UDP sockets get silent ICMP, connected ones gets errors.
	if err := syscall.Connect(fd, &addr); err != nil {
		return ProbeResult{}, fmt.Errorf("connect: %w", err)
	}

	sendTime := time.Now()
	payload := []byte("pathprofiler-probe")
	if _, err := syscall.Write(fd, payload); err != nil {
		return ProbeResult{}, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 512)
	syscall.SetNonblock(fd, false)
	tv := syscall.NsecToTimeval(int64(timeout))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	_, _, err = syscall.Recvfrom(fd, buf, 0)
	if err == nil {
		return ProbeResult{NextHopIP: dstIP, RTT: time.Since(sendTime), Lost: false}, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		// ICMP port-unreachable: host reachable, port closed -> valid RTT.
		return ProbeResult{NextHopIP: dstIP, RTT: time.Since(sendTime), Lost: false}, nil
	}
	// EAGAIN / timeout, or any other error -> genuinely lost.
	return ProbeResult{NextHopIP: dstIP, Lost: true}, nil
}

// DivergenceCheck compares probe RTT against passive egress RTT for the same
// next-hop and flags probing as unreliable if they diverge too much --
// implements the plan's residual-uncertainty mitigation ("continuously
// verify probe-to-live-flow alignment; fall back to passive on divergence").
func DivergenceCheck(probeRTT, passiveRTT time.Duration, thresholdPct float64) bool {
	if passiveRTT <= 0 {
		return false // no passive baseline yet, can't judge divergence
	}
	diff := float64(probeRTT-passiveRTT) / float64(passiveRTT)
	if diff < 0 {
		diff = -diff
	}
	return diff > thresholdPct
}
