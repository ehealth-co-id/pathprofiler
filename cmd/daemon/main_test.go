//go:build linux

package main

import (
	"testing"
	"time"

	"pathprofiler/internal/actuate"
)

// F1: one neighbor, two legs, traffic on one — the other must still be probed.
func TestColdProbeGate_SkipsOnlyLegsWithLiveTraffic(t *testing.T) {
	passiveLegs := map[string]bool{
		"10.255.0.3:wg0": true, // wg0 has live traffic
		// ens21 has NO live traffic — must still be probed
	}

	// wg0 should be skipped.
	if gateColdProbeLeg("10.255.0.3", "wg0", passiveLegs) {
		t.Error("wg0 should be skipped (has passive traffic)")
	}

	// ens21 must still be probed despite sibling wg0 having traffic.
	if !gateColdProbeLeg("10.255.0.3", "ens21", passiveLegs) {
		t.Error("ens21 should be probed (no passive traffic on this leg)")
	}
}

// F1: no passive legs — all legs must be probed.
func TestColdProbeGate_NoPassiveLegs(t *testing.T) {
	passiveLegs := map[string]bool{}

	if !gateColdProbeLeg("10.255.0.3", "wg0", passiveLegs) {
		t.Error("wg0 should be probed (no passive traffic at all)")
	}
	if !gateColdProbeLeg("10.255.0.3", "ens21", passiveLegs) {
		t.Error("ens21 should be probed (no passive traffic at all)")
	}
}

// F1: all legs have traffic — nothing should be probed.
func TestColdProbeGate_AllLegsHaveTraffic(t *testing.T) {
	passiveLegs := map[string]bool{
		"10.255.0.3:wg0":   true,
		"10.255.0.3:ens21": true,
	}

	if gateColdProbeLeg("10.255.0.3", "wg0", passiveLegs) {
		t.Error("wg0 should be skipped")
	}
	if gateColdProbeLeg("10.255.0.3", "ens21", passiveLegs) {
		t.Error("ens21 should be skipped")
	}
}

// F4: per-neighbor dampener couples sibling prefixes. Prefix A's legitimate
// change on neighbor X is suppressed if prefix B on X flapped recently.
func TestDampener_SiblingPrefixFlapSuppressesUnrelatedPrefixOnSameNeighbor(t *testing.T) {
	dampener := actuate.NewDampener(30 * time.Second)

	// Prefix B flaps on neighbor X — record it.
	dampener.Record("10.255.0.3")

	// Prefix A on the same neighbor X tries to actuate immediately.
	// It should be suppressed because the dampener is keyed per-neighbor.
	if dampener.Allow("10.255.0.3") {
		t.Error("prefix A on same neighbor should be suppressed after prefix B's flap")
	}

	// Prefix A on a DIFFERENT neighbor Y should NOT be suppressed.
	if !dampener.Allow("10.255.0.4") {
		t.Error("prefix on different neighbor should not be affected")
	}
}

// F5 trip-wire: asserts current host-order byte conversion. If BPF-side
// byte order is fixed (egress_sockops.bpf.c:81), this test will fail
// as the signal that the centralized conversion needs updating too.
func TestUint32ToIPStr_RoundTrip(t *testing.T) {
	tests := []struct {
		u    uint32
		want string
	}{
		{0x01020304, "1.2.3.4"},
		{0xC0A8C805, "192.168.200.5"},
		{0x0A000001, "10.0.0.1"},
		{0x00000000, "0.0.0.0"},
		{0xFFFFFFFF, "255.255.255.255"},
	}
	for _, tt := range tests {
		got := uint32ToIPStr(tt.u)
		if got != tt.want {
			t.Errorf("uint32ToIPStr(0x%08X) = %q, want %q", tt.u, got, tt.want)
		}
	}

	// Verify round-trip.
	for _, tt := range tests {
		ip := uint32ToIPStr(tt.u)
		back := ipStrToUint32(ip)
		if back != tt.u {
			t.Errorf("round-trip failed: 0x%08X -> %q -> 0x%08X", tt.u, ip, back)
		}
	}
}
