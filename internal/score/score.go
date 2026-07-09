// Package score computes a composite path cost from raw eBPF counters and
// decides whether that cost change is significant enough to actuate.
//
// GAP FOUND DURING IMPLEMENTATION, NOT IN THE ORIGINAL PLAN: Phase 4 of the
// plan computes "Path Cost" and actuates directly. Doing that on every
// polling interval (e.g. every 1s) against noisy jitter/retransmit samples
// will oscillate BGP Local-Pref / ip route weights continuously. Real BGP
// peers apply route-flap dampening and will penalize a neighbor that
// reconverges too often; local ECMP weight changes that flap will cause
// TCP flows to repeatedly see mid-stream RTT discontinuities, which is
// itself a jank source, not a jank fix. This is exactly the kind of
// "fixed the named flaw, didn't re-derive from first principles" pattern
// already flagged elsewhere in your infra work -- so: hysteresis and a
// minimum dwell time are added here structurally, not as an afterthought.
package score

import (
	"math"
	"time"
)

type PathCost struct {
	NextHopIP       uint32
	Neighbor        string  // BGP advertising peer IP (loopback for RR clients); set by caller after Compute
	EgressRTTUs     float64
	EgressLossRate  float64 // retransmits per byte-ish proxy; see caveat below
	IngressJitterUs float64
	IngressGapRate  float64
	Composite       float64
	Confidence      float64 // 0..1, based on sample count -- low-sample paths should not win on noise
}

type Weights struct {
	EgressRTT     float64
	EgressLoss    float64
	IngressJitter float64
	IngressGap    float64
}

// lostProbeComposite is the sentinel composite assigned to lost cold probes.
// Always worse than any measured path (even 10s RTT is only 10,000,000us
// with weight 1.0), so a dead path can never outrank a live one.
const lostProbeComposite = math.MaxFloat32

var DefaultWeights = Weights{
	EgressRTT:     1.0,
	EgressLoss:    500.0, // loss dominates RTT in the cost function; retransmits are a stronger
	IngressJitter: 1.0,   // signal of real congestion than RTT alone, which can be a stable-but-slow path
	IngressGap:    300.0,
}

// Compute derives a PathCost from raw counter deltas (already delta'd by the
// caller between polling intervals -- NOT cumulative totals, or slow-changing
// paths will never show up as improving after a bad period ages out).
func Compute(nextHop uint32,
	srttUsSum, srttSamples, retransDelta, bytesAckedDelta uint64,
	iatSumNs, iatSqSumNs, iatSamples, seqGapsDelta, packetsDelta uint64,
	w Weights) PathCost {

	var rtt float64
	if srttSamples > 0 {
		rtt = float64(srttUsSum) / float64(srttSamples)
	}

	var lossRate float64
	if bytesAckedDelta > 0 {
		lossRate = float64(retransDelta) / float64(bytesAckedDelta)
	} else if retransDelta > 0 {
		// bytes_acked wasn't wired up by the sock_ops program in this draft
		// (BPF_SOCK_OPS_BYTES_ACKED_CB not yet hooked -- flagged as TODO,
		// not silently assumed complete). Fall back to raw retransmit count
		// as a weaker proxy so the daemon degrades rather than divides by zero.
		lossRate = float64(retransDelta)
	}

	var jitterUs float64
	if iatSamples > 1 {
		mean := float64(iatSumNs) / float64(iatSamples)
		meanSq := float64(iatSqSumNs) / float64(iatSamples)
		variance := meanSq - mean*mean
		if variance < 0 {
			variance = 0 // guard fixed-point rounding underflow
		}
		jitterUs = math.Sqrt(variance) / 1000.0
	}

	var gapRate float64
	if packetsDelta > 0 {
		gapRate = float64(seqGapsDelta) / float64(packetsDelta)
	}

	confidence := 1.0
	if srttSamples < 5 || iatSamples < 5 {
		confidence = math.Min(float64(srttSamples), float64(iatSamples)) / 5.0
	}

	res := PathCost{
		NextHopIP:       nextHop,
		EgressRTTUs:     rtt,
		EgressLossRate:  lossRate,
		IngressJitterUs: jitterUs,
		IngressGapRate:  gapRate,
		Confidence:      confidence,
	}
	res.Composite = composite(res, w)
	return res
}

// composite computes the weighted cost from a PathCost's component fields.
// Single source of truth for the cost formula -- used by both Compute (passive)
// and FromProbeResult (cold probe) so both are on the same scale.
func composite(pc PathCost, w Weights) float64 {
	return w.EgressRTT*pc.EgressRTTUs +
		w.EgressLoss*pc.EgressLossRate +
		w.IngressJitter*pc.IngressJitterUs +
		w.IngressGap*pc.IngressGapRate
}

// FromProbeResult builds a PathCost from a single cold-path probe.
// RTT -> EgressRTTUs (underlay-only, not end-to-end); Lost -> sentinel
// EgressLossRate 1.0; ingress fields zero; Confidence = 0 (cold-probe taint).
//
// Confidence=0 marks the entry as underlay-scale so (a) RankByTier demotes
// cold-only neighbors via the existing Confidence < 0.5 -> defaultTier rule,
// and (b) CollapseByNeighbor drops it when a passive path for the same
// neighbor exists, avoiding RTT scale mismatch in the averaged metric.
func FromProbeResult(nextHop uint32, rtt time.Duration, lost bool) PathCost {
	pc := PathCost{NextHopIP: nextHop, Confidence: 0}
	if lost {
		pc.EgressLossRate = 1.0
		pc.Composite = lostProbeComposite // sentinel: always worse than any measured path
	} else {
		pc.EgressRTTUs = float64(rtt.Microseconds())
		pc.Composite = composite(pc, DefaultWeights)
	}
	return pc
}
