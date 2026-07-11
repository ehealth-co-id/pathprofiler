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
// transit_loss) on the same next-hop whenever live traffic exists; if
// they diverge beyond a threshold, that's the middlebox/bucket-divergence
// signal from the plan's residual-uncertainty section, and probing for
// that path should be flagged low-confidence via actuate.ProbeState.
package actuate

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"syscall"
	"time"
)

// ProbeOutcome classifies the adaptive SPRT result against the active path.
type ProbeOutcome int

const (
	OutcomeUndecided ProbeOutcome = iota // no decision at maxN; overlap gate decides
	OutcomeBetter                         // challenger loss rate < p0 - delta (SPRT H1 accepted)
	OutcomeWorse                          // challenger loss rate > p0 + delta (SPRT H1 accepted)
	OutcomeIndifferent                    // challenger within +/-delta of active (both SPRT nulls accepted)
)

func (o ProbeOutcome) String() string {
	switch o {
	case OutcomeBetter:
		return "better"
	case OutcomeWorse:
		return "worse"
	case OutcomeIndifferent:
		return "indifferent"
	default:
		return "undecided"
	}
}

// evaluateSPRT performs a single check of the three-decision Wald SPRT stopping
// rule. Given accumulated k losses out of n probes, fixed thresholds p0 (null),
// p1 (better), p2 (worse), and Wald boundaries A = ln((1-beta)/alpha),
// B = ln(beta/(1-alpha)), returns the decision:
//
//   - OutcomeBetter: LLR_better >= A and LLR_worse <= B  (challenger beats active)
//   - OutcomeWorse:  LLR_worse >= A and LLR_better <= B  (active beats challenger)
//   - OutcomeIndifferent: both LLRs <= B  (within indifference band)
//   - OutcomeUndecided: otherwise (need more samples)
//
// ponytail: valid only for iid Bernoulli outcomes. Wald (1945) Eq 10.1-10.3.
// If the path state changes mid-burst, nominal alpha/beta are approximate.
func evaluateSPRT(k, n int, p0, p1, p2, A, B float64) ProbeOutcome {
	if n == 0 {
		return OutcomeUndecided
	}
	llrBetter := sprtLLR(k, n, p0, p1)
	llrWorse := sprtLLR(k, n, p0, p2)

	if llrBetter >= A && llrWorse <= B {
		return OutcomeBetter
	}
	if llrWorse >= A && llrBetter <= B {
		return OutcomeWorse
	}
	if llrBetter <= B && llrWorse <= B {
		return OutcomeIndifferent
	}
	return OutcomeUndecided
}

// sprtLLR computes the Wald log-likelihood ratio for H1: p=p1 vs H0: p=p0:
//
//	LLR = k * ln(p1/p0) + (n-k) * ln((1-p1)/(1-p0))
//
// Clamps p values to the open interval (epsilon, 1-epsilon) so that log(0) at
// the boundaries (p=0 or p=1) never happens. At the boundaries the Bernoulli
// log-likelihood is still well-defined but the LLR against a different p would
// be infinite; clamping lets the SPRT terminate normally with a decision.
func sprtLLR(k, n int, p0, p1 float64) float64 {
	const epsilon = 1e-15
	p0c := math.Max(epsilon, math.Min(1-epsilon, p0))
	p1c := math.Max(epsilon, math.Min(1-epsilon, p1))
	fk := float64(k)
	fn := float64(n)
	return fk*math.Log(p1c/p0c) + (fn-fk)*math.Log((1-p1c)/(1-p0c))
}

// sprtBoundaries pre-computes the Wald decision boundaries A (accept H1) and
// B (accept H0) from the SPRT error rates alpha and beta.
func sprtBoundaries(alpha, beta float64) (A, B float64) {
	A = math.Log((1.0 - beta) / alpha)
	B = math.Log(beta / (1.0 - alpha))
	return A, B
}

// probePayload is the fixed UDP payload sent by every cold probe. Shared with
// StartColdProbeResponder (responder.go), which only echoes datagrams that
// match this exactly -- so the two can never drift apart.
const probePayload = "pathprofiler-probe"

// ProbeResult carries the aggregated result of a cold-path probe burst.
type ProbeResult struct {
	NextHopIP   string
	RTT         time.Duration
	LossRate    float64 // 0..1, fraction of probes lost (k/N)
	LossRateErr float64 // Wilson score 95% semi-width
	ProbeCount  int     // n: probes actually sent. For ProbeNextHopAdaptive, n < maxN
	// signals the SPRT stopped early (see ProbeOutcome).
}

// ProbeLegBurst sends up to n sequential UDP probes (bounded by an overall
// deadline of timeout*n) out iface to dstIP:dstPort, binding via
// SO_BINDTODEVICE (requires CAP_NET_RAW) and connecting so Linux delivers
// ICMP errors synchronously as ECONNREFUSED on Recvfrom (the traceroute
// idiom: unconnected UDP sockets get silent ICMP, connected ones get errors).
// Returns the RTTs of successful replies and the count of replies received;
// callers treat n-replied as the loss count (matching the pre-refactor
// behavior of both ProbeNextHop and the former ProbeNextHopAdaptive, where a
// deadline cutting a burst short counts every un-attempted probe as lost
// rather than shrinking the denominator). Shared by ProbeNextHop and
// ProbeNextHopAccumulating.
func ProbeLegBurst(iface, dstIP string, dstPort int, timeout time.Duration, n int) (rtts []time.Duration, replied int, err error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, 0, fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.BindToDevice(fd, iface); err != nil {
		return nil, 0, fmt.Errorf("SO_BINDTODEVICE %s (needs CAP_NET_RAW): %w", iface, err)
	}

	// DSCP/TOS should mirror the live traffic class this next-hop normally
	// carries, so the probe experiences the same QoS queue on the ISP edge
	// -- this preserves the plan's QoS-fidelity intent even without hash
	// matching. Set via IP_TOS; the actual value should come from config
	// per traffic class, hardcoded here as a placeholder (0x00 = best-effort).
	const placeholderTOS = 0x00
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, placeholderTOS); err != nil {
		return nil, 0, fmt.Errorf("IP_TOS: %w", err)
	}

	addr := syscall.SockaddrInet4{Port: dstPort}
	ip := net.ParseIP(dstIP).To4()
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid dst ip %s", dstIP)
	}
	copy(addr.Addr[:], ip)

	if err := syscall.Connect(fd, &addr); err != nil {
		return nil, 0, fmt.Errorf("connect: %w", err)
	}

	deadline := time.Now().Add(timeout * time.Duration(n))
	payload := []byte(probePayload)
	buf := make([]byte, 512)

	for i := 0; i < n; i++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sendTime := time.Now()
		if _, err := syscall.Write(fd, payload); err != nil {
			continue // send failed, count as lost
		}

		// Wait for reply with per-probe timeout.
		syscall.SetNonblock(fd, false)
		tv := syscall.NsecToTimeval(int64(timeout))
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		_, _, err := syscall.Recvfrom(fd, buf, 0)
		if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
			rtts = append(rtts, time.Since(sendTime))
			replied++
		}
		// EAGAIN / timeout: count as lost, continue to next probe
	}

	return rtts, replied, nil
}

// ProbeNextHop sends a burst of N UDP probes out a specific interface and
// waits for replies. Returns the median RTT across survivors, the measured
// loss rate, and a Wilson score interval error band. Caller loops this on an
// interval per candidate next-hop that currently has no live traffic (the
// cold-path case).
//
// ponytail: the blocking is bounded by probeCount * timeout; at default 5*2s=10s
// every 60s probeInterval, the daemon blocks ~17% wall-time. Upgrade path:
// goroutine per probe or non-blocking send+select.
func ProbeNextHop(iface string, dstIP string, dstPort int, timeout time.Duration, probeCount int) (ProbeResult, error) {
	rtts, replied, err := ProbeLegBurst(iface, dstIP, dstPort, timeout, probeCount)
	if err != nil {
		return ProbeResult{}, err
	}

	lost := probeCount - replied
	lossRate := 0.0
	if probeCount > 0 {
		lossRate = float64(lost) / float64(probeCount)
	}
	lossRateErr := wilsonLossErr(lost, probeCount)

	// Median RTT across survivors. Median is more robust than min: min selects
	// the one probe least affected by congestion, masking the degradation we
	// want to detect. Median captures the typical path RTT even when some
	// probes are dropped or delayed.
	medianRTT := sortAndMedian(rtts)

	return ProbeResult{NextHopIP: dstIP, RTT: medianRTT, LossRate: lossRate, LossRateErr: lossRateErr}, nil
}

// wilsonLossErr returns the semi-width (±) of the 95% Wilson score interval
// for k observed losses out of n probes. Uniform across all k=0..n — no
// special-casing at the boundaries. Uses p_hat (k/n) as the point estimate
// but the Wilson interval for the error band, which is continuous and
// handles k=0/k=n without the normal-approximation breakdown.
func wilsonLossErr(k, n int) float64 {
	if k > n || n == 0 {
		return 0
	}
	if k == n {
		return 0 // sentinel: all-lost; error irrelevant
	}
	phat := float64(k) / float64(n)
	z := 1.96 // 95% confidence
	z2 := z * z
	fn := float64(n)

	center := (float64(k) + z2/2.0) / (fn + z2)
	margin := z * math.Sqrt((phat*(1.0-phat)+z2/(4.0*fn))/fn) / (1.0 + z2/fn)

	lower := center - margin
	upper := center + margin
	if lower < 0 {
		lower = 0
	}
	return (upper - lower) / 2.0
}

// ProbeNextHopAccumulating sends this tick's small fixed burst (burstN
// probes) for one leg, folds the result into acc (mutated in place -- the
// caller persists acc across ticks, keyed per leg), and evaluates the
// three-decision Wald SPRT against the accumulated evidence rather than just
// this tick's burst. This lets the SPRT accumulate the sample size it needs
// over many small, cheap ticks instead of one large blocking burst.
//
// The per-probe timeout for this tick's burst is itself adaptive: derived
// from acc's RTT baseline (acc.AdaptiveTimeout) rather than a flat
// configuredTimeout, once a baseline exists -- a lost probe no longer has to
// wait out the full configured timeout when the path's real RTT is known to
// be far smaller.
//
// When activeComposite is +Inf (no active path) or no RTT baseline exists
// yet, falls back to OutcomeUndecided (same as the no-active case before).
//
// lossWeight = DefaultWeights.EgressLoss (passed in to avoid importing score).
// delta = indifference band in loss-rate units. alpha/beta = SPRT error rates.
func ProbeNextHopAccumulating(iface, dstIP string, dstPort int, configuredTimeout time.Duration,
	burstN, maxN int, acc *ProbeAccumulator, now time.Time, halfLife time.Duration,
	timeoutMultiplier float64, minTimeout time.Duration,
	activeComposite, delta, alpha, beta, lossWeight float64,
) (result ProbeResult, outcome ProbeOutcome, err error) {

	if maxN < burstN {
		maxN = burstN
	}

	timeout := acc.AdaptiveTimeout(configuredTimeout, timeoutMultiplier, minTimeout)

	rtts, replied, err := ProbeLegBurst(iface, dstIP, dstPort, timeout, burstN)
	if err != nil {
		return ProbeResult{}, OutcomeUndecided, err
	}
	kTick := burstN - replied
	rttMedianUs := sortAndMedianUs(rtts)

	acc.Ingest(now, halfLife, kTick, burstN, rttMedianUs, maxN)

	// Determine whether to run the SPRT.
	var p0c, p1, p2, A, B float64
	runSPRT := activeComposite >= 0 && !math.IsInf(activeComposite, 1) && acc.RTTBaselineUs > 0
	if runSPRT {
		p0 := p0FromActive(activeComposite, acc.RTTBaselineUs, lossWeight)
		if p0 < 0 {
			runSPRT = false // RTT alone beats the challenger
		} else {
			const epsilon = 1e-15
			p0c = math.Max(epsilon, math.Min(1-epsilon, p0))
			p1 = math.Max(epsilon, math.Min(1-epsilon, p0-delta))
			p2 = math.Max(epsilon, math.Min(1-epsilon, p0+delta))
			A, B = sprtBoundaries(alpha, beta)
		}
	}

	effK, effN := int(math.Round(acc.EffectiveK)), int(math.Round(acc.EffectiveN))
	if runSPRT {
		outcome = evaluateSPRT(effK, effN, p0c, p1, p2, A, B)
	} else {
		outcome = OutcomeUndecided
	}

	// Finalize result from the accumulated (not just this tick's) evidence.
	lossRate := 0.0
	if acc.EffectiveN > 0 {
		lossRate = acc.EffectiveK / acc.EffectiveN
	}
	lossRateErr := wilsonLossErr(effK, effN)

	return ProbeResult{
		NextHopIP:   dstIP,
		RTT:         time.Duration(acc.RTTBaselineUs * float64(time.Microsecond)),
		LossRate:    lossRate,
		LossRateErr: lossRateErr,
		ProbeCount:  effN,
	}, outcome, nil
}

// p0FromActive derives the loss-rate threshold p0 from the active path's
// composite and the challenger's measured RTT:
//
//	p0 = (activeComposite - rttWeight * rttChUs) / lossWeight
//
// rttWeight = 1.0 (DefaultWeights.EgressRTT). Returns -1 (no-active sentinel)
// when activeComposite is +Inf or when the computed p0 is negative (challenger's
// RTT alone already exceeds the active composite — no plausible loss-rate
// improvement can compensate).
func p0FromActive(activeComposite, rttChUs, lossWeight float64) float64 {
	if math.IsInf(activeComposite, 1) || activeComposite < 0 {
		return -1
	}
	p0 := (activeComposite - 1.0*rttChUs) / lossWeight
	if p0 < 0 {
		return -1 // RTT alone beats the challenger; don't bother with SPRT
	}
	if p0 > 1.0 {
		return 1.0 // challenger would need >100% loss to equal active — impossible, treat as always better
	}
	return p0
}

// sortAndMedianUs returns the median of rtts in microseconds, or 0 if empty.
func sortAndMedianUs(rtts []time.Duration) float64 {
	if len(rtts) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return float64(sorted[len(sorted)/2].Microseconds())
}

// sortAndMedian returns the median of rtts, or 0 if empty.
func sortAndMedian(rtts []time.Duration) time.Duration {
	if len(rtts) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(rtts))
	copy(sorted, rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
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
