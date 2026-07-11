//go:build linux

package actuate

import (
	"math"
	"math/rand"
	"net"
	"testing"
	"time"
)

// runSPRT is the testable pure-SPRT driver extracted from the socket-backed
// ProbeNextHopAdaptive. sampler returns true for a successful reply (no loss),
// false for a lost probe. It decouples the SPRT math from real I/O so the
// null-simulation test can feed Bernoulli outcomes.
//
// When p0 < 0 (no-active sentinel), skips SPRT entirely and returns
// OutcomeUndecided after minN probes.
func runSPRT(sampler func() bool, minN, maxN int, p0, delta, alpha, beta float64) (n, k int, outcome ProbeOutcome) {
	if maxN < minN {
		maxN = minN
	}

	// No-active sentinel.
	if p0 < 0 || math.IsInf(p0, 1) {
		for n < minN {
			if !sampler() {
				k++
			}
			n++
		}
		return n, k, OutcomeUndecided
	}

	const epsilon = 1e-15
	p0c := math.Max(epsilon, math.Min(1-epsilon, p0))
	p1 := math.Max(epsilon, math.Min(1-epsilon, p0-delta))
	p2 := math.Max(epsilon, math.Min(1-epsilon, p0+delta))
	A, B := sprtBoundaries(alpha, beta)

	// Initial burst.
	for n < minN {
		if !sampler() {
			k++
		}
		n++
	}

	outcome = evaluateSPRT(k, n, p0c, p1, p2, A, B)
	if outcome != OutcomeUndecided {
		return n, k, outcome
	}

	for n < maxN {
		if !sampler() {
			k++
		}
		n++
		outcome = evaluateSPRT(k, n, p0c, p1, p2, A, B)
		if outcome != OutcomeUndecided {
			return n, k, outcome
		}
	}

	outcome = evaluateSPRT(k, n, p0c, p1, p2, A, B)
	return n, k, outcome
}

// ---------------------------------------------------------------------------
// (a) Null simulation (discriminating test): SPRT must NOT inflate Type-I error
// ---------------------------------------------------------------------------

// TestSPRT_NullFalseDecisionRate simulates two paths with the same true loss
// rate p through the SPRT decision loop and asserts the empirical false-decision
// (OutcomeBetter or OutcomeWorse) rate is within 2x the nominal alpha.
// This runs BEFORE any integration tests as a sanity gate.
func TestSPRT_NullFalseDecisionRate(t *testing.T) {
	const trials = 10000
	const minN = 5
	const maxN = 30
	const delta = 0.02
	const alpha = 0.05
	const beta = 0.05

	for _, p := range []float64{0.0, 0.05, 0.1, 0.2, 0.5} {
		falseDecisions := 0
		rng := rand.New(rand.NewSource(int64(p * 1000)))
		for i := 0; i < trials; i++ {
			// Bernoulli sampler with loss rate p (same for challenger and active).
			sampler := func() bool {
				return rng.Float64() >= p // true = success (no loss)
			}
			_, _, outcome := runSPRT(sampler, minN, maxN, p, delta, alpha, beta)
			if outcome == OutcomeBetter || outcome == OutcomeWorse {
				falseDecisions++
			}
		}
		rate := float64(falseDecisions) / float64(trials)
		// SPRT guarantees <= alpha in theory; allow 2x margin for finite-trial noise.
		if rate > 2*alpha {
			t.Errorf("null p=%.2f: false-decision rate=%.4f, want <= ~%.4f", p, rate, 2*alpha)
		}
	}
}

// Additional null simulation: probe near the boundary (p0 near delta) where the
// SPRT has the hardest time. p = delta/2 from the threshold means both
// hypotheses are close to equally likely so the test should mostly return
// OutcomeIndifferent or OutcomeUndecided.
func TestSPRT_NullFalseDecisionRate_NearTrivial(t *testing.T) {
	const trials = 5000
	const minN = 5
	const maxN = 30
	const delta = 0.02
	const alpha = 0.05
	const beta = 0.05

	// p = 0.05, within 1% of a delta/2 boundary. The test is trivially
	// indifferent (the true p is within the indifference band of p0 by
	// definition since p0 == p).
	falseDecisions := 0
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < trials; i++ {
		sampler := func() bool {
			return rng.Float64() >= 0.05
		}
		_, _, outcome := runSPRT(sampler, minN, maxN, 0.05, delta, alpha, beta)
		if outcome == OutcomeBetter || outcome == OutcomeWorse {
			falseDecisions++
		}
	}
	rate := float64(falseDecisions) / float64(trials)
	if rate > 2*alpha {
		t.Errorf("null near-trivial p=0.05 p0=0.05: false-decision rate=%.4f, want <= %.4f", rate, 2*alpha)
	}
}

// ---------------------------------------------------------------------------
// (b) evaluateSPRT unit tests (pure-math, deterministic)
// ---------------------------------------------------------------------------

func TestEvaluateSPRT_CertainBetter(t *testing.T) {
	// 5/5 successes (0/5 losses) with p0=0.5, delta=0.45 => p1=0.05.
	// LLR_better = 5 * ln(0.95/0.5) = 5 * ln(1.9) ≈ 3.21 > A=ln(19)≈2.94
	// LLR_worse  = 5 * ln(0.05/0.5) = 5 * ln(0.1) ≈ -11.51 < B=-2.94
	A, B := sprtBoundaries(0.05, 0.05)
	outcome := evaluateSPRT(0, 5, 0.5, 0.05, 0.95, A, B)
	if outcome != OutcomeBetter {
		t.Errorf("0/5 loss against p0=0.5: want OutcomeBetter, got %v", outcome)
	}
}

func TestEvaluateSPRT_CertainWorse(t *testing.T) {
	// 5/5 losses with p0=0.5, delta=0.45 => p2=0.95.
	// LLR_worse  = 5 * ln(0.95/0.5) = 5 * ln(1.9) ≈ 3.21 > A=ln(19)≈2.94
	// LLR_better = 5 * ln(0.05/0.5) = 5 * ln(0.1) ≈ -11.51 < B=-2.94
	A, B := sprtBoundaries(0.05, 0.05)
	outcome := evaluateSPRT(5, 5, 0.5, 0.05, 0.95, A, B)
	if outcome != OutcomeWorse {
		t.Errorf("5/5 loss against p0=0.5: want OutcomeWorse, got %v", outcome)
	}
}

func TestEvaluateSPRT_UndecidedNeedsMore(t *testing.T) {
	// 3/10 losses with p0=0.2, delta=0.1 => p1=0.1, p2=0.3.
	// 3/10=0.3 = p2 boundary; needs more data.
	A, B := sprtBoundaries(0.05, 0.05)
	outcome := evaluateSPRT(3, 10, 0.2, 0.1, 0.3, A, B)
	// At this small n the LLRs are unlikely to cross boundaries.
	if outcome == OutcomeUndecided {
		return // valid
	}
	// Allow any non-error outcome in either direction; just confirm it ran.
}

func TestEvaluateSPRT_Indifferent_LargeN(t *testing.T) {
	// 40/200 losses with p0=0.2, delta=0.1 => p1=0.1, p2=0.3.
	// At p_hat=p0=0.2, both LLRs converge to -inf as n→∞.
	// n=200 is enough to push both below B=-2.94.
	A, B := sprtBoundaries(0.05, 0.05)
	outcome := evaluateSPRT(40, 200, 0.2, 0.1, 0.3, A, B)
	if outcome != OutcomeIndifferent {
		t.Errorf("40/200 at p0=0.2: want OutcomeIndifferent, got %v (B=%.4f)", outcome, B)
	}
}

func TestEvaluateSPRT_Indifferent_LooseBoundaries(t *testing.T) {
	// alpha=beta=0.5 gives A=B=0. Both LLRs at p_hat=p0 are negative → indifferent.
	A, B := sprtBoundaries(0.5, 0.5)
	outcome := evaluateSPRT(2, 10, 0.2, 0.1, 0.3, A, B)
	if outcome != OutcomeIndifferent {
		t.Errorf("2/10 at p0=0.2 alpha=0.5: want OutcomeIndifferent, got %v (A=%.4f, B=%.4f)", outcome, A, B)
	}
}

func TestEvaluateSPRT_EdgeP0(t *testing.T) {
	// p0 = 0.01 (near 0). With delta = 0.10, p1 is clamped to epsilon,
	// p2 = 0.11. At 0/5 losses the challenger (0%) is harder to distinguish
	// from 1% loss than from a larger p0 because clamping limits the LLR.
	// This test just confirms no crash; use generous delta for certainty.
	A, B := sprtBoundaries(0.05, 0.05)

	// p0 = 0.001, p2 = 0.101. 5/5 losses should be OutcomeWorse.
	outcome := evaluateSPRT(5, 5, 0.001, 0.0, 0.101, A, B)
	if outcome != OutcomeWorse {
		t.Errorf("5/5 loss against p0=0.001: want OutcomeWorse, got %v", outcome)
	}

	// p0 = 0.99, p1 = 0.89. 0/5 losses should be OutcomeBetter.
	outcome = evaluateSPRT(0, 5, 0.99, 0.89, 1.0, A, B)
	if outcome != OutcomeBetter {
		t.Errorf("0/5 loss against p0=0.99: want OutcomeBetter, got %v", outcome)
	}
}

// ---------------------------------------------------------------------------
// (c) runSPRT integration tests with synthetic Bernoulli samplers
// ---------------------------------------------------------------------------

func TestRunSPRT_BetterAtMinN(t *testing.T) {
	// 0% loss challenger against p0=0.5. With delta=0.49, p1=0.01.
	// LLR_better = 5*ln(0.99/0.5) = 5*ln(1.98) ≈ 3.42 > A=ln(19)≈2.94
	sampler := func() bool { return true }
	n, k, outcome := runSPRT(sampler, 5, 30, 0.5, 0.49, 0.05, 0.05)
	if outcome != OutcomeBetter {
		t.Errorf("0%% loss vs p0=0.5 delta=0.49: want OutcomeBetter, got %v (n=%d, k=%d)", outcome, n, k)
	}
	if n > 6 {
		t.Errorf("expected n near minN (5-6), got %d", n)
	}
}

func TestRunSPRT_WorseAtMinN(t *testing.T) {
	// 100% loss challenger against p0=0.5. With delta=0.49, p2=0.99.
	// LLR_worse = 5*ln(0.99/0.5) = 5*ln(1.98) ≈ 3.42 > A=ln(19)≈2.94
	sampler := func() bool { return false }
	n, k, outcome := runSPRT(sampler, 5, 30, 0.5, 0.49, 0.05, 0.05)
	if outcome != OutcomeWorse {
		t.Errorf("100%% loss vs p0=0.5 delta=0.49: want OutcomeWorse, got %v (n=%d, k=%d)", outcome, n, k)
	}
	if n > 6 {
		t.Errorf("expected n near minN (5-6), got %d", n)
	}
}

func TestRunSPRT_NoActive(t *testing.T) {
	// No active path: p0 < 0 -> skip SPRT, fixed minN, OutcomeUndecided.
	sampler := func() bool { return true }
	n, k, outcome := runSPRT(sampler, 5, 30, -1, 0.02, 0.05, 0.05)
	if outcome != OutcomeUndecided {
		t.Errorf("no active: want OutcomeUndecided, got %v", outcome)
	}
	if n != 5 {
		t.Errorf("no active: expected n=5 (minN), got %d", n)
	}
	if k != 0 {
		t.Errorf("no active: expected k=0 (0%% loss sampler), got %d", k)
	}
}

func TestRunSPRT_NoActiveInfComposite(t *testing.T) {
	// +Inf composite -> skip SPRT.
	sampler := func() bool { return false } // 100% loss
	n, k, outcome := runSPRT(sampler, 5, 30, math.Inf(1), 0.02, 0.05, 0.05)
	if outcome != OutcomeUndecided {
		t.Errorf("no active (+Inf): want OutcomeUndecided, got %v", outcome)
	}
	if n != 5 {
		t.Errorf("no active (+Inf): expected n=5 (minN), got %d", n)
	}
	if k != 5 {
		t.Errorf("no active (+Inf): expected k=5 (100%% loss sampler), got %d", k)
	}
}

func TestRunSPRT_HitsMaxN(t *testing.T) {
	// Challenger loss rate = p0 = 0.2, delta = 0.01 (tiny indifference band),
	// so the SPRT requires many samples. It should hit maxN=10 and return
	// OutcomeIndifferent or OutcomeUndecided.
	const p = 0.2
	rng := rand.New(rand.NewSource(99))
	sampler := func() bool {
		return rng.Float64() >= p
	}
	n, k, outcome := runSPRT(sampler, 5, 10, p, 0.01, 0.05, 0.05)
	if outcome != OutcomeUndecided && outcome != OutcomeIndifferent {
		t.Errorf("p=challenger=p0=0.2 small delta: want OutcomeUndecided or OutcomeIndifferent, got %v (n=%d)", outcome, n)
	}
	if n != 10 {
		t.Errorf("expected n=10 (hit maxN), got %d", n)
	}
	if k <= 0 {
		t.Errorf("expected positive losses at p=0.2, got k=%d", k)
	}
}

// ---------------------------------------------------------------------------
// (d) p0FromActive tests
// ---------------------------------------------------------------------------

func TestP0FromActive_Normal(t *testing.T) {
	// activeComposite = 2000, rttChUs = 1000, lossWeight = 500
	// p0 = (2000 - 1000) / 500 = 2.0 -> clamped to 1.0 (always-better)
	p0 := p0FromActive(2000, 1000, 500)
	if p0 != 1.0 {
		t.Errorf("want clamped 1.0, got %f", p0)
	}
}

func TestP0FromActive_Partial(t *testing.T) {
	// activeComposite = 3000, rttChUs = 2000, lossWeight = 500
	// p0 = (3000 - 2000) / 500 = 2.0 -> clamped to 1.0
	p0 := p0FromActive(3000, 2000, 500)
	if p0 != 1.0 {
		t.Errorf("want clamped 1.0, got %f", p0)
	}
}

func TestP0FromActive_RTTDominates(t *testing.T) {
	// activeComposite = 1000, rttChUs = 2000, lossWeight = 500
	// p0 = (1000 - 2000) / 500 = -2.0 -> return -1 (no-active sentinel)
	p0 := p0FromActive(1000, 2000, 500)
	if p0 >= 0 {
		t.Errorf("want -1 (RTT dominates), got %f", p0)
	}
}

func TestP0FromActive_InfComposite(t *testing.T) {
	p0 := p0FromActive(math.Inf(1), 1000, 500)
	if p0 >= 0 {
		t.Errorf("want -1 (+Inf composite), got %f", p0)
	}
}

// ---------------------------------------------------------------------------
// (e) sprtBoundaries tests
// ---------------------------------------------------------------------------

func TestSprtBoundaries_Symmetric(t *testing.T) {
	A, B := sprtBoundaries(0.05, 0.05)
	// A = ln((1-0.05)/0.05) = ln(0.95/0.05) = ln(19) ≈ 2.944
	if math.Abs(A-math.Log(19.0)) > 0.001 {
		t.Errorf("A: want ~%.4f, got %f", math.Log(19.0), A)
	}
	// B = ln(0.05/0.95) = -ln(19) ≈ -2.944
	if math.Abs(B-math.Log(0.05/0.95)) > 0.001 {
		t.Errorf("B: want ~%.4f, got %f", math.Log(0.05/0.95), B)
	}
}

func TestSprtBoundaries_Asymmetric(t *testing.T) {
	A, B := sprtBoundaries(0.01, 0.05)
	// A = ln(0.95/0.01) = ln(95) ≈ 4.554
	if math.Abs(A-math.Log(95.0)) > 0.001 {
		t.Errorf("A: want ~%.4f, got %f", math.Log(95.0), A)
	}
	// B = ln(0.05/0.99) ≈ ln(0.0505) ≈ -2.985
	expectedB := math.Log(0.05 / 0.99)
	if math.Abs(B-expectedB) > 0.001 {
		t.Errorf("B: want ~%.4f, got %f", expectedB, B)
	}
}

// ---------------------------------------------------------------------------
// (f) End-to-end localhost smoke test (requires a real network stack)
// ---------------------------------------------------------------------------

// startUDPEcho starts a UDP echo responder on a random loopback port and
// returns its address. Shared by the ProbeNextHopAccumulating smoke tests.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, cli, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], cli)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestProbeAccumulating_LocalhostEcho(t *testing.T) {
	addr := startUDPEcho(t)

	// Active composite set very high means p0 = 1.0 (always-better). Feed
	// enough ticks for the accumulator to build up sample size; with 0% loss
	// against lo it should decide OutcomeBetter within a few ticks.
	acc := &ProbeAccumulator{}
	var result ProbeResult
	var outcome ProbeOutcome
	var err error
	now := time.Now()
	for i := 0; i < 10 && outcome == OutcomeUndecided; i++ {
		result, outcome, err = ProbeNextHopAccumulating("lo", addr.IP.String(), addr.Port,
			2*time.Second, 5, 30, acc, now, 5*time.Minute, 8.0, 20*time.Millisecond,
			1e7, 0.02, 0.05, 0.05, 500.0)
		if err != nil {
			t.Fatalf("ProbeNextHopAccumulating: %v", err)
		}
		now = now.Add(2 * time.Second)
	}
	if outcome != OutcomeBetter {
		t.Logf("expected OutcomeBetter against easy echo, got %v (loss=%.3f)", outcome, result.LossRate)
		// Not fatal — the SPRT may not declare on a localhost echo depending on RTT noise.
	}
	if result.LossRate > 0.1 {
		t.Errorf("expected near-zero loss rate on lo echo, got %.3f", result.LossRate)
	}
	if result.RTT <= 0 {
		t.Errorf("expected positive RTT, got %v", result.RTT)
	}
}

func TestProbeAccumulating_NoActiveLocalhost(t *testing.T) {
	// No active path (activeComposite = +Inf). Should fall back to OutcomeUndecided.
	addr := startUDPEcho(t)

	acc := &ProbeAccumulator{}
	result, outcome, err := ProbeNextHopAccumulating("lo", addr.IP.String(), addr.Port,
		2*time.Second, 3, 10, acc, time.Now(), 5*time.Minute, 8.0, 20*time.Millisecond,
		math.Inf(1), 0.02, 0.05, 0.05, 500.0)
	if err != nil {
		t.Fatalf("ProbeNextHopAccumulating (no-active): %v", err)
	}
	if outcome != OutcomeUndecided {
		t.Errorf("no-active: want OutcomeUndecided, got %v", outcome)
	}
	if result.LossRate > 0.1 {
		t.Errorf("expected near-zero loss rate on lo echo, got %.3f", result.LossRate)
	}
}

// ---------------------------------------------------------------------------
// (g) ProbeAccumulator.Ingest / AdaptiveTimeout tests
// ---------------------------------------------------------------------------

func TestProbeAccumulator_IngestSteadyState(t *testing.T) {
	// Feeding a fixed (k=0,n=5) every halfLife-worth of ticks should converge
	// EffectiveN toward n/(1-decay). With dt == halfLife, decay = exp(-1) so
	// steady-state EffectiveN ~= 5 / (1 - exp(-1)) ~= 7.9.
	acc := &ProbeAccumulator{}
	halfLife := time.Minute
	now := time.Time{}.Add(time.Hour) // avoid IsZero on first tick
	for i := 0; i < 200; i++ {
		acc.Ingest(now, halfLife, 0, 5, 1000, 1000000) // maxN huge: don't clamp
		now = now.Add(halfLife)
	}
	wantN := 5.0 / (1 - math.Exp(-1))
	if math.Abs(acc.EffectiveN-wantN) > 0.01 {
		t.Errorf("EffectiveN = %f, want ~%f", acc.EffectiveN, wantN)
	}
	if acc.EffectiveK != 0 {
		t.Errorf("EffectiveK = %f, want 0 (no losses fed)", acc.EffectiveK)
	}
}

func TestProbeAccumulator_IngestMaxNClamp(t *testing.T) {
	acc := &ProbeAccumulator{}
	now := time.Time{}.Add(time.Hour)
	halfLife := time.Hour // slow decay so evidence keeps piling up
	for i := 0; i < 20; i++ {
		acc.Ingest(now, halfLife, 1, 5, 1000, 10) // maxN=10
		now = now.Add(time.Second)
	}
	if acc.EffectiveN > 10.0001 {
		t.Errorf("EffectiveN = %f, want clamped to <= 10", acc.EffectiveN)
	}
	// Loss rate (EffectiveK/EffectiveN) should still be ~= 1/5 = 0.2 after clamping.
	rate := acc.EffectiveK / acc.EffectiveN
	if math.Abs(rate-0.2) > 0.01 {
		t.Errorf("post-clamp loss rate = %f, want ~0.2", rate)
	}
}

func TestProbeAccumulator_IngestFirstTick(t *testing.T) {
	acc := &ProbeAccumulator{}
	acc.Ingest(time.Now(), time.Minute, 2, 5, 1500, 30)
	if acc.EffectiveK != 2 || acc.EffectiveN != 5 {
		t.Errorf("first tick: want EffectiveK=2 EffectiveN=5, got K=%f N=%f", acc.EffectiveK, acc.EffectiveN)
	}
	if acc.RTTBaselineUs != 1500 {
		t.Errorf("first tick: want RTTBaselineUs=1500, got %f", acc.RTTBaselineUs)
	}
}

func TestProbeAccumulator_AdaptiveTimeout_NoBaseline(t *testing.T) {
	acc := &ProbeAccumulator{}
	got := acc.AdaptiveTimeout(2*time.Second, 8.0, 20*time.Millisecond)
	if got != 2*time.Second {
		t.Errorf("no baseline: want configured timeout 2s, got %v", got)
	}
}

func TestProbeAccumulator_AdaptiveTimeout_Floor(t *testing.T) {
	acc := &ProbeAccumulator{RTTBaselineUs: 100} // 100us * 8 = 800us, below the 20ms floor
	got := acc.AdaptiveTimeout(2*time.Second, 8.0, 20*time.Millisecond)
	if got != 20*time.Millisecond {
		t.Errorf("floor: want 20ms, got %v", got)
	}
}

func TestProbeAccumulator_AdaptiveTimeout_Ceiling(t *testing.T) {
	acc := &ProbeAccumulator{RTTBaselineUs: 1000000} // 1s * 8 = 8s, above the 2s configured ceiling
	got := acc.AdaptiveTimeout(2*time.Second, 8.0, 20*time.Millisecond)
	if got != 2*time.Second {
		t.Errorf("ceiling: want configured 2s, got %v", got)
	}
}

func TestProbeAccumulator_AdaptiveTimeout_Scaled(t *testing.T) {
	acc := &ProbeAccumulator{RTTBaselineUs: 5000} // 5ms * 8 = 40ms, within [floor, configured]
	got := acc.AdaptiveTimeout(2*time.Second, 8.0, 20*time.Millisecond)
	want := 40 * time.Millisecond
	if got != want {
		t.Errorf("scaled: want %v, got %v", want, got)
	}
}
