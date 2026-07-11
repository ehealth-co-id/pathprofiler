//go:build linux

package actuate

import (
	"math"
	"time"
)

// ProbeKey identifies one cold-probe leg being tracked across ticks: a
// specific physical next-hop, on a specific interface, as a candidate for a
// specific prefix (no cross-prefix dedup -- see plan).
type ProbeKey struct {
	Prefix  string
	Iface   string
	NextHop string
}

// ProbeAccumulator carries decayed SPRT sufficient statistics and an RTT
// baseline for one ProbeKey across ticks, so the SPRT accumulates evidence
// from many small per-tick bursts instead of needing one large blocking
// burst to resolve. Mirrors metrics.PathEMA's decay formula.
//
// ponytail: EffectiveK/EffectiveN are exponentially-discounted pseudo-counts,
// not exact Bernoulli counts -- a discounted/weighted SPRT approximation,
// not textbook Wald SPRT (which assumes one fixed p across all n samples).
// Fine for a slowly-drifting path; upgrade path is a proper CUSUM/GLR test
// if the discounting bias ever matters.
type ProbeAccumulator struct {
	EffectiveK    float64
	EffectiveN    float64
	RTTBaselineUs float64
	LastUpdate    time.Time
}

// Ingest folds one tick's (kTick losses, nTick probes, rttMedianUs) into the
// accumulator: decays prior evidence by exp(-dt/halfLife) (same formula as
// EMAStore.Update), adds this tick's counts, and clamps EffectiveN to maxN
// (scaling EffectiveK proportionally so the loss rate is preserved) so
// MaxCount keeps its existing meaning as a ceiling.
func (a *ProbeAccumulator) Ingest(now time.Time, halfLife time.Duration, kTick, nTick int, rttMedianUs float64, maxN int) {
	if a.LastUpdate.IsZero() {
		a.EffectiveK, a.EffectiveN = float64(kTick), float64(nTick)
		a.RTTBaselineUs = rttMedianUs
	} else {
		dt := now.Sub(a.LastUpdate)
		decay := math.Exp(-dt.Seconds() / halfLife.Seconds())
		a.EffectiveK = a.EffectiveK*decay + float64(kTick)
		a.EffectiveN = a.EffectiveN*decay + float64(nTick)
		if rttMedianUs > 0 {
			alpha := 1.0 - decay
			a.RTTBaselineUs = alpha*rttMedianUs + (1-alpha)*a.RTTBaselineUs
		}
	}
	a.LastUpdate = now

	if maxN > 0 && a.EffectiveN > float64(maxN) {
		scale := float64(maxN) / a.EffectiveN
		a.EffectiveN = float64(maxN)
		a.EffectiveK *= scale
	}
}

// AdaptiveTimeout returns clamp(multiplier * RTTBaseline, floor, configured).
// Falls back to configured timeout when RTTBaselineUs == 0 (no baseline yet
// -- first burst for this leg), so first-tick behavior is unchanged from
// today's flat timeout.
func (a *ProbeAccumulator) AdaptiveTimeout(configured time.Duration, multiplier float64, floor time.Duration) time.Duration {
	if a.RTTBaselineUs <= 0 {
		return configured
	}
	t := time.Duration(a.RTTBaselineUs*multiplier) * time.Microsecond
	if t < floor {
		t = floor
	}
	if t > configured {
		t = configured
	}
	return t
}
