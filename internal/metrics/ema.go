// Package metrics provides EMA-based loss-rate smoothing for the transit-loss
// detector, ported from ebpf-packet-loss-exporter/internal/metrics/ema.go.
package metrics

import (
	"math"
	"sync"
	"time"

	"pathprofiler/internal/maps"
)

// TransitDelta represents the per-tick delta from the transit_loss_map.
type TransitDelta struct {
	Segments    uint64
	Retransmits uint64
}

// PathEMA holds the smoothed loss-rate state for a single path_key.
type PathEMA struct {
	NextHopIP       uint32
	DstSubnet       uint32
	InstantLossRate float64 // sliding-window loss rate (per-tick average)
	InstantLossErr  float64 // Wilson 95% semi-width on the sliding-window binomial
	EMALossRate     float64 // EMA-smoothed loss rate (feeds score.Compute)
	EMALossRateErr  float64 // EMA-smoothed error (same EMA from InstantLossErr)
	LastUpdate      time.Time
	LastTick        time.Time
	WindowSegments  uint64   // total segments in sliding window (sample count for Confidence)
	// internal sliding window state
	window    []sample
	windowCap int
	windowPos int
	windowLen int
	sumSeg    uint64
	sumRet    uint64
}

type sample struct {
	seg uint64
	ret uint64
}

// EMAStore manages per-path EMA state with concurrent read access.
type EMAStore struct {
	mu    sync.RWMutex
	paths map[maps.PathKey]*PathEMA
	// config
	instantWindow time.Duration // sliding window width (default 10s)
	emaHalfLife   time.Duration // EMA half-life (default 5m)
}

// NewEMAStore creates an EMAStore. instantWindow controls the sliding-window
// width (default 10s), emaHalfLife controls the EMA smoothing factor (default 5m).
func NewEMAStore(instantWindow, emaHalfLife time.Duration) *EMAStore {
	return &EMAStore{
		paths:         make(map[maps.PathKey]*PathEMA),
		instantWindow: instantWindow,
		emaHalfLife:   emaHalfLife,
	}
}

// windowCap returns the number of ticks that fit in the instant window.
// Called lazily on first update per path to accommodate ticker interval changes.
func (s *EMAStore) windowCap(interval time.Duration) int {
	n := int(s.instantWindow / interval)
	if n < 1 {
		n = 1
	}
	return n
}

// Update feeds a map of per-path transit deltas into the EMA store.
// Called once per tick with the delta'd transit counters.
func (s *EMAStore) Update(now time.Time, interval time.Duration, deltas map[maps.PathKey]TransitDelta) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for pk, delta := range deltas {
		p, ok := s.paths[pk]
		if !ok {
			cap := s.windowCap(interval)
			p = &PathEMA{
				NextHopIP: pk.NextHopIP,
				DstSubnet: pk.DstSubnet,
				window:    make([]sample, cap),
				windowCap: cap,
			}
			s.paths[pk] = p
		}

		// Sliding window update
		if p.windowLen == p.windowCap {
			old := p.window[p.windowPos]
			p.sumSeg -= old.seg
			p.sumRet -= old.ret
		} else {
			p.windowLen++
		}
		p.window[p.windowPos] = sample{seg: delta.Segments, ret: delta.Retransmits}
		p.sumSeg += delta.Segments
		p.sumRet += delta.Retransmits
		p.windowPos = (p.windowPos + 1) % p.windowCap

		// Expose the total segment count in the window for Confidence derivation.
		p.WindowSegments = p.sumSeg

		// Instant rate and Wilson confidence interval on the sliding window.
		if p.sumSeg > 0 {
			instant := float64(p.sumRet) / float64(p.sumSeg)
			p.InstantLossRate = instant
			p.InstantLossErr = wilsonLossErr(int(p.sumRet), int(p.sumSeg))

			// EMA update on both rate and error.
			dt := interval
			if !p.LastTick.IsZero() {
				dt = now.Sub(p.LastTick)
			}
			alpha := 1.0 - math.Exp(-dt.Seconds()/s.emaHalfLife.Seconds())
			if alpha < 0 {
				alpha = 0
			}
			if p.LastUpdate.IsZero() {
				p.EMALossRate = instant
				p.EMALossRateErr = p.InstantLossErr
			} else {
				p.EMALossRate = alpha*instant + (1.0-alpha)*p.EMALossRate
				p.EMALossRateErr = alpha*p.InstantLossErr + (1.0-alpha)*p.EMALossRateErr
			}
			p.LastUpdate = now
		}
		// sumSeg == 0: hold rates unchanged

		p.LastTick = now
	}
}

// Snapshot returns a copy of the current EMA state for all paths.
func (s *EMAStore) Snapshot() map[maps.PathKey]PathEMA {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[maps.PathKey]PathEMA, len(s.paths))
	for pk, p := range s.paths {
		cp := *p
		out[pk] = cp
	}
	return out
}

// wilsonLossErr returns the semi-width (±) of the 95% Wilson score interval
// for k observed losses out of n probes. Duplicated from internal/actuate/prober.go
// (unexported there) so the metrics package does not depend on the actuate package.
func wilsonLossErr(k, n int) float64 {
	if k > n || n == 0 {
		return 0
	}
	if k == n {
		return 0
	}
	phat := float64(k) / float64(n)
	z := 1.96
	z2 := z * z
	fn := float64(n)

	center := (float64(k) + z2/2.0) / (fn + z2)
	margin := z * math.Sqrt((phat*(1.0-phat)+z2/(4.0*fn))/fn) / (1.0 + z2/fn)

	lower := center - margin
	upper := center + margin
	if lower < 0 {
		lower = 0
	}
	semi := (upper - lower) / 2.0
	if semi < 0 {
		semi = 0
	}
	return semi
}