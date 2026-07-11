# Changelog

## v0.0.3

- **Dampener-gated cold-probe SPRT reference.** Fixed the SPRT `outcome` for
  a cold-probe leg flip-flopping between `worse` and `undecided` tick to
  tick with no change in the underlying evidence. `activeComposite`/
  `activeNeighbor` (`cmd/daemon/main.go`) previously came from raw per-tick
  `minComposite()` ranking — recomputed every tick, ignoring the dampener,
  and including the probed leg's own composite in the pool it was judged
  against. Now sourced from `appliedActiveNeighbor`/`appliedActiveComposite`,
  a mirror updated only when a neighbor's tier update is actually applied
  (dampener-allowed and `SetNeighborTiers` succeeds), via new
  `syncAppliedActiveMirror`. The SPRT reference's identity is now
  rate-limited by `--min-dwell` instead of moving with ordinary EMA noise or
  a tier flip that never made it into FRR. (`outcome` remains log-only —
  not wired into `RankByTier`/actuation.)

- **Clsact-only TC egress.** Removed TCX primary path; the TC egress program
  now attaches exclusively via clsact (netlink BpfFilter). TCX only supports one
  program per interface per direction, which prevented coexistence with other
  eBPF-based tools like `ebpf-packet-loss-exporter` on the same interface.
  clsact supports multiple filters, so both tools can now receive traffic.
  Stale TCX links and clsact filters from prior pathprofiler runs are cleaned
  up at startup — matched strictly by our own `transit_egress` program name,
  never touching other tools' filters (e.g. ebpf-packet-loss-exporter's
  `path_egress`) sharing the same interface.

- **Transit loss detection.** Replaced `egress_sockops` + `egress_retrans` with
  `transit_loss.bpf.c` — a TC egress hook that uses a double-buffered Bloom
  filter to detect TCP retransmits from forwarded (transit) traffic, with
  per-path PERCPU_HASH counters. No sockops or local socket termination needed.

- **EMA-smoothed loss rates.** New `internal/metrics/ema.go` provides a
  sliding-window + exponentially weighted moving average of transit loss rates
  with Wilson-score error bands. Configurable via `--transit-ema-half-life`
  (default 5m).

- **Transit override pipeline.** Real forwarded-traffic loss (from transit EMA)
  overrides synthetic cold-probe loss rates per (prefix, next-hop). Transit
  `Confidence` from observed segment count enables `RankByTier` to promote
  neighbors above `defaultTier` even without local TCP flows.

- **Adaptive cold prober with SPRT.** `ProbeNextHopAccumulating` uses a
  three-decision Wald sequential probability ratio test (`OutcomeBetter / Worse
  / Indifferent / Undecided`). Configurable indifference band, error rates, and
  probe count bounds via YAML and CLI flags. Falls back to `OutcomeUndecided`
  when no active-path composite (or no RTT baseline) exists (cold-vs-cold).

- **Cross-tick SPRT accumulation + adaptive probe timeout.** Replaced the
  one-shot `ProbeNextHopAdaptive` (which restarted the SPRT from `k=0,n=0`
  every tick, needing thousands of samples in one blocking burst to resolve a
  tight indifference band at real-world loss rates) with `ProbeNextHopAccumulating`:
  a new `ProbeAccumulator` (`internal/actuate/probe_accumulator.go`) carries
  exponentially-decayed pseudo-counts and an RTT baseline per `(prefix, iface,
  next-hop)` leg across ticks, so a small fixed burst per tick accumulates the
  sample size the SPRT needs over several ticks instead of one large blocking
  call. Each tick's per-probe timeout is itself adaptive — derived from the
  leg's RTT baseline (`ema_half_life_seconds`, `timeout_rtt_multiplier`,
  `min_timeout_ms`) instead of a flat `timeout_seconds` — so a lost probe no
  longer waits out the full configured timeout once a real RTT baseline is
  known.

- **Standalone `pathprofiler-responder` binary for real UDP echo replies.**
  Cold probes previously relied on the destination generating ICMP
  port-unreachable (nothing listens on the probe port), which most kernels
  rate-limit (`net.ipv4.icmp_ratelimit`, historically ~1/sec per destination)
  -- a burst sent faster than that (routine once the adaptive per-probe
  timeout above kicks in) saw only the first probe or two actually replied
  to, making healthy links look 40-90%+ "lossy". New `cmd/responder`
  (`pathprofiler-responder`) is a separate, minimal binary: `--port` flag,
  calls `actuate.StartColdProbeResponder` (`internal/actuate/responder.go`),
  echoes back only datagrams whose payload exactly matches the fixed probe
  payload (1:1 size, no amplification), and blocks forever. No YAML config,
  no BPF, no FRR/vtysh, no root/capabilities -- it imports only
  `internal/actuate`, which has zero dependency on `internal/loader`/
  `internal/maps`, so `make responder` builds with plain `go build` and no
  BPF toolchain at all. Ships with its own `scripts/pathprofiler-responder.service`
  (unprivileged `DynamicUser=yes` unit) and `scripts/install-cold-probe-responder.sh`
  (mirrors `install.sh`, trimmed: no AppArmor/config steps, `--port` flag
  `sed`-patches the unit's `ExecStart`). Release workflow now builds and
  publishes both binaries per architecture.

- **Multi-probe burst + median RTT.** Cold probes now send a burst of N UDP
  probes per target and return median RTT, measured loss rate (k/N), and
  Wilson-score error band — replacing the single binary lost/not-lost model.

- **LPM trie `dst_to_nexthop`.** Upgraded from LRU_HASH to LPM_TRIE keyed by
  (prefixlen, daddr). Populated from the RIB prefix sweep (`populateDstToNexthopFromRIB`)
  rather than passive egress data, fixing the bootstrap deadlock where transit
  traffic couldn't populate the map needed to produce transit data.

- **Per-neighbor route-map actuation.** Route-maps are applied atomically per
  BGP neighbor (one route-map per neighbor, rewritten each tick). Fixed
  `RemoveNeighborTiers` to issue `no neighbor ... route-map ... in` inside
  `router bgp` context so drained-neighbor cleanup works correctly.

- **Error-band gating in ranking.** `RankByTier` applies `compositeIntervalsOverlap`
  gating: neighbors whose composite error bands overlap are capped at the same
  tier, suppressing noise-driven flapping from statistically indistinguishable paths.

- **TCX/clsact attachment.** TC egress program uses `link.AttachTCX` (kernel
  6.6+) with `netlink.BpfFilter` clsact fallback for older kernels. Deferred
  attachment retries until OSPF underlay is available.

- **Config expansion.** Probe config extended with adaptive SPRT parameters
  (`min_count`, `max_count`, `delta`, `alpha`, `beta`) plus cross-tick
  accumulation/adaptive-timeout parameters (`ema_half_life_seconds`,
  `timeout_rtt_multiplier`, `min_timeout_ms`). All validated at startup.
  CLI flags for all adaptive probe params plus `--transit-ema-half-life`.

- **Diagnostic tripwires.** `transit_debug_dropped` per-CPU counter for
  `dst_to_nexthop` misses. Confidence-zero self-check warning on every tick
  when no neighbor has `Confidence > 0`. First-populate entry count log.

- **AppArmor & systemd hardening.** Updated AppArmor profile for `ip` command
  access (`dst_to_nexthop` population) and vtysh `.tmp` file handling. Systemd
  unit comment updated to reflect TC egress instead of sockops.

- **Simplified test suite.** `rank_test.go` reduced from ~750 to ~300 lines,
  replacing redundant cases with targeted `prober_adaptive_test.go` (440 lines)
  covering SPRT decisions, median RTT, and Wilson error computation.

- **Dependency additions.** `github.com/vishvananda/netlink` (TC clsact
  fallback), `golang.org/x/sys` promoted from indirect to direct.

## v0.0.2

- Delete dead `ShouldSwitch` function (replaced by RankByTier).
- Cold probes set `Confidence=0` (underlay taint) so CollapseByNeighbor drops
  them when passive data exists, and RankByTier demotes them.
- Add cold-probe regression tests covering collapse, ranking, and monotonicity.