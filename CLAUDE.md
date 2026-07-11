# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pathprofiler` is a Linux daemon (Go + eBPF) that watches path health (latency, jitter, TCP retransmits) for BGP/OSPF next-hops on a router and dynamically reweights routes — via FRR `vtysh` route-maps setting local-pref — so traffic shifts off degrading paths without restarting connections. It targets **transit routers that forward traffic**, not hosts terminating TCP locally (no sockops path).

Module: `pathprofiler` (Go 1.22). Two binary targets: `bin/pathprofiler-daemon` (the full BPF+FRR daemon) and `bin/pathprofiler-responder` (standalone cold-probe UDP echo responder, `cmd/responder`, no BPF dependency).

## Build

```bash
make vmlinux    # generate bpf/vmlinux.h from running kernel BTF (no-op if already present)
make bpf        # compile bpf/*.bpf.c -> bpf/*.bpf.o via clang -target bpf
make daemon     # copy bpf/*.bpf.o -> internal/loader/, then go build ./cmd/daemon -> bin/pathprofiler-daemon
make responder  # plain `go build ./cmd/responder` -> bin/pathprofiler-responder; deliberately has no bpf/vmlinux prerequisite since internal/actuate has no dependency on internal/loader or internal/maps
make all        # vmlinux + bpf + daemon + responder
make clean      # remove compiled .bpf.o (both bpf/ and internal/loader/) and both binaries
```

`internal/loader/loader.go` embeds its BPF objects with `//go:embed *.bpf.o` **from its own directory**, not from `bpf/`. `make daemon` is what copies the freshly compiled objects over. Compiled `.bpf.o` files are already checked into `internal/loader/` in this tree, so `go build ./...` / `go test ./...` work standalone — but after editing any `bpf/*.bpf.c` source, you must rebuild and re-copy (`make bpf && cp bpf/*.bpf.o internal/loader/`, or just `make daemon`) or the daemon will embed stale bytecode.

BPF compilation needs `clang`/`llvm` 14+, `libbpf-dev`, and (for `make vmlinux`) `bpftool`; CI (`.github/workflows/release.yml`) instead fetches a prebuilt `vmlinux.h` from `libbpf/vmlinux.h` since GitHub's `-azure` kernel has no matching `linux-tools` package for `bpftool btf dump`.

## Test / lint

```bash
go test ./...                                   # all packages
go test ./internal/score/...                    # one package
go test ./internal/score/ -run TestRankByTier    # one test
go vet ./...
```

Files that touch kernel syscalls or embed BPF objects carry `//go:build linux` (`cmd/daemon/main.go`, `cmd/responder/main.go`, `internal/actuate/prober.go`, `internal/actuate/probe_accumulator.go`, `internal/actuate/responder.go`, `internal/loader/loader.go`, and their `_test.go` counterparts) — normal on this dev box (WSL2 Linux), but be aware if a `go build`/`go test` invocation seems to silently skip a package on another OS.

External-command dependencies are injected via package-level vars so tests can swap them without a subprocess: `bgp.runVtysh`, `ospf.runVtysh`, `actuate.runVtysh` (all `vtysh`), and `netutil.ipRouteGetCmd` (`ip route get`). Follow this pattern for any new shell-out.

## Architecture

Runtime data flow (one `--poll` tick of the loop in `cmd/daemon/main.go`):

```
vtysh "show ip bgp json"  --> bgp.FetchRIB --> bgp.InScope(scope.prefixes)
vtysh "show ip ospf route json" --> ospf.FetchTopo --> Underlay{loopback -> []PhysicalPath}
TC egress (transit_loss.bpf.c) --> maps.AllTransit --> metrics.EMAStore --> EMA snapshot
  for each in-scope (prefix, path): netutil.ResolvePaths + actuate.ProbeNextHopAdaptive (cold UDP probe)
    --> score.FromProbeResult --> synthetic PathCost
  transit EMA overrides cold-probe loss rate + bumps Confidence where forwarded traffic exists
  --> score.CollapseByNeighbor (average ECMP legs per neighbor) --> score.RankByTier (per prefix)
  --> score.GroupByNeighbor (merge across prefixes into one update per neighbor)
  --> dampener.Allow? --> actuate.SetNeighborTiers (one route-map per neighbor, rewritten atomically)
  --> neighbors missing this tick: actuate.RemoveNeighborTiers (Drained -> Absent cleanup)
```

Topology (RIB + OSPF underlay) refreshes on a slower cadence (`probeInterval`, YAML/CLI `probe.interval_seconds`) than the poll tick; XDP/TC attachment is retried opportunistically once underlay data first becomes available (FRR may not be up at daemon startup).

### Package map

- `bpf/` — eBPF C sources compiled with `clang -target bpf`. `transit_loss.bpf.c` (TC egress hook): double-buffered Bloom filter detects TCP retransmits from **forwarded** traffic, PERCPU_HASH counters keyed by `path_key{next_hop_ip, dst_subnet}`. `ingress_xdp.bpf.c`: inter-arrival jitter + sequence-gap proxy on ingress. `common.h` defines the shared struct layouts (`lpm_key`, `path_key`, `transit_stats`, `ingress_stats`) — these must byte-match the Go structs in `internal/maps/maps.go` exactly (field order/size), since map values are read as raw bytes.
- `internal/loader/` — loads embedded `.bpf.o`, pins all maps under `/sys/fs/bpf/pathprofiler/`, attaches ingress XDP and TC egress. TC attaches via **clsact only** (not TCX) so other eBPF tools (e.g. `ebpf-packet-loss-exporter`) can coexist on the same interface; `DetachStaleTC` cleans up both clsact filters and legacy TCX links left by prior daemon runs before attaching fresh ones.
- `internal/maps/` — typed readers (`cilium/ebpf`) over the pinned maps; sums PERCPU_HASH values across CPUs.
- `internal/metrics/` — `EMAStore`: sliding-window + exponentially-weighted average of transit loss-rate deltas, with Wilson-score error bands, half-life configurable via `--transit-ema-half-life`.
- `internal/bgp/` — parses `vtysh -c "show ip bgp json"` (FRR 10.x schema). `InScope` filters by CIDR containment against `scope.prefixes`; `PrefixForSubnet` does the reverse longest-match lookup used to join passive BPF stats back to a RIB prefix.
- `internal/ospf/` — parses `vtysh -c "show ip ospf route json"`; `Underlay` maps each BGP loopback to its `[]PhysicalPath` (interface + gateway IP, ECMP-aware). `LoopbackForGateway` is the reverse lookup and **assumes gateway IP uniquely identifies one loopback** — returns an error on ambiguity rather than silently misattributing traffic.
- `internal/netutil/` — resolves egress interface/next-hop via `ip route get` output parsing.
- `internal/score/` — `score.go`: `Compute` (passive path cost from raw counter deltas) and `FromProbeResult` (cold-probe path cost) both funnel through the single `composite()` weighted-cost formula (`internal/score/score.go`), so passive and active measurements stay on the same scale. `rank.go`: `CollapseByNeighbor` averages multiple ECMP legs sharing a BGP neighbor into one `PathCost`; `RankByTier` assigns local-pref tiers (best/2nd/default) per prefix with Confidence gating (<0.5 can't be promoted), error-band overlap gating (`compositeIntervalsOverlap` — statistically indistinguishable paths get capped to the same tier), and a monotonicity invariant (a worse-ranked path can never get a higher tier than a better-ranked one); `GroupByNeighbor` merges per-prefix updates into the actual actuation unit — one update per neighbor.
- `internal/actuate/` — `actuate.go`: `SetNeighborTiers`/`RemoveNeighborTiers` shell out to `vtysh`, generating **one route-map per BGP neighbor** (`PATHPROFILER-<neighbor-slug>`), stateless (`no route-map ...` then full re-add every call) so stale sequence numbers can't persist; a final `permit 65535` catch-all passes through out-of-scope prefixes. `Dampener` enforces `--min-dwell` per neighbor to prevent flapping. `ListAppliedNeighbors`/`ParseAppliedNeighbors` bootstrap applied-neighbor state from FRR's running-config at startup so a daemon restart doesn't orphan prior route-maps. `prober.go`: `ProbeNextHop`/`ProbeNextHopAccumulating` send UDP probes bound to a specific interface (`SO_BINDTODEVICE`, deterministic next-hop selection instead of hash-matching ECMP buckets); the accumulating variant runs a three-decision Wald SPRT (`OutcomeBetter/Worse/Indifferent/Undecided`) against `probe_accumulator.go`'s `ProbeAccumulator` (decayed evidence carried across ticks, keyed per `(prefix, iface, next-hop)`) rather than a one-shot burst. `responder.go`: `StartColdProbeResponder` -- a UDP listener that echoes back exact-payload-matching probes so peers don't depend on (often rate-limited) ICMP port-unreachable; used by the standalone `cmd/responder` binary, not `cmd/daemon`.
- `internal/config/` — YAML config (`scope`/`tiers`/`probe`), strict unknown-field rejection (`yaml.Decoder.KnownFields(true)`), defaults + validation (distinct positive tiers, valid CIDRs, SPRT params in range). CLI flags override YAML only when explicitly set (nonzero).
- `cmd/daemon/main.go` — the control loop described above; also owns dst_to_nexthop population (`populateDstToNexthopFromRIB`, resolves one representative host IP per in-scope prefix via `ip route get` and writes an LPM trie entry so BPF can classify forwarded traffic without needing passive data first — this breaks what would otherwise be a bootstrap deadlock) and several tripwire/self-check log lines (e.g. warning when no cold-probe entry ever gets `Confidence>0`, meaning transit data isn't flowing).
- `cmd/responder/main.go` — standalone `pathprofiler-responder` binary: `--port` flag, calls `actuate.StartColdProbeResponder`, blocks forever. No `internal/config`, no BPF, no FRR/vtysh — imports only `internal/actuate`, which has no dependency on `internal/loader`/`internal/maps`, so this builds with plain `go build` and needs no root/capabilities to run.
- `scripts/` — `install.sh` (fetches daemon release binary + checksum, installs systemd unit + AppArmor profile), `install-cold-probe-responder.sh` (same shape, trimmed: no AppArmor/config step, fetches `pathprofiler-responder` instead), `pathprofiler.service`, `pathprofiler-responder.service`, `pathprofiler.apparmor`, `pathprofiler.yaml.example`.

### Conventions to preserve when editing

- **`ponytail:` comments** mark an intentional simplification with a named ceiling and upgrade path (e.g. O(n²) scan, global lock, averaging instead of per-leg actuation) — this is a repo-wide convention (see `.cursor/rules/ponytail.mdc`), not incidental. Keep using the tag when you deliberately cut a corner, and note the ceiling.
- Comments throughout reference "the plan", numbered "Phase N" steps, and lettered "Finding N" — these are call-outs of where the implementation deliberately diverged from (or fixed a gap in) a prior design document that isn't in this repo. Treat them as historical rationale, not as pointers to files that exist.
- The cost formula (`internal/score/score.go:composite`) is the **single source of truth** for combining RTT/loss/jitter/gap into a comparable number — passive (`Compute`) and active-probe (`FromProbeResult`) paths must both go through it, not duplicate the weighting logic.
- Known, accepted gaps (see README "Known limitations" / "Out of scope"): ECMP legs are averaged per neighbor, not actuated per-leg; `LoopbackForGateway` assumes 1:1 gateway-to-loopback mapping; the per-neighbor dampener couples sibling prefixes sharing a peer (forced by FRR's one-route-map-per-neighbor-per-direction model); `bpf/transit_loss.bpf.c` stores host byte order despite `bpf/common.h`'s comment saying so explicitly (trip-wired by `TestUint32ToIPStr_RoundTrip` in `cmd/daemon/main_test.go`, deliberately not "fixed" out from under the test); `bytes_acked` isn't wired up in BPF yet, so `score.Compute` falls back to a raw retransmit-count proxy.
