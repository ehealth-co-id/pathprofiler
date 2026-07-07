// Package maps reads the pinned eBPF maps populated by egress_sockops.bpf.c,
// egress_retrans.bpf.c, and ingress_xdp.bpf.c.
//
// UNVERIFIED IN THIS ENVIRONMENT: no Go toolchain, no clang/libbpf, no root,
// no real NICs were available in the sandbox this was written in. This
// compiles against cilium/ebpf's API surface from memory/docs, not against
// a built module -- treat as a strong draft, not a tested artifact. Build
// with `go build` after `go mod tidy` on a real Linux host with kernel
// headers before trusting it.
package maps

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
)

// PathKey mirrors struct path_key in bpf/common.h. Field order and sizes
// must match exactly (no padding surprises) or the map will silently
// misparse -- this is the single most common cause of "reads garbage"
// bugs in this kind of daemon, so pin it down explicitly here rather than
// relying on struct-tag magic.
type PathKey struct {
	NextHopIP uint32
	DstSubnet uint32
}

type EgressStats struct {
	SrttUsSum    uint64
	SrttSamples  uint64
	Retransmits  uint64
	BytesAcked   uint64
	LastUpdateNs uint64
}

type IngressStats struct {
	IatSumNs      uint64
	IatSamples    uint64
	IatSqSumNs    uint64
	LastArrivalNs uint64
	Packets       uint64
	LastSeqSeen   uint64
	SeqGaps       uint64
}

// Reader wraps the pinned maps. Pin paths are fixed by convention under
// /sys/fs/bpf/pathprofiler/ -- the loader pins all maps there so both BPF
// programs and this daemon reference the *same* map instances.
type Reader struct {
	egress       *ebpf.Map
	ingress      *ebpf.Map
	dstToNexthop *ebpf.Map // may be nil if map is missing (older daemon)
}

const (
	pinDir          = "/sys/fs/bpf/pathprofiler"
	egressPin       = pinDir + "/egress_map"
	ingressPin      = pinDir + "/ingress_map"
	dstToNexthopPin = pinDir + "/dst_to_nexthop"
)

func Open() (*Reader, error) {
	egress, err := ebpf.LoadPinnedMap(egressPin, nil)
	if err != nil {
		return nil, fmt.Errorf("open egress_map (is it pinned? did the BPF programs load?): %w", err)
	}
	ingress, err := ebpf.LoadPinnedMap(ingressPin, nil)
	if err != nil {
		egress.Close()
		return nil, fmt.Errorf("open ingress_map: %w", err)
	}
	// dst_to_nexthop is non-fatal if missing (older daemon version or first
	// boot before populate sweep runs). Egress sockops still works, just
	// with empty next-hops until the sweep populates the map.
	dstToNexthop, err := ebpf.LoadPinnedMap(dstToNexthopPin, nil)
	if err != nil {
		log.Printf("maps: open dst_to_nexthop (non-fatal, will retry): %v", err)
	}
	return &Reader{egress: egress, ingress: ingress, dstToNexthop: dstToNexthop}, nil
}

func (r *Reader) Close() {
	r.egress.Close()
	r.ingress.Close()
	if r.dstToNexthop != nil {
		r.dstToNexthop.Close()
	}
}

// DstToNexthop returns the dst_to_nexthop map, or nil if it's unavailable.
func (r *Reader) DstToNexthop() *ebpf.Map {
	return r.dstToNexthop
}

// UpdateDstToNexthop sets a single destination -> next-hop mapping.
func (r *Reader) UpdateDstToNexthop(dst, nh uint32) error {
	if r.dstToNexthop == nil {
		return fmt.Errorf("dst_to_nexthop map not available")
	}
	return r.dstToNexthop.Update(&dst, &nh, ebpf.UpdateAny)
}

// AllEgress iterates the LRU hash and returns a snapshot. LRU maps can evict
// under memory pressure -- a path with no recent traffic legitimately
// disappearing from this map is expected behavior, not a bug; callers must
// not treat "missing key" as "path is dead", only as "no recent data".
func (r *Reader) AllEgress() (map[PathKey]EgressStats, error) {
	out := make(map[PathKey]EgressStats)
	var key PathKey
	var val EgressStats
	it := r.egress.Iterate()
	for it.Next(&key, &val) {
		out[key] = val
	}
	return out, it.Err()
}

// AllIngress is keyed by gateway_ip only (PERCPU_HASH), so per-CPU values
// must be summed by the ebpf library's aggregation before we see them here
// -- confirm cilium/ebpf's PerCPU map iteration semantics match this
// assumption (it returns a slice per CPU; summing is our responsibility).
func (r *Reader) AllIngress() (map[uint32]IngressStats, error) {
	out := make(map[uint32]IngressStats)
	var key uint32
	var perCPUVals []IngressStats
	it := r.ingress.Iterate()
	for it.Next(&key, &perCPUVals) {
		var agg IngressStats
		for _, v := range perCPUVals {
			agg.IatSumNs += v.IatSumNs
			agg.IatSamples += v.IatSamples
			agg.IatSqSumNs += v.IatSqSumNs
			agg.Packets += v.Packets
			agg.SeqGaps += v.SeqGaps
			if v.LastArrivalNs > agg.LastArrivalNs {
				agg.LastArrivalNs = v.LastArrivalNs
			}
		}
		out[key] = agg
	}
	return out, it.Err()
}

func ipToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}
