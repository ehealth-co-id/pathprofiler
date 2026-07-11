// Package maps reads the pinned eBPF maps populated by transit_loss.bpf.c
// and ingress_xdp.bpf.c.
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

// LpmKey mirrors struct lpm_key in bpf/common.h. Used for LPM trie lookups
// in dst_to_nexthop.
type LpmKey struct {
	PrefixLen uint32
	Daddr     uint32
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

type TransitStats struct {
	Segments     uint64
	Retransmits  uint64
	LastUpdateNs uint64
}

// Reader wraps the pinned maps. Pin paths are fixed by convention under
// /sys/fs/bpf/pathprofiler/ -- the loader pins all maps there so both BPF
// programs and this daemon reference the *same* map instances.
type Reader struct {
	ingress      *ebpf.Map
	transit      *ebpf.Map // may be nil if transit BPF not loaded
	dstToNexthop *ebpf.Map // may be nil if map is missing (older daemon)
	debugDropped *ebpf.Map // may be nil if transit BPF not loaded
}

const (
	pinDir          = "/sys/fs/bpf/pathprofiler"
	ingressPin      = pinDir + "/ingress_map"
	dstToNexthopPin = pinDir + "/dst_to_nexthop"
	transitPin      = pinDir + "/transit_loss_map"
	debugDroppedPin = pinDir + "/transit_debug_dropped"
)

func Open() (*Reader, error) {
	ingress, err := ebpf.LoadPinnedMap(ingressPin, nil)
	if err != nil {
		return nil, fmt.Errorf("open ingress_map: %w", err)
	}
	// dst_to_nexthop is non-fatal if missing (older daemon version or first
	// boot before populate sweep runs).
	dstToNexthop, err := ebpf.LoadPinnedMap(dstToNexthopPin, nil)
	if err != nil {
		log.Printf("maps: open dst_to_nexthop (non-fatal, will retry): %v", err)
	}
	// transit_loss_map is non-fatal — TC attachments may not be configured yet.
	transit, err := ebpf.LoadPinnedMap(transitPin, nil)
	if err != nil {
		log.Printf("maps: open transit_loss_map (non-fatal, TC programs will populate it when attached): %v", err)
	}
	// transit_debug_dropped is non-fatal — TC attachments may not be configured.
	dd, err := ebpf.LoadPinnedMap(debugDroppedPin, nil)
	if err != nil {
		log.Printf("maps: open transit_debug_dropped (non-fatal): %v", err)
	}
	return &Reader{ingress: ingress, transit: transit, dstToNexthop: dstToNexthop, debugDropped: dd}, nil
}

func (r *Reader) Close() {
	r.ingress.Close()
	if r.dstToNexthop != nil {
		r.dstToNexthop.Close()
	}
	if r.transit != nil {
		r.transit.Close()
	}
	if r.debugDropped != nil {
		r.debugDropped.Close()
	}
}

// DstToNexthop returns the dst_to_nexthop map, or nil if it's unavailable.
func (r *Reader) DstToNexthop() *ebpf.Map {
	return r.dstToNexthop
}

// UpdateDstToNexthop sets a single LPM trie entry: prefix -> next-hop.
// prefixLen is the prefix length (e.g. 24 for a /24); daddr is the network
// address in host byte order.
func (r *Reader) UpdateDstToNexthop(prefixLen, daddr, nextHop uint32) error {
	if r.dstToNexthop == nil {
		return fmt.Errorf("dst_to_nexthop map not available")
	}
	key := LpmKey{PrefixLen: prefixLen, Daddr: daddr}
	return r.dstToNexthop.Update(&key, &nextHop, ebpf.UpdateAny)
}

// AllIngress is keyed by gateway_ip only (PERCPU_HASH), so per-CPU values
// must be summed by the ebpf library's aggregation before we see them here.
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

// AllTransit iterates the PERCPU_HASH transit_loss_map and sums per-CPU values.
// Returns nil map when transit is not loaded (non-fatal).
func (r *Reader) AllTransit() (map[PathKey]TransitStats, error) {
	if r.transit == nil {
		return nil, nil
	}
	out := make(map[PathKey]TransitStats)
	var key PathKey
	var perCPUVals []TransitStats
	it := r.transit.Iterate()
	for it.Next(&key, &perCPUVals) {
		var agg TransitStats
		for _, v := range perCPUVals {
			agg.Segments += v.Segments
			agg.Retransmits += v.Retransmits
			if v.LastUpdateNs > agg.LastUpdateNs {
				agg.LastUpdateNs = v.LastUpdateNs
			}
		}
		out[key] = agg
	}
	return out, it.Err()
}

// DebugDropped returns the total dropped-packet count across all CPUs from
// transit_debug_dropped. Returns 0 if the map is not available.
func (r *Reader) DebugDropped() (uint64, error) {
	if r.debugDropped == nil {
		return 0, nil
	}
	var key uint32 = 0
	var perCPUVals []uint64
	if err := r.debugDropped.Lookup(&key, &perCPUVals); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range perCPUVals {
		sum += v
	}
	return sum, nil
}

func ipToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}