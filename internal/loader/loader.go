//go:build linux

// Package loader embeds and loads the BPF programs at daemon startup.
// It pins shared maps under /sys/fs/bpf/pathprofiler/ so internal/maps can
// open them, and attaches sockops / raw tracepoint / XDP programs to the kernel.
//
// The .bpf.o files must be copied into this directory before go build
// (the Makefile and CI workflow handle this). They are git-ignored.
package loader

import (
	"embed"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed *.bpf.o
var bpfFS embed.FS

const defaultPinDir = "/sys/fs/bpf/pathprofiler"

func cleanPinDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue // ponytail: never recurse; we own this flat pin dir
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return fmt.Errorf("remove stale pin %s: %w", e.Name(), err)
		}
	}
	return nil
}

// IfaceAttach describes one gateway-facing interface and its gateway IP.
type IfaceAttach struct {
	Iface     string // kernel interface name, e.g. wg0
	GatewayIP uint32 // host byte order, stored into iface_gateway_map[0]
}

// Loader holds loaded BPF collections and attached links.
// Call Close to detach programs and release resources.
type Loader struct {
	sockopsColl    *ebpf.Collection
	retransColl    *ebpf.Collection
	ingressColl    *ebpf.Collection
	links          []link.Link
	attachedIfaces map[string]bool // tracks XDP-attached interfaces
}

// Load reads the embedded .o files, creates and pins BPF maps, and attaches
// sockops + raw tracepoint programs. XDP is NOT attached here -- use AttachXDP
// separately so it can be retried when gateway interfaces become available.
func Load() (*Loader, error) {
	l := &Loader{attachedIfaces: make(map[string]bool)}

	if err := os.MkdirAll(defaultPinDir, 0o755); err != nil {
		return nil, fmt.Errorf("create pin dir %s: %w", defaultPinDir, err)
	}

	if err := cleanPinDir(defaultPinDir); err != nil {
		return nil, fmt.Errorf("clean pin dir %s: %w", defaultPinDir, err)
	}

	if err := l.loadEgress(); err != nil {
		return nil, fmt.Errorf("load egress BPF: %w", err)
	}

	if err := l.loadIngress(); err != nil {
		l.Close()
		return nil, fmt.Errorf("load ingress BPF: %w", err)
	}

	// Populate subnet_mask_map with /24 (matches bpf/common.h default).
	key := uint32(0)
	mask := uint32(0xffffff00)
	if err := l.sockopsColl.Maps["subnet_mask_map"].Update(&key, &mask, ebpf.UpdateAny); err != nil {
		log.Printf("loader: set subnet_mask_map (non-fatal): %v", err)
	}

	// --- Attach sockops and tracepoint ---

	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupSockOps,
		Program: l.sockopsColl.Programs["track_egress"],
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach sockops to /sys/fs/cgroup: %w", err)
	}
	l.links = append(l.links, sockopsLink)

	tpLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "tcp_retransmit_skb",
		Program: l.retransColl.Programs["on_tcp_retransmit"],
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach raw_tp tcp_retransmit_skb: %w", err)
	}
	l.links = append(l.links, tpLink)

	return l, nil
}

// AttachXDP attaches the ingress XDP program to the given interfaces.
// Idempotent: skips interfaces already attached. Called at startup if
// discoverGatewayIfaces succeeded, or retried in the loop once underlay
// data is available.
func (l *Loader) AttachXDP(ifaces []IfaceAttach) {
	for _, iface := range ifaces {
		if l.attachedIfaces[iface.Iface] {
			continue
		}
		ifIdx, err := net.InterfaceByName(iface.Iface)
		if err != nil {
			log.Printf("loader: XDP skip %s: %v", iface.Iface, err)
			continue
		}
		xdpLink, err := link.AttachXDP(link.XDPOptions{
			Program:   l.ingressColl.Programs["track_ingress"],
			Interface: ifIdx.Index,
		})
		if err != nil {
			log.Printf("loader: XDP attach %s (idx %d): %v (non-fatal)", iface.Iface, ifIdx.Index, err)
			continue
		}
		l.links = append(l.links, xdpLink)
		l.attachedIfaces[iface.Iface] = true
		log.Printf("loader: XDP attached to %s", iface.Iface)
	}
}

// loadEgress loads egress_sockops and egress_retrans as two collections that
// share egress_map and dst_to_nexthop via MapReplacements. Both collections
// and all maps are pinned.
func (l *Loader) loadEgress() error {
	sockopsSpec, err := loadSpec("egress_sockops.bpf.o")
	if err != nil {
		return err
	}
	retransSpec, err := loadSpec("egress_retrans.bpf.o")
	if err != nil {
		return err
	}

	// Load sockops first -- it owns egress_map and dst_to_nexthop.
	l.sockopsColl, err = ebpf.NewCollection(sockopsSpec)
	if err != nil {
		return fmt.Errorf("new sockops collection: %w", err)
	}

	// Load retrans with egress_map and dst_to_nexthop replaced by sockops
	// instances. Both programs look up the same kernel maps.
	l.retransColl, err = ebpf.NewCollectionWithOptions(retransSpec, ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"egress_map":     l.sockopsColl.Maps["egress_map"],
			"dst_to_nexthop": l.sockopsColl.Maps["dst_to_nexthop"],
		},
	})
	if err != nil {
		l.sockopsColl.Close()
		return fmt.Errorf("new retrans collection: %w", err)
	}

	// Pin all egress maps (sockops has the originals).
	for name, m := range l.sockopsColl.Maps {
		if err := m.Pin(filepath.Join(defaultPinDir, name)); err != nil {
			l.Close()
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}
	// Pin retrans-only maps. egress_map and dst_to_nexthop are already pinned
	// from the sockops collection above.
	for name, m := range l.retransColl.Maps {
		if name == "egress_map" || name == "dst_to_nexthop" {
			continue
		}
		if err := m.Pin(filepath.Join(defaultPinDir, name)); err != nil {
			l.Close()
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	return nil
}

// loadIngress loads ingress_xdp.bpf.o and pins its maps.
func (l *Loader) loadIngress() error {
	spec, err := loadSpec("ingress_xdp.bpf.o")
	if err != nil {
		return err
	}

	l.ingressColl, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new ingress collection: %w", err)
	}

	for name, m := range l.ingressColl.Maps {
		if err := m.Pin(filepath.Join(defaultPinDir, name)); err != nil {
			l.Close()
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}

	return nil
}

// Close detaches all programs and closes all collections.
func (l *Loader) Close() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil
	if l.ingressColl != nil {
		l.ingressColl.Close()
		l.ingressColl = nil
	}
	if l.retransColl != nil {
		l.retransColl.Close()
		l.retransColl = nil
	}
	if l.sockopsColl != nil {
		l.sockopsColl.Close()
		l.sockopsColl = nil
	}
}

func loadSpec(name string) (*ebpf.CollectionSpec, error) {
	f, err := bpfFS.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open embedded %s: %w", name, err)
	}
	defer f.Close()

	ra, ok := f.(io.ReaderAt)
	if !ok {
		return nil, fmt.Errorf("embedded %s: file does not implement io.ReaderAt", name)
	}
	return ebpf.LoadCollectionSpecFromReader(ra)
}
