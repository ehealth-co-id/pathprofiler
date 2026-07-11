//go:build linux

// Package loader embeds and loads the BPF programs at daemon startup.
// It pins shared maps under /sys/fs/bpf/pathprofiler/ so internal/maps can
// open them, and attaches XDP / TC egress programs to the kernel.
package loader

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
	ingressColl      *ebpf.Collection
	transitColl      *ebpf.Collection
	links            []link.Link
	tcLinks          []tcLink // TC attachments (TCX or clsact), cleaned up separately
	attachedIfaces   map[string]bool  // tracks XDP-attached interfaces
	tcAttachedIfaces map[string]bool  // tracks TC-attached interfaces
}

// tcLink wraps a single TC attachment — either TCX (link.Link) or clsact fallback.
type tcLink struct {
	link   link.Link     // non-nil if TCX
	clsact *clsactFilter // non-nil if clsact fallback
	iface  string
}

// Load reads the embedded .o files, creates and pins BPF maps, and attaches
// the transit TC egress program (via AttachTC) and ingress XDP (via AttachXDP).
// AttachXDP is called separately so it can be retried when gateway interfaces
// become available.
func Load() (*Loader, error) {
	l := &Loader{attachedIfaces: make(map[string]bool), tcAttachedIfaces: make(map[string]bool)}

	if err := os.MkdirAll(defaultPinDir, 0o755); err != nil {
		return nil, fmt.Errorf("create pin dir %s: %w", defaultPinDir, err)
	}

	if err := cleanPinDir(defaultPinDir); err != nil {
		return nil, fmt.Errorf("clean pin dir %s: %w", defaultPinDir, err)
	}

	// Load transit first so it owns dst_to_nexthop and subnet_mask_map.
	if err := l.loadTransit(); err != nil {
		l.Close()
		return nil, fmt.Errorf("load transit BPF: %w", err)
	}

	if err := l.loadIngress(); err != nil {
		l.Close()
		return nil, fmt.Errorf("load ingress BPF: %w", err)
	}

	// Populate subnet_mask_map with /24 (matches bpf/common.h default).
	key := uint32(0)
	mask := uint32(0xffffff00)
	if err := l.transitColl.Maps["subnet_mask_map"].Update(&key, &mask, ebpf.UpdateAny); err != nil {
		log.Printf("loader: set subnet_mask_map (non-fatal): %v", err)
	}

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
	for _, tl := range l.tcLinks {
		if tl.link != nil {
			tl.link.Close()
		}
		if tl.clsact != nil {
			tl.clsact.Close()
		}
	}
	l.tcLinks = nil
	if l.transitColl != nil {
		l.transitColl.Close()
		l.transitColl = nil
	}
	if l.ingressColl != nil {
		l.ingressColl.Close()
		l.ingressColl = nil
	}
}

// loadTransit loads transit_loss.bpf.o and pins its maps.
// Owns dst_to_nexthop and subnet_mask_map (declared in the BPF C source).
func (l *Loader) loadTransit() error {
	spec, err := loadSpec("transit_loss.bpf.o")
	if err != nil {
		return err
	}

	l.transitColl, err = ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new transit collection: %w", err)
	}

	// Pin shared maps so the daemon can populate dst_to_nexthop from the RIB.
	for _, name := range []string{"dst_to_nexthop", "subnet_mask_map"} {
		m, ok := l.transitColl.Maps[name]
		if !ok {
			l.transitColl.Close()
			return fmt.Errorf("transit collection missing map %s", name)
		}
		if err := m.Pin(filepath.Join(defaultPinDir, name)); err != nil {
			l.transitColl.Close()
			return fmt.Errorf("pin %s: %w", name, err)
		}
	}

	// Pin transit_loss_map for userspace access. Bloom maps are internal-only.
	if m, ok := l.transitColl.Maps["transit_loss_map"]; ok {
		if err := m.Pin(filepath.Join(defaultPinDir, "transit_loss_map")); err != nil {
			l.transitColl.Close()
			return fmt.Errorf("pin transit_loss_map: %w", err)
		}
	}
	// Pin transit_debug_dropped for tripwire diagnostics.
	if m, ok := l.transitColl.Maps["transit_debug_dropped"]; ok {
		if err := m.Pin(filepath.Join(defaultPinDir, "transit_debug_dropped")); err != nil {
			l.transitColl.Close()
			return fmt.Errorf("pin transit_debug_dropped: %w", err)
		}
	}
	return nil
}

// AttachTC attaches the transit_egress TC program to the given interfaces
// via clsact (netlink BpfFilter). clsact supports multiple filters per
// interface so both pathprofiler and ebpf-packet-loss-exporter can coexist.
// Idempotent: skips interfaces already attached.
func (l *Loader) AttachTC(ifaces []string) error {
	for _, iface := range ifaces {
		if l.tcAttachedIfaces[iface] {
			continue
		}
		a, err := attachClsActEgress(iface, l.transitColl.Programs["transit_egress"])
		if err != nil {
			return fmt.Errorf("attach TC egress on %s: %w", iface, err)
		}
		l.tcLinks = append(l.tcLinks, a)
		l.tcAttachedIfaces[iface] = true
		log.Printf("loader: TC egress attached to %s", iface)
	}
	return nil
}

// --- TCX / clsact attachment helpers ---

type clsactFilter struct {
	ifaceName string
	ifaceIdx  int
	handle    uint32
	parent    uint32
}

func (c *clsactFilter) Close() error {
	if c == nil || c.handle == 0 {
		return nil
	}
	link, err := netlink.LinkByIndex(c.ifaceIdx)
	if err != nil {
		return fmt.Errorf("lookup interface index %d: %w", c.ifaceIdx, err)
	}
	filters, err := netlink.FilterList(link, c.parent)
	if err != nil {
		return fmt.Errorf("list filters: %w", err)
	}
	for _, filter := range filters {
		if filter.Attrs().Handle == c.handle {
			if err := netlink.FilterDel(filter); err != nil {
				return fmt.Errorf("delete filter: %w", err)
			}
			c.handle = 0
			return nil
		}
	}
	return fmt.Errorf("filter handle %#x not found on %q", c.handle, c.ifaceName)
}

const filterHandleBase = 0x1610

func attachClsActEgress(ifaceName string, prog *ebpf.Program) (tcLink, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return tcLink{}, fmt.Errorf("interface %q: %w", ifaceName, err)
	}
	nl, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return tcLink{}, fmt.Errorf("netlink lookup: %w", err)
	}
	if err := ensureClsAct(nl); err != nil {
		return tcLink{}, err
	}
	parent := uint32(netlink.HANDLE_MIN_EGRESS)
	handle, err := nextFilterHandle(nl, parent)
	if err != nil {
		return tcLink{}, err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    parent,
			Handle:    handle,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "transit_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return tcLink{}, fmt.Errorf("add bpf filter: %w", err)
	}
	return tcLink{
		clsact: &clsactFilter{
			ifaceName: ifaceName,
			ifaceIdx:  iface.Index,
			handle:    handle,
			parent:    parent,
		},
		iface: ifaceName,
	}, nil
}

func ensureClsAct(link netlink.Link) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return verifyClsAct(link)
		}
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return nil
}

func verifyClsAct(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		attrs := q.Attrs()
		if attrs.Parent == netlink.HANDLE_CLSACT {
			if q.Type() == "clsact" {
				return nil
			}
			return fmt.Errorf("interface already has non-clsact qdisc on clsact parent: %s", q.Type())
		}
	}
	return nil
}

func nextFilterHandle(link netlink.Link, parent uint32) (uint32, error) {
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return 0, err
	}
	used := make(map[uint32]struct{}, len(filters))
	for _, f := range filters {
		used[f.Attrs().Handle] = struct{}{}
	}
	for handle := uint32(filterHandleBase); handle < 0xffff; handle++ {
		if _, ok := used[handle]; !ok {
			return handle, nil
		}
	}
	return 0, errors.New("no free tc filter handles")
}

// DetachStaleTC removes any TC egress BPF programs attached to the given
// interfaces that were left by prior daemon runs. Must be called once
// at startup before AttachTC. Best-effort: failures are logged, not fatal.
func DetachStaleTC(ifaceNames []string) {
	for _, ifaceName := range ifaceNames {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Printf("loader: DetachStaleTC skip %s: %v", ifaceName, err)
			continue
		}
		detachStaleTCXLinks(ifaceName)
		if err := detachClsActFilters(*iface); err != nil {
			log.Printf("loader: DetachStaleTC clsact %s: %v", ifaceName, err)
		}
	}
}

// detachStaleTCXLinks enumerates all BPF links and detaches tcx_egress
// links whose program name matches "transit_egress" (our own program only —
// other tools' TCX links must be left alone since clsact-only coexistence
// depends on not touching them).
func detachStaleTCXLinks(ifaceName string) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return
	}
	it := new(link.Iterator)
	defer it.Close()
	for it.Next() {
		id := it.ID
		l := it.Take()
		if l == nil {
			continue
		}
		info, err := l.Info()
		if err != nil {
			l.Close()
			continue
		}
		tcx := info.TCX()
		if tcx == nil || tcx.Ifindex != uint32(iface.Index) {
			l.Close()
			continue
		}
		if uint32(tcx.AttachType) != uint32(ebpf.AttachTCXEgress) {
			l.Close()
			continue
		}
		prog, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			l.Close()
			continue
		}
		pi, err := prog.Info()
		prog.Close()
		if err != nil {
			l.Close()
			continue
		}
		name := pi.Name
		if strings.HasPrefix(name, "transit_egress") {
			if err := l.Close(); err != nil {
				log.Printf("loader: DetachStaleTC detach tcx link %d (%s) on %s: %v", id, name, ifaceName, err)
			} else {
				log.Printf("loader: DetachStaleTC removed stale tcx link %d (%s) on %s", id, name, ifaceName)
			}
		} else {
			l.Close()
		}
	}
}

// detachClsActFilters removes any BPF filters on the clsact egress qdisc
// whose name matches "transit_egress" — our own program only. clsact
// supports multiple filters per interface specifically so other tools
// (e.g. ebpf-packet-loss-exporter's "path_egress") can coexist; deleting
// their filters here would defeat that.
func detachClsActFilters(iface net.Interface) error {
	nl, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("netlink lookup: %w", err)
	}
	parent := uint32(netlink.HANDLE_MIN_EGRESS)
	filters, err := netlink.FilterList(nl, parent)
	if err != nil {
		return err
	}
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		name := bpf.Name
		// ponytail: name is truncated to 15 chars by the kernel, so we
		// check prefix instead of exact match.
		if strings.HasPrefix(name, "transit_egress") {
			if err := netlink.FilterDel(f); err != nil {
				log.Printf("loader: DetachStaleTC: delete filter %s on %s: %v", name, iface.Name, err)
			} else {
				log.Printf("loader: DetachStaleTC: removed stale filter %s on %s", name, iface.Name)
			}
		}
	}
	return nil
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
