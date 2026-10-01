//go:build linux

package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestCleanPinDir_RemovesFilesLeavesDirs(t *testing.T) {
	dir := t.TempDir()

	// Simulate pinned objects as plain files.
	if err := os.WriteFile(filepath.Join(dir, "transit_loss_map"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Simulate unexpected subdir; we should not recurse.
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}

	if err := cleanPinDir(dir); err != nil {
		t.Fatalf("cleanPinDir: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "transit_loss_map")); err == nil {
		t.Fatalf("expected file to be removed")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat file: %v", err)
	}

	if fi, err := os.Stat(filepath.Join(dir, "subdir")); err != nil {
		t.Fatalf("stat subdir: %v", err)
	} else if !fi.IsDir() {
		t.Fatalf("expected subdir to remain a directory")
	}
}

// TestIsOurs_OnlyMatchesOurProgram is the coexistence guard: the clsact qdisc is
// shared with ebpf-packet-loss-exporter's path_egress filter, so we must
// recognize exactly our own transit_egress filter and nothing else.
func TestIsOurs_OnlyMatchesOurProgram(t *testing.T) {
	cases := []struct {
		name string
		f    netlink.Filter
		want bool
	}{
		{"ours", &netlink.BpfFilter{Name: "transit_egress"}, true},
		{"ours (kernel truncates names to 15 chars)", &netlink.BpfFilter{Name: "transit_egress"}, true},
		{"other tool", &netlink.BpfFilter{Name: "path_egress"}, false},
		{"unrelated bpf filter", &netlink.BpfFilter{Name: "foo"}, false},
		{"non-bpf filter", &netlink.GenericFilter{}, false},
		{"nil bpf filter", (*netlink.BpfFilter)(nil), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isOurs(c.f); got != c.want {
				t.Errorf("isOurs(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// TestDropStale_ForgetsOnlyTheRecreatedInterface pins the record-pruning rule
// behind the v0.0.6 fix: when an interface is recreated its stale handles are
// forgotten, other interfaces' records survive, and nil handles (already gone
// from the kernel) must not panic.
func TestDropStale_ForgetsOnlyTheRecreatedInterface(t *testing.T) {
	l := &Loader{
		links:   []xdpAttach{{iface: "wg0", ifindex: 7}, {iface: "eth3", ifindex: 5}},
		tcLinks: []tcLink{{iface: "wg0"}, {iface: "eth3"}},
	}
	l.dropStaleXDP("wg0")
	l.dropStaleTC("wg0")

	if len(l.links) != 1 || l.links[0].iface != "eth3" {
		t.Errorf("XDP records after dropping wg0 = %+v, want only eth3", l.links)
	}
	if len(l.tcLinks) != 1 || l.tcLinks[0].iface != "eth3" {
		t.Errorf("TC records after dropping wg0 = %+v, want only eth3", l.tcLinks)
	}
}
