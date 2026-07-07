//go:build docker

package actuate

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestSetNeighborTiers_FRRSemantics runs SetNeighborTiers against a real FRR
// container to catch the semantic bugs the pure-Go tests structurally cannot:
// wrong match clause (route-source vs address), implicit final deny blackholing
// out-of-scope prefixes, and single-attachment enforcement.
//
// Run with: go test -tags docker ./internal/actuate/...
// Skips automatically if docker is unavailable.
func TestSetNeighborTiers_FRRSemantics(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Capture the script SetNeighborTiers would send.
	var captured string
	orig := runVtysh
	runVtysh = func(script string) ([]byte, error) {
		captured = script
		return nil, nil
	}

	u := NeighborTierUpdate{
		Neighbor: "192.168.100.6",
		Prefs: []PrefixPref{
			{Prefix: "192.168.5.0/24", LocalPref: 300},
			{Prefix: "192.168.6.0/24", LocalPref: 200},
		},
	}
	if err := SetNeighborTiers(u); err != nil {
		t.Fatalf("SetNeighborTiers: %v", err)
	}
	runVtysh = orig

	if captured == "" {
		t.Fatal("no script captured")
	}

	// Start frrouting/frr container.
	container := "pathprofiler-frr-test-" + t.Name()
	defer func() {
		exec.Command("docker", "rm", "-f", container).Run()
	}()

	// Use frrouting/frr:latest. Enable bgpd by touching /etc/frr/daemons
	// and restarting in the entrypoint, or by using the frrouting/frr image
	// which has bgpd enabled by default.
	start := exec.Command("docker", "run", "-d",
		"--name", container,
		"--privileged",
		"frrouting/frr:latest",
	)
	out, err := start.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run failed: %v\n%s", err, string(out))
	}

	// Wait for FRR to be ready.
	waitForFRR(t, container, 30*time.Second)

	// Pipe the captured script into the container's vtysh.
	applyScript(t, container, captured)

	// Verify: show running-config | grep route-map
	configOutput := dockerExec(t, container, "show running-config | grep route-map")

	// Route-map exists.
	if !strings.Contains(configOutput, "route-map PATHPROFILER-192-168-100-6 permit 10") {
		t.Errorf("route-map seq 10 not found in FRR config:\n%s", configOutput)
	}
	if !strings.Contains(configOutput, "route-map PATHPROFILER-192-168-100-6 permit 20") {
		t.Errorf("route-map seq 20 not found in FRR config:\n%s", configOutput)
	}
	// Catch-all present.
	if !strings.Contains(configOutput, "route-map PATHPROFILER-192-168-100-6 permit 65535") {
		t.Errorf("catch-all seq 65535 not found in FRR config:\n%s", configOutput)
	}

	// Verify neighbor has exactly one inbound route-map.
	neighborConfig := dockerExec(t, container, "show running-config | grep 'neighbor 192.168.100.6'")
	if n := strings.Count(neighborConfig, "route-map"); n != 1 {
		t.Errorf("expected exactly 1 route-map on neighbor, got %d:\n%s", n, neighborConfig)
	}

	// Verify route-map details via show route-map.
	rmDetail := dockerExec(t, container, "show route-map PATHPROFILER-192-168-100-6")
	if !strings.Contains(rmDetail, "match ip address prefix-list") {
		t.Errorf("match clause should use 'ip address prefix-list', got:\n%s", rmDetail)
	}
	if strings.Contains(rmDetail, "match ip route-source") {
		t.Errorf("match clause should NOT use 'route-source', got:\n%s", rmDetail)
	}

	// Verify prefix-lists exist.
	plOutput := dockerExec(t, container, "show running-config | grep prefix-list")
	if !strings.Contains(plOutput, "PATHPROFILER-SCOPE-192-168-5-0-24") {
		t.Errorf("prefix-list for 192.168.5.0/24 not found:\n%s", plOutput)
	}
	if !strings.Contains(plOutput, "PATHPROFILER-SCOPE-192-168-6-0-24") {
		t.Errorf("prefix-list for 192.168.6.0/24 not found:\n%s", plOutput)
	}
}

func waitForFRR(t *testing.T, container string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cmd := exec.Command("docker", "exec", container, "vtysh", "-c", "show version")
		if out, err := cmd.CombinedOutput(); err == nil && strings.Contains(string(out), "FRRouting") {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("FRR not ready within %v", timeout)
}

func applyScript(t *testing.T, container, script string) {
	t.Helper()
	// Write script to a temp file, then docker cp + exec vtysh.
	// Using docker exec with heredoc via sh -c.
	escaped := strings.ReplaceAll(script, "'", "'\\''")
	cmd := exec.Command("docker", "exec", container, "vtysh", "-c", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("applyScript failed: %v\nscript:\n%s\noutput:\n%s", err, script, string(out))
	}
	_ = escaped
}

func dockerExec(t *testing.T, container, command string) string {
	t.Helper()
	cmd := exec.Command("docker", "exec", container, "vtysh", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %q failed: %v\n%s", command, err, string(out))
	}
	return string(out)
}
