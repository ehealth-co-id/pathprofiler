package bgp

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseRIB_Fixture(t *testing.T) {
	rib := parseFixture(t)

	// 192.168.5.0/24 has 2 paths.
	paths := rib["192.168.5.0/24"]
	if len(paths) != 2 {
		t.Fatalf("192.168.5.0/24: got %d paths, want 2", len(paths))
	}

	// Best path via 192.168.100.6, LocPrf 200.
	found := map[string]bool{}
	for _, p := range paths {
		if p.Prefix != "192.168.5.0/24" {
			t.Errorf("Prefix = %q, want 192.168.5.0/24", p.Prefix)
		}
		if p.Origin != "IGP" {
			t.Errorf("origin = %q, want IGP", p.Origin)
		}
		switch p.NextHop {
		case "192.168.100.6":
			if !p.Best {
				t.Errorf("192.168.100.6: expected Best=true")
			}
			if p.LocPrf != 200 {
				t.Errorf("192.168.100.6: LocPrf=%d, want 200", p.LocPrf)
			}
			if p.Neighbor != "192.168.100.6" {
				t.Errorf("192.168.100.6: Neighbor=%q, want 192.168.100.6", p.Neighbor)
			}
			found["best"] = true
		case "192.168.200.6":
			if p.Best {
				t.Errorf("192.168.200.6: expected Best=false")
			}
			if p.LocPrf != 100 {
				t.Errorf("192.168.200.6: LocPrf=%d, want 100", p.LocPrf)
			}
			if p.Neighbor != "192.168.200.6" {
				t.Errorf("192.168.200.6: Neighbor=%q, want 192.168.200.6", p.Neighbor)
			}
			found["alt"] = true
		default:
			t.Errorf("unexpected next-hop %q", p.NextHop)
		}
	}
	if !found["best"] || !found["alt"] {
		t.Errorf("did not find both paths for 192.168.5.0/24: %v", found)
	}

	// 192.168.0.0/24 has 1 path via 192.168.200.3.
	paths = rib["192.168.0.0/24"]
	if len(paths) != 1 {
		t.Fatalf("192.168.0.0/24: got %d paths, want 1", len(paths))
	}
	if paths[0].NextHop != "192.168.200.3" {
		t.Errorf("192.168.0.0/24 next-hop = %q, want 192.168.200.3", paths[0].NextHop)
	}
	if paths[0].Metric != 0 {
		t.Errorf("192.168.0.0/24 Metric = %d, want 0", paths[0].Metric)
	}
	if paths[0].LocPrf != 100 {
		t.Errorf("192.168.0.0/24 LocPrf = %d, want 100", paths[0].LocPrf)
	}
	if paths[0].Neighbor != "192.168.200.3" {
		t.Errorf("192.168.0.0/24 Neighbor = %q, want 192.168.200.3", paths[0].Neighbor)
	}

	// 192.168.250.250/32 has 1 path via 192.168.3.200, LocPrf 300.
	paths = rib["192.168.250.250/32"]
	if len(paths) != 1 {
		t.Fatalf("192.168.250.250/32: got %d paths, want 1", len(paths))
	}
	if paths[0].NextHop != "192.168.3.200" {
		t.Errorf("192.168.250.250/32 next-hop = %q, want 192.168.3.200", paths[0].NextHop)
	}
	if paths[0].LocPrf != 300 {
		t.Errorf("192.168.250.250/32 LocPrf = %d, want 300", paths[0].LocPrf)
	}

	// 192.168.3.0/24 (locally originated, next-hop 0.0.0.0) should be filtered out.
	if _, ok := rib["192.168.3.0/24"]; ok {
		t.Errorf("192.168.3.0/24 should have been filtered out (locally originated)")
	}
	// 192.168.4.0/24 (locally originated, next-hop 0.0.0.0) should be filtered out.
	if _, ok := rib["192.168.4.0/24"]; ok {
		t.Errorf("192.168.4.0/24 should have been filtered out (locally originated)")
	}
}

func TestParseRIB_TotalPrefixCount(t *testing.T) {
	rib := parseFixture(t)
	// After filtering 2 locally-originated (/24s with next-hop 0.0.0.0):
	// 192.168.0.0/24, 192.168.1.0/24, 192.168.5.0/24, 192.168.6.0/24, 192.168.250.250/32
	if len(rib) != 5 {
		t.Fatalf("expected 5 prefixes after filtering, got %d", len(rib))
	}
}

func TestParseRIB_AlsoHasSinglePathPrefixes(t *testing.T) {
	rib := parseFixture(t)
	for _, prefix := range []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.250.250/32"} {
		if len(rib[prefix]) != 1 {
			t.Errorf("%s: expected 1 path, got %d", prefix, len(rib[prefix]))
		}
	}
}

func TestParseRIB_MultiPathPrefixes(t *testing.T) {
	rib := parseFixture(t)
	for _, prefix := range []string{"192.168.5.0/24", "192.168.6.0/24"} {
		if len(rib[prefix]) != 2 {
			t.Errorf("%s: expected 2 paths, got %d", prefix, len(rib[prefix]))
		}
	}
}

func TestInScope_Includes24(t *testing.T) {
	rib := parseFixture(t)

	// scope 192.168.0.0/16 should include all /24 prefixes and the /32.
	scoped := InScope(rib, []string{"192.168.0.0/16"})

	for _, prefix := range []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.5.0/24", "192.168.6.0/24", "192.168.250.250/32"} {
		if _, ok := scoped[prefix]; !ok {
			t.Errorf("%s should be in scope 192.168.0.0/16", prefix)
		}
	}
}

func TestInScope_ExcludesBySubnet(t *testing.T) {
	rib := parseFixture(t)

	// scope 192.168.0.0/24 should include only 192.168.0.0/24.
	scoped := InScope(rib, []string{"192.168.0.0/24"})

	if len(scoped) != 1 {
		t.Fatalf("expected 1 prefix in scope, got %d", len(scoped))
	}
	if _, ok := scoped["192.168.0.0/24"]; !ok {
		t.Errorf("expected 192.168.0.0/24 to be in scope")
	}
}

func TestInScope_EmptyScope(t *testing.T) {
	rib := parseFixture(t)

	scoped := InScope(rib, nil)
	if !reflect.DeepEqual(scoped, rib) {
		t.Errorf("empty scope should return all prefixes unchanged")
	}

	scoped = InScope(rib, []string{})
	if !reflect.DeepEqual(scoped, rib) {
		t.Errorf("empty scope slice should return all prefixes unchanged")
	}
}

func TestPrefixForSubnet_LPM(t *testing.T) {
	rib := parseFixture(t)

	tests := []struct {
		name     string
		subnetIP string
		want     string
	}{
		{"exact /24 match", "192.168.5.0", "192.168.5.0/24"},
		{"IP inside /24", "192.168.5.42", "192.168.5.0/24"},
		{"IP inside different /24", "192.168.6.10", "192.168.6.0/24"},
		{"/32 match", "192.168.250.250", "192.168.250.250/32"},
		{"no match", "10.0.0.1", ""},
		{"invalid IP", "not-an-ip", ""},
		{"empty RIB", "", ""}, // handled separately
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := rib
			if tt.name == "empty RIB" {
				r = map[string][]Path{}
			}
			got := PrefixForSubnet(r, tt.subnetIP)
			if got != tt.want {
				t.Errorf("PrefixForSubnet(%s) = %q, want %q", tt.subnetIP, got, tt.want)
			}
		})
	}
}

func TestPrefixForSubnet_LongestPrefixWins(t *testing.T) {
	rib := map[string][]Path{
		"10.0.0.0/8":   {{Prefix: "10.0.0.0/8"}},
		"10.0.1.0/24":  {{Prefix: "10.0.1.0/24"}},
		"10.0.1.128/25": {{Prefix: "10.0.1.128/25"}},
	}
	got := PrefixForSubnet(rib, "10.0.1.200")
	if got != "10.0.1.128/25" {
		t.Errorf("PrefixForSubnet(10.0.1.200) = %q, want 10.0.1.128/25 (longest prefix)", got)
	}
}

func TestParseRIB_MalformedJSON(t *testing.T) {
	_, err := ParseRIB([]byte(`{"routes": "not-an-array"}`))
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}

	_, err = ParseRIB([]byte(`not-json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}

	_, err = ParseRIB([]byte(`{}`))
	if err == nil {
		t.Fatal("expected error for JSON missing 'routes' key, got nil")
	}
}

// parseFixture reads the sample_rib.json and parses it.
func parseFixture(t *testing.T) map[string][]Path {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "sample_rib.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	rib, err := ParseRIB(raw)
	if err != nil {
		t.Fatalf("ParseRIB: %v", err)
	}
	return rib
}
