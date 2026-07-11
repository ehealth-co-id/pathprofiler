package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenParse(t *testing.T) {
	yamlContent := []byte(`
scope:
  prefixes:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
tiers:
  local: 300
  dedicated: 200
  default: 100
probe:
  port: 33434
  timeout_seconds: 2
  interval_seconds: 60
`)
	path := writeTempYAML(t, yamlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify scope.
	if len(cfg.Scope.Prefixes) != 2 {
		t.Fatalf("expected 2 scope prefixes, got %d", len(cfg.Scope.Prefixes))
	}
	if cfg.Scope.Prefixes[0] != "192.168.0.0/16" {
		t.Errorf("prefixes[0] = %q, want %q", cfg.Scope.Prefixes[0], "192.168.0.0/16")
	}
	if cfg.Scope.Prefixes[1] != "10.0.0.0/8" {
		t.Errorf("prefixes[1] = %q, want %q", cfg.Scope.Prefixes[1], "10.0.0.0/8")
	}

	// Verify tiers.
	if cfg.Tiers.Local != 300 {
		t.Errorf("Tiers.Local = %d, want 300", cfg.Tiers.Local)
	}
	if cfg.Tiers.Dedicated != 200 {
		t.Errorf("Tiers.Dedicated = %d, want 200", cfg.Tiers.Dedicated)
	}
	if cfg.Tiers.Default != 100 {
		t.Errorf("Tiers.Default = %d, want 100", cfg.Tiers.Default)
	}

	// Verify probe.
	if cfg.Probe.Port != 33434 {
		t.Errorf("Probe.Port = %d, want 33434", cfg.Probe.Port)
	}
	if cfg.Probe.TimeoutSeconds != 2 {
		t.Errorf("Probe.TimeoutSeconds = %d, want 2", cfg.Probe.TimeoutSeconds)
	}
	if cfg.Probe.IntervalSeconds != 60 {
		t.Errorf("Probe.IntervalSeconds = %d, want 60", cfg.Probe.IntervalSeconds)
	}
}

func TestDefaultsApplied(t *testing.T) {
	// Empty YAML should produce default values.
	yamlContent := []byte(`{}`)
	path := writeTempYAML(t, yamlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Tiers.Local != 300 {
		t.Errorf("default Tiers.Local = %d, want 300", cfg.Tiers.Local)
	}
	if cfg.Tiers.Dedicated != 200 {
		t.Errorf("default Tiers.Dedicated = %d, want 200", cfg.Tiers.Dedicated)
	}
	if cfg.Tiers.Default != 100 {
		t.Errorf("default Tiers.Default = %d, want 100", cfg.Tiers.Default)
	}
	if cfg.Probe.Port != 33434 {
		t.Errorf("default Probe.Port = %d, want 33434", cfg.Probe.Port)
	}
	if cfg.Probe.TimeoutSeconds != 2 {
		t.Errorf("default Probe.TimeoutSeconds = %d, want 2", cfg.Probe.TimeoutSeconds)
	}
	if cfg.Probe.IntervalSeconds != 60 {
		t.Errorf("default Probe.IntervalSeconds = %d, want 60", cfg.Probe.IntervalSeconds)
	}
	if cfg.Probe.EMAHalfLifeSeconds != 300 {
		t.Errorf("default Probe.EMAHalfLifeSeconds = %d, want 300", cfg.Probe.EMAHalfLifeSeconds)
	}
	if cfg.Probe.TimeoutRTTMultiplier != 8.0 {
		t.Errorf("default Probe.TimeoutRTTMultiplier = %f, want 8.0", cfg.Probe.TimeoutRTTMultiplier)
	}
	if cfg.Probe.MinTimeoutMs != 20 {
		t.Errorf("default Probe.MinTimeoutMs = %d, want 20", cfg.Probe.MinTimeoutMs)
	}
	// Scope should be empty (nil).
	if len(cfg.Scope.Prefixes) != 0 {
		t.Errorf("expected empty scope prefixes, got %v", cfg.Scope.Prefixes)
	}
}

func TestValidateProbeEMAHalfLifeNegative(t *testing.T) {
	yamlContent := []byte(`
probe:
  ema_half_life_seconds: -1
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for negative ema_half_life_seconds, got nil")
	}
}

func TestValidateProbeTimeoutRTTMultiplierNegative(t *testing.T) {
	yamlContent := []byte(`
probe:
  timeout_rtt_multiplier: -1
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for negative timeout_rtt_multiplier, got nil")
	}
}

func TestValidateProbeMinTimeoutMsNegative(t *testing.T) {
	yamlContent := []byte(`
probe:
  min_timeout_ms: -1
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for negative min_timeout_ms, got nil")
	}
}

func TestPartialOverrides(t *testing.T) {
	// Only override one field per section; rest should be defaulted.
	yamlContent := []byte(`
tiers:
  local: 500
probe:
  port: 12345
`)
	path := writeTempYAML(t, yamlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Tiers.Local != 500 {
		t.Errorf("Tiers.Local = %d, want 500", cfg.Tiers.Local)
	}
	if cfg.Tiers.Dedicated != 200 {
		t.Errorf("default Tiers.Dedicated = %d, want 200", cfg.Tiers.Dedicated)
	}
	if cfg.Tiers.Default != 100 {
		t.Errorf("default Tiers.Default = %d, want 100", cfg.Tiers.Default)
	}
	if cfg.Probe.Port != 12345 {
		t.Errorf("Probe.Port = %d, want 12345", cfg.Probe.Port)
	}
	if cfg.Probe.TimeoutSeconds != 2 {
		t.Errorf("default Probe.TimeoutSeconds = %d, want 2", cfg.Probe.TimeoutSeconds)
	}
	if cfg.Probe.IntervalSeconds != 60 {
		t.Errorf("default Probe.IntervalSeconds = %d, want 60", cfg.Probe.IntervalSeconds)
	}
}

func TestValidateDuplicateTierValues(t *testing.T) {
	yamlContent := []byte(`
tiers:
  local: 200
  dedicated: 200
  default: 100
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate tier values, got nil")
	}
}

func TestValidateTierNegative(t *testing.T) {
	yamlContent := []byte(`
tiers:
  local: -10
  dedicated: 200
  default: 100
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for negative tier value, got nil")
	}
}

func TestValidatePortOutOfRange(t *testing.T) {
	yamlContent := []byte(`
probe:
  port: 99999
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for port out of range, got nil")
	}
}

func TestValidateBadCIDR(t *testing.T) {
	yamlContent := []byte(`
scope:
  prefixes:
    - "not-a-cidr"
`)
	path := writeTempYAML(t, yamlContent)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for bad CIDR, got nil")
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestValidateEmptyScopeIsValid(t *testing.T) {
	// Empty scope (nil prefixes) is valid — means "all RIB prefixes".
	yamlContent := []byte(`{}`)
	path := writeTempYAML(t, yamlContent)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Scope.Prefixes) != 0 {
		t.Errorf("expected empty scope, got %v", cfg.Scope.Prefixes)
	}
}

// writeTempYAML writes contents to a temp file and returns the path.
func writeTempYAML(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pathprofiler.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}
	return path
}
