package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Scope defines the set of RIB prefixes to actuate on.
type Scope struct {
	Prefixes []string `yaml:"prefixes"` // CIDRs; empty = all RIB prefixes
}

// Tiers defines local-preference values for ranked paths.
type Tiers struct {
	Local     int `yaml:"local"`     // best path
	Dedicated int `yaml:"dedicated"` // 2nd-best path
	Default   int `yaml:"default"`   // all other paths (FRR default)
}

// Probe defines cold-path probing parameters.
type Probe struct {
	Port            int     `yaml:"port"`
	TimeoutSeconds  int     `yaml:"timeout_seconds"`
	IntervalSeconds int     `yaml:"interval_seconds"`
	MinCount        int     `yaml:"min_count"` // initial burst; adaptive probe starts here
	MaxCount        int     `yaml:"max_count"` // SPRT ceiling; wall-time cap = max_count * timeout
	Delta           float64 `yaml:"delta"`     // indifference band in loss-rate units
	Alpha           float64 `yaml:"alpha"`     // SPRT Type-I error (false-better / false-worse rate)
	Beta            float64 `yaml:"beta"`      // SPRT Type-II error (miss a real delta-difference)

	// EMAHalfLifeSeconds controls how fast accumulated SPRT evidence (across
	// ticks) decays -- mirrors --transit-ema-half-life's role for transit loss.
	EMAHalfLifeSeconds int `yaml:"ema_half_life_seconds"`
	// TimeoutRTTMultiplier and MinTimeoutMs size each tick's per-probe
	// timeout adaptively from the leg's RTT baseline (multiplier * RTT,
	// floored at MinTimeoutMs) instead of always waiting the full
	// TimeoutSeconds on a loss once a baseline is known.
	TimeoutRTTMultiplier float64 `yaml:"timeout_rtt_multiplier"`
	MinTimeoutMs         int     `yaml:"min_timeout_ms"`
}

// Config is the top-level pathprofiler configuration.
type Config struct {
	Scope Scope `yaml:"scope"`
	Tiers Tiers `yaml:"tiers"`
	Probe Probe `yaml:"probe"`
}

// defaultConfig holds the zero-value defaults.
func defaultConfig() *Config {
	return &Config{
		Tiers: Tiers{
			Local:     300,
			Dedicated: 200,
			Default:   100,
		},
		Probe: Probe{
			Port:                 33434,
			TimeoutSeconds:       2,
			IntervalSeconds:      60,
			MinCount:             5,
			MaxCount:             30,
			Delta:                0.02,
			Alpha:                0.05,
			Beta:                 0.05,
			EMAHalfLifeSeconds:   300,
			TimeoutRTTMultiplier: 8.0,
			MinTimeoutMs:         20,
		},
	}
}

// Load opens a YAML file at path, decodes it into a Config, applies defaults
// for zero-valued fields, and validates the result.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()

	c := defaultConfig()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}

	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}
	return c, nil
}

// applyDefaults fills zero-valued fields with their defaults.
func (c *Config) applyDefaults() {
	if c.Tiers.Local == 0 {
		c.Tiers.Local = 300
	}
	if c.Tiers.Dedicated == 0 {
		c.Tiers.Dedicated = 200
	}
	if c.Tiers.Default == 0 {
		c.Tiers.Default = 100
	}
	if c.Probe.Port == 0 {
		c.Probe.Port = 33434
	}
	if c.Probe.TimeoutSeconds == 0 {
		c.Probe.TimeoutSeconds = 2
	}
	if c.Probe.IntervalSeconds == 0 {
		c.Probe.IntervalSeconds = 60
	}
	if c.Probe.MinCount == 0 {
		c.Probe.MinCount = 5
	}
	if c.Probe.MaxCount == 0 {
		c.Probe.MaxCount = 30
	}
	if c.Probe.Delta == 0 {
		c.Probe.Delta = 0.02
	}
	if c.Probe.Alpha == 0 {
		c.Probe.Alpha = 0.05
	}
	if c.Probe.Beta == 0 {
		c.Probe.Beta = 0.05
	}
	if c.Probe.EMAHalfLifeSeconds == 0 {
		c.Probe.EMAHalfLifeSeconds = 300
	}
	if c.Probe.TimeoutRTTMultiplier == 0 {
		c.Probe.TimeoutRTTMultiplier = 8.0
	}
	if c.Probe.MinTimeoutMs == 0 {
		c.Probe.MinTimeoutMs = 20
	}
}

// Validate checks that all fields are sensible.
func (c *Config) Validate() error {
	// Tier values must be distinct and positive.
	tiers := []int{c.Tiers.Local, c.Tiers.Dedicated, c.Tiers.Default}
	seen := make(map[int]bool)
	for _, t := range tiers {
		if t <= 0 {
			return fmt.Errorf("tier value must be > 0, got %d", t)
		}
		if seen[t] {
			return fmt.Errorf("tier values must be distinct: duplicate %d", t)
		}
		seen[t] = true
	}

	// Port must be within valid range.
	if c.Probe.Port < 1 || c.Probe.Port > 65535 {
		return fmt.Errorf("probe port %d out of range [1, 65535]", c.Probe.Port)
	}

	// Timeout and interval must be positive.
	if c.Probe.TimeoutSeconds <= 0 {
		return fmt.Errorf("probe timeout_seconds must be > 0, got %d", c.Probe.TimeoutSeconds)
	}
	if c.Probe.IntervalSeconds <= 0 {
		return fmt.Errorf("probe interval_seconds must be > 0, got %d", c.Probe.IntervalSeconds)
	}

	if c.Probe.MinCount < 1 {
		return fmt.Errorf("probe min_count must be >= 1, got %d", c.Probe.MinCount)
	}
	if c.Probe.MaxCount < c.Probe.MinCount {
		return fmt.Errorf("probe max_count (%d) must be >= min_count (%d)", c.Probe.MaxCount, c.Probe.MinCount)
	}
	if c.Probe.Delta <= 0 || c.Probe.Delta >= 1 {
		return fmt.Errorf("probe delta must be in (0, 1), got %f", c.Probe.Delta)
	}
	if c.Probe.Alpha <= 0 || c.Probe.Alpha >= 0.5 {
		return fmt.Errorf("probe alpha must be in (0, 0.5), got %f", c.Probe.Alpha)
	}
	if c.Probe.Beta <= 0 || c.Probe.Beta >= 0.5 {
		return fmt.Errorf("probe beta must be in (0, 0.5), got %f", c.Probe.Beta)
	}
	if c.Probe.EMAHalfLifeSeconds <= 0 {
		return fmt.Errorf("probe ema_half_life_seconds must be > 0, got %d", c.Probe.EMAHalfLifeSeconds)
	}
	if c.Probe.TimeoutRTTMultiplier <= 0 {
		return fmt.Errorf("probe timeout_rtt_multiplier must be > 0, got %f", c.Probe.TimeoutRTTMultiplier)
	}
	if c.Probe.MinTimeoutMs < 1 {
		return fmt.Errorf("probe min_timeout_ms must be >= 1, got %d", c.Probe.MinTimeoutMs)
	}

	// Each prefix must be a valid CIDR.
	for i, p := range c.Scope.Prefixes {
		if _, _, err := net.ParseCIDR(p); err != nil {
			return fmt.Errorf("scope.prefixes[%d]: invalid CIDR %q: %w", i, p, err)
		}
	}

	return nil
}
