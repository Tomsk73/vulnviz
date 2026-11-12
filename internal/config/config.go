// Package config loads the sources configuration that describes which
// distributions are tracked, where their advisory feeds live, and how fix
// timestamps should be interpreted for each.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Source describes one way of obtaining a distro's advisories.
type Source struct {
	// Type is "osv_zip" (a zip of OSV JSON files, e.g. the OSV.dev
	// per-ecosystem bundles) or "osv_index" (a JSON array of {id, modified}
	// with one JSON document per advisory behind RecordURL).
	Type string `yaml:"type"`
	URL  string `yaml:"url"`
	// RecordURL is a template with {id} for osv_index sources.
	RecordURL string `yaml:"record_url"`
}

// Rules controls how a distro's OSV records are turned into fix facts.
type Rules struct {
	// FixTimeBasis is "published" (default) or "component_event" (use the
	// latest fixed event timestamp recorded per affected component, as
	// Chainguard publishes).
	FixTimeBasis string `yaml:"fix_time_basis"`
	// TrustedKinds lists advisory ID prefixes whose published date is a real
	// remediation date. Empty means every kind is trusted.
	TrustedKinds []string `yaml:"trusted_kinds"`
	// MaxIDYearGap, when set, marks a record untrusted if its published year
	// exceeds the year embedded in its ID by more than this. 0 requires the
	// years to match (catches backfilled historical errata); unset disables.
	MaxIDYearGap *int `yaml:"max_id_year_gap,omitempty"`
	// EcosystemPrefix restricts affected entries to ecosystems with this
	// prefix (e.g. "Chainguard" to drop the duplicate Wolfi entries).
	EcosystemPrefix string `yaml:"ecosystem_prefix"`
}

// Distro is one tracked distribution.
type Distro struct {
	ID          string  `yaml:"id"`
	Name        string  `yaml:"name"`
	Homepage    string  `yaml:"homepage"`
	Notes       string  `yaml:"notes"`
	Bulk        *Source `yaml:"bulk"`
	Incremental *Source `yaml:"incremental"`
	Rules       Rules   `yaml:"rules"`
	Enabled     *bool   `yaml:"enabled"`
}

// CVESource describes where the CVE list comes from.
type CVESource struct {
	// ReleasesAPI is the GitHub releases API URL for CVEProject/cvelistV5.
	ReleasesAPI string `yaml:"releases_api"`
	// BulkURL optionally overrides the full "all CVEs" zip (or local path).
	BulkURL string `yaml:"bulk_url"`
}

// Config is the whole file.
type Config struct {
	CVE     CVESource `yaml:"cve"`
	Distros []Distro  `yaml:"distros"`
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]bool{}
	for i := range c.Distros {
		d := &c.Distros[i]
		if d.ID == "" {
			return nil, fmt.Errorf("distro %d has no id", i)
		}
		if seen[d.ID] {
			return nil, fmt.Errorf("duplicate distro id %q", d.ID)
		}
		seen[d.ID] = true
		if d.Name == "" {
			d.Name = d.ID
		}
		if d.Rules.FixTimeBasis == "" {
			d.Rules.FixTimeBasis = "published"
		}
		for _, s := range []*Source{d.Bulk, d.Incremental} {
			if s == nil {
				continue
			}
			switch s.Type {
			case "osv_zip":
				if s.URL == "" {
					return nil, fmt.Errorf("distro %s: osv_zip source needs url", d.ID)
				}
			case "osv_index":
				if s.URL == "" || s.RecordURL == "" {
					return nil, fmt.Errorf("distro %s: osv_index source needs url and record_url", d.ID)
				}
			default:
				return nil, fmt.Errorf("distro %s: unknown source type %q", d.ID, s.Type)
			}
		}
	}
	if c.CVE.ReleasesAPI == "" {
		c.CVE.ReleasesAPI = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
	}
	return &c, nil
}

// IsEnabled reports whether a distro should be ingested.
func (d Distro) IsEnabled() bool { return d.Enabled == nil || *d.Enabled }

// Find returns a distro by id.
func (c *Config) Find(id string) (*Distro, bool) {
	for i := range c.Distros {
		if c.Distros[i].ID == id {
			return &c.Distros[i], true
		}
	}
	return nil, false
}
