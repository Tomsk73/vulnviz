// Package osv parses OSV (Open Source Vulnerability) JSON documents and applies
// per-distribution rules to derive fix facts from them.
package osv

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"vulnviz/internal/config"
	"vulnviz/internal/cvss"
)

// Doc mirrors the subset of the OSV schema the app needs.
type Doc struct {
	ID        string     `json:"id"`
	Published string     `json:"published"`
	Modified  string     `json:"modified"`
	Withdrawn string     `json:"withdrawn"`
	Summary   string     `json:"summary"`
	Aliases   []string   `json:"aliases"`
	Upstream  []string   `json:"upstream"`
	Related   []string   `json:"related"`
	Severity  []Severity `json:"severity"`
	Affected  []Affected `json:"affected"`
	DBSpec    json.RawMessage `json:"database_specific"`
}

// Severity is one entry of the OSV severity array.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected is one affected package block.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	EcoSpec json.RawMessage `json:"ecosystem_specific"`
	DBSpec  json.RawMessage `json:"database_specific"`
}

// Package is a normalised affected-package row.
type Package struct {
	Ecosystem  string
	Name       string
	Introduced string
	Fixed      string
	FixTime    *time.Time // component-level fix event when the distro records one
}

// Advisory is the normalised form stored in the database.
type Advisory struct {
	Distro         string
	ID             string
	Kind           string
	Published      *time.Time
	Modified       *time.Time
	Withdrawn      *time.Time
	Summary        string
	CVSSVector     string
	CVSSScore      float64 // -1 when unknown
	Severity       string  // distro-stated severity bucket, "" if none
	HasFix         bool
	FixTime        *time.Time
	FixTimeTrusted bool
	CVEs           []string
	Packages       []Package
}

var (
	cveRe    = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	kindRe   = regexp.MustCompile(`^([A-Za-z]+)(-CVE)?-`)
	idYearRe = regexp.MustCompile(`(?:^|[-:])((?:19|20)\d{2})(?:[-:]|$)`)
)

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		t = t.UTC()
		return &t
	}
	return nil
}

// Kind returns the advisory family encoded in an OSV ID, e.g. "RHSA",
// "DEBIAN-CVE", "USN", "CGA".
func Kind(id string) string {
	m := kindRe.FindStringSubmatch(id)
	if m == nil {
		return "OTHER"
	}
	return strings.ToUpper(m[1] + m[2])
}

// IDYear extracts a four-digit year embedded in an advisory ID, or 0.
func IDYear(id string) int {
	m := idYearRe.FindStringSubmatch(id)
	if m == nil {
		return 0
	}
	y := 0
	for _, c := range m[1] {
		y = y*10 + int(c-'0')
	}
	return y
}

type componentSpec struct {
	Components []struct {
		Status    string `json:"latest_event_status"`
		Timestamp string `json:"latest_event_timestamp"`
	} `json:"components"`
	Urgency        string `json:"urgency"`
	UbuntuPriority string `json:"ubuntu_priority"`
}

// Parse decodes one OSV document and applies the distro's rules.
func Parse(data []byte, d config.Distro) (*Advisory, error) {
	var doc Doc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	a := &Advisory{
		Distro:    d.ID,
		ID:        doc.ID,
		Kind:      Kind(doc.ID),
		Published: parseTime(doc.Published),
		Modified:  parseTime(doc.Modified),
		Withdrawn: parseTime(doc.Withdrawn),
		Summary:   doc.Summary,
		CVSSScore: -1,
	}
	a.Summary = cvss.Clip(a.Summary, 400)

	// CVE links: the ID itself, aliases, upstream, related, and prefixed
	// tracker IDs such as DEBIAN-CVE-2024-1 or UBUNTU-CVE-2024-1.
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.ToUpper(strings.TrimSpace(s))
		if i := strings.Index(s, "CVE-"); i > 0 {
			s = s[i:]
		}
		if cveRe.MatchString(s) && !seen[s] {
			seen[s] = true
			a.CVEs = append(a.CVEs, s)
		}
	}
	add(doc.ID)
	for _, l := range [][]string{doc.Aliases, doc.Upstream, doc.Related} {
		for _, s := range l {
			add(s)
		}
	}
	sort.Strings(a.CVEs)

	// Distro-stated severity.
	for _, s := range doc.Severity {
		switch strings.ToUpper(s.Type) {
		case "CVSS_V3", "CVSS_V2", "CVSS_V4":
			if a.CVSSVector == "" {
				a.CVSSVector = s.Score
				if _, sc, ok := cvss.Score(s.Score); ok {
					a.CVSSScore = sc
					a.Severity = cvss.Bucket(sc)
				}
			}
		default: // "Ubuntu", "Debian" style words
			if a.Severity == "" {
				a.Severity = cvss.NormalizeSeverity(s.Score)
			}
		}
	}

	var compFix *time.Time
	for _, af := range doc.Affected {
		eco := af.Package.Ecosystem
		if d.Rules.EcosystemPrefix != "" && !strings.HasPrefix(eco, d.Rules.EcosystemPrefix) {
			continue
		}
		var spec componentSpec
		if len(af.EcoSpec) > 0 {
			_ = json.Unmarshal(af.EcoSpec, &spec)
		}
		if a.Severity == "" {
			if s := cvss.NormalizeSeverity(spec.Urgency); s != "" {
				a.Severity = s
			} else if s := cvss.NormalizeSeverity(spec.UbuntuPriority); s != "" {
				a.Severity = s
			}
		}
		var pkgFix *time.Time
		if d.Rules.FixTimeBasis == "component_event" {
			for _, c := range spec.Components {
				if c.Status == "fixed" {
					if t := parseTime(c.Timestamp); t != nil && (pkgFix == nil || t.Before(*pkgFix)) {
						pkgFix = t
					}
				}
			}
			if pkgFix != nil && (compFix == nil || pkgFix.Before(*compFix)) {
				compFix = pkgFix
			}
		}
		if len(af.Ranges) == 0 {
			a.Packages = append(a.Packages, Package{Ecosystem: eco, Name: af.Package.Name})
			continue
		}
		for _, r := range af.Ranges {
			p := Package{Ecosystem: eco, Name: af.Package.Name}
			for _, ev := range r.Events {
				if v, ok := ev["introduced"]; ok && p.Introduced == "" {
					p.Introduced = v
				}
				if v, ok := ev["fixed"]; ok && p.Fixed == "" {
					p.Fixed = v
				}
			}
			if p.Fixed != "" {
				a.HasFix = true
				p.FixTime = pkgFix
			}
			a.Packages = append(a.Packages, p)
		}
	}

	// Fix time per the distro's basis.
	switch d.Rules.FixTimeBasis {
	case "component_event":
		if compFix != nil {
			a.FixTime = compFix
		} else {
			a.FixTime = a.Published
		}
	case "modified":
		a.FixTime = a.Modified
	default:
		a.FixTime = a.Published
	}
	a.FixTimeTrusted = a.HasFix && a.Withdrawn == nil && a.FixTime != nil && kindTrusted(a.Kind, d.Rules.TrustedKinds)
	if a.FixTimeTrusted && d.Rules.MaxIDYearGap != nil {
		if y := IDYear(a.ID); y > 0 && a.FixTime.Year()-y > *d.Rules.MaxIDYearGap {
			a.FixTimeTrusted = false
		}
	}
	return a, nil
}

func kindTrusted(kind string, trusted []string) bool {
	if len(trusted) == 0 {
		return true
	}
	for _, k := range trusted {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}
