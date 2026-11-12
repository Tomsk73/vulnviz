// Package cve parses CVE Record Format 5.x JSON documents (as published by the
// CVE Program at cve.org / github.com/CVEProject/cvelistV5) into the compact
// representation stored by the app.
package cve

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"vulnviz/internal/cvss"
)

// Metric is one CVSS assessment attached to a record.
type Metric struct {
	Source   string  `json:"source"` // "cna" or "adp:<provider>"
	Version  string  `json:"version"`
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Vector   string  `json:"vector,omitempty"`
}

// Record is the normalised form of a CVE.
type Record struct {
	ID          string
	State       string
	Published   *time.Time
	Reserved    *time.Time
	Updated     *time.Time
	Assigner    string
	Title       string
	Description string
	CWEs        []string
	Metrics     []Metric
	// Chosen is the metric used for the record's headline score/severity.
	Chosen *Metric
	KEV    bool
}

type raw struct {
	CveMetadata struct {
		CveID             string `json:"cveId"`
		State             string `json:"state"`
		DatePublished     string `json:"datePublished"`
		DateReserved      string `json:"dateReserved"`
		DateUpdated       string `json:"dateUpdated"`
		AssignerShortName string `json:"assignerShortName"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA container   `json:"cna"`
		ADP []container `json:"adp"`
	} `json:"containers"`
}

type container struct {
	Title        string `json:"title"`
	ProviderMeta struct {
		ShortName string `json:"shortName"`
	} `json:"providerMetadata"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	ProblemTypes []struct {
		Descriptions []struct {
			CweID string `json:"cweId"`
		} `json:"descriptions"`
	} `json:"problemTypes"`
	Metrics []map[string]json.RawMessage `json:"metrics"`
}

type cvssBlock struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

var cweRe = regexp.MustCompile(`^CWE-\d+$`)

func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04:05.000"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// metricRank orders metrics for choosing the headline one: CNA first, then
// ADP, preferring CVSS 3.1 > 3.0 > 4.0 > 2.0 within a source.
func metricRank(m Metric) int {
	r := 0
	if strings.HasPrefix(m.Source, "adp") {
		r += 10
	}
	switch m.Version {
	case "3.1":
		r += 0
	case "3.0":
		r += 1
	case "4.0":
		r += 2
	case "2.0":
		r += 3
	default:
		r += 5
	}
	return r
}

func extractMetrics(source string, c container) []Metric {
	var out []Metric
	for _, m := range c.Metrics {
		for key, val := range m {
			var version string
			switch key {
			case "cvssV4_0":
				version = "4.0"
			case "cvssV3_1":
				version = "3.1"
			case "cvssV3_0":
				version = "3.0"
			case "cvssV2_0":
				version = "2.0"
			default:
				continue
			}
			var b cvssBlock
			if err := json.Unmarshal(val, &b); err != nil {
				continue
			}
			sev := cvss.NormalizeSeverity(b.BaseSeverity)
			if sev == "" {
				sev = cvss.Bucket(b.BaseScore)
			}
			if b.BaseScore == 0 && b.VectorString != "" {
				if _, s, ok := cvss.Score(b.VectorString); ok {
					b.BaseScore = s
					sev = cvss.Bucket(s)
				}
			}
			out = append(out, Metric{Source: source, Version: version, Score: b.BaseScore, Severity: sev, Vector: b.VectorString})
		}
	}
	return out
}

// Parse decodes one CVE 5.x JSON document.
func Parse(data []byte) (*Record, error) {
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	rec := &Record{
		ID:        r.CveMetadata.CveID,
		State:     r.CveMetadata.State,
		Published: parseTime(r.CveMetadata.DatePublished),
		Reserved:  parseTime(r.CveMetadata.DateReserved),
		Updated:   parseTime(r.CveMetadata.DateUpdated),
		Assigner:  r.CveMetadata.AssignerShortName,
		Title:     r.Containers.CNA.Title,
	}
	for _, d := range r.Containers.CNA.Descriptions {
		if d.Lang == "en" || strings.HasPrefix(d.Lang, "en-") || rec.Description == "" {
			rec.Description = d.Value
			if d.Lang == "en" {
				break
			}
		}
	}
	rec.Description = cvss.Clip(rec.Description, 1200)
	rec.Title = cvss.Clip(rec.Title, 300)
	seen := map[string]bool{}
	for _, pt := range r.Containers.CNA.ProblemTypes {
		for _, d := range pt.Descriptions {
			if cweRe.MatchString(d.CweID) && !seen[d.CweID] {
				seen[d.CweID] = true
				rec.CWEs = append(rec.CWEs, d.CweID)
			}
		}
	}
	rec.Metrics = extractMetrics("cna", r.Containers.CNA)
	for _, adp := range r.Containers.ADP {
		name := strings.ToLower(adp.ProviderMeta.ShortName)
		if name == "" {
			name = "unknown"
		}
		rec.Metrics = append(rec.Metrics, extractMetrics("adp:"+name, adp)...)
		for _, m := range adp.Metrics {
			if raw, ok := m["other"]; ok && strings.Contains(string(raw), `"kev"`) {
				rec.KEV = true
			}
		}
	}
	if len(rec.Metrics) > 0 {
		sort.SliceStable(rec.Metrics, func(i, j int) bool { return metricRank(rec.Metrics[i]) < metricRank(rec.Metrics[j]) })
		rec.Chosen = &rec.Metrics[0]
	}
	return rec, nil
}

// Severity returns the headline severity bucket for the record.
func (r *Record) Severity() string {
	if r.Chosen != nil {
		return r.Chosen.Severity
	}
	return "unknown"
}
