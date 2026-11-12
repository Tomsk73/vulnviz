// Package cvss computes CVSS base scores from vector strings and maps scores
// to qualitative severity buckets.
package cvss

import (
	"math"
	"strings"
)

// Bucket maps a numeric CVSS base score to the standard qualitative rating.
// A zero score is "none"; a negative score means unknown.
func Bucket(score float64) string {
	switch {
	case score < 0:
		return "unknown"
	case score == 0:
		return "none"
	case score < 4:
		return "low"
	case score < 7:
		return "medium"
	case score < 9:
		return "high"
	default:
		return "critical"
	}
}

// NormalizeSeverity lowercases a vendor-supplied severity word and maps common
// aliases onto the five buckets used by the app.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "urgent":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "negligible", "minor":
		return "low"
	case "none", "unimportant", "not yet assigned", "end of life", "end-of-life":
		return "none"
	default:
		return ""
	}
}

// Score computes the base score of a CVSS v2 or v3.x vector string. It returns
// the version label ("2.0", "3.0", "3.1"), the score and ok=false when the
// vector cannot be scored (including all CVSS 4.0 vectors, whose scoring is
// lookup-table based and whose numeric score is always supplied alongside the
// vector in the sources this app ingests).
func Score(vector string) (version string, score float64, ok bool) {
	v := strings.TrimSpace(vector)
	switch {
	case strings.HasPrefix(v, "CVSS:3.1/"):
		s, ok := scoreV3(v[len("CVSS:3.1/"):])
		return "3.1", s, ok
	case strings.HasPrefix(v, "CVSS:3.0/"):
		s, ok := scoreV3(v[len("CVSS:3.0/"):])
		return "3.0", s, ok
	case strings.HasPrefix(v, "CVSS:4.0/"):
		return "4.0", 0, false
	case strings.HasPrefix(v, "AV:"):
		s, ok := scoreV2(v)
		return "2.0", s, ok
	}
	return "", 0, false
}

func parseMetrics(v string) map[string]string {
	m := map[string]string{}
	for _, part := range strings.Split(v, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

func roundUp31(x float64) float64 {
	i := math.Round(x * 100000)
	if math.Mod(i, 10000) == 0 {
		return i / 100000
	}
	return (math.Floor(i/10000) + 1) / 10
}

func scoreV3(v string) (float64, bool) {
	m := parseMetrics(v)
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, cok := cia[m["C"]]
	i, iok := cia[m["I"]]
	a, aok := cia[m["A"]]
	scope := m["S"]
	if av == 0 || ac == 0 || ui == 0 || !cok || !iok || !aok || (scope != "U" && scope != "C") {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scope == "C" {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scope == "C" {
			pr = 0.5
		}
	default:
		return 0, false
	}
	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	expl := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	if scope == "U" {
		return roundUp31(math.Min(impact+expl, 10)), true
	}
	return roundUp31(math.Min(1.08*(impact+expl), 10)), true
}

func scoreV2(v string) (float64, bool) {
	m := parseMetrics(v)
	av := map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
	ac := map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
	au := map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
	cia := map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
	c, cok := cia[m["C"]]
	i, iok := cia[m["I"]]
	a, aok := cia[m["A"]]
	if av == 0 || ac == 0 || au == 0 || !cok || !iok || !aok {
		return 0, false
	}
	impact := 10.41 * (1 - (1-c)*(1-i)*(1-a))
	expl := 20 * av * ac * au
	f := 1.176
	if impact == 0 {
		f = 0
	}
	base := ((0.6 * impact) + (0.4 * expl) - 1.5) * f
	return math.Round(base*10) / 10, true
}
