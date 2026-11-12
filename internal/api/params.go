// Package api serves the vulnviz REST API.
package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

var validSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "none": true, "unknown": true, "all": true}

// params are the common query parameters shared by the analytics endpoints.
type params struct {
	Distros    []string
	From, To   time.Time // month boundaries: From inclusive, To exclusive
	Severities []string  // explicit list; empty means each severity separately
	Unit       string    // cve | package
	Basis      string    // fix_month | cve_month
	Ecosystem  string    // exact or prefix (trailing *)
	Trusted    bool      // restrict counts to trusted fix times
	Recent     bool      // only CVEs published inside [From, To)
}

func parseMonth(s string, end bool) (time.Time, error) {
	for _, layout := range []string{"2006-01", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
			if end {
				t = t.AddDate(0, 1, 0)
			}
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("bad month %q (use YYYY-MM)", s)
}

func parseParams(r *http.Request) (params, error) {
	q := r.URL.Query()
	p := params{Unit: "cve", Basis: "fix_month"}
	if v := q.Get("distros"); v != "" {
		for _, d := range strings.Split(v, ",") {
			if d = strings.TrimSpace(d); d != "" {
				p.Distros = append(p.Distros, d)
			}
		}
	}
	now := time.Now().UTC()
	thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	p.From = thisMonth.AddDate(0, -23, 0)
	p.To = thisMonth.AddDate(0, 1, 0)
	var err error
	if v := q.Get("from"); v != "" {
		if p.From, err = parseMonth(v, false); err != nil {
			return p, err
		}
	}
	if v := q.Get("to"); v != "" {
		if p.To, err = parseMonth(v, true); err != nil {
			return p, err
		}
	}
	if !p.To.After(p.From) {
		return p, fmt.Errorf("to must not be before from")
	}
	if v := q.Get("severity"); v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.ToLower(strings.TrimSpace(s))
			if !validSeverities[s] {
				return p, fmt.Errorf("bad severity %q", s)
			}
			p.Severities = append(p.Severities, s)
		}
	}
	if v := q.Get("unit"); v != "" {
		if v != "cve" && v != "package" {
			return p, fmt.Errorf("unit must be cve or package")
		}
		p.Unit = v
	}
	if v := q.Get("basis"); v != "" {
		if v != "fix_month" && v != "cve_month" {
			return p, fmt.Errorf("basis must be fix_month or cve_month")
		}
		p.Basis = v
	}
	p.Ecosystem = strings.TrimSpace(q.Get("ecosystem"))
	p.Trusted = q.Get("trusted") == "true" || q.Get("trusted") == "1"
	// Grouping by fix month is only meaningful for records whose date is a
	// real remediation date; tracker records carry the CVE date instead.
	if p.Basis == "fix_month" {
		p.Trusted = true
	}
	p.Recent = q.Get("scope") != "all"
	return p, nil
}

// ecosystemClause returns a SQL predicate on column `col` and its argument.
func ecosystemClause(col, eco string) (string, any) {
	if strings.HasSuffix(eco, "*") {
		prefix := strings.TrimSuffix(eco, "*")
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix)
		return col + " LIKE %s", esc + "%"
	}
	return col + " = %s", eco
}
