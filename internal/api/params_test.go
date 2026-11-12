package api

import (
	"net/http/httptest"
	"testing"
)

func TestParseParams(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/fixes/monthly?distros=chainguard,ubuntu&from=2025-01&to=2025-12&severity=critical,high&unit=package&basis=fix_month&ecosystem=Ubuntu:24.04*", nil)
	p, err := parseParams(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Distros) != 2 || p.From.Format("2006-01") != "2025-01" || p.To.Format("2006-01") != "2026-01" {
		t.Fatalf("range/distros wrong: %+v", p)
	}
	if !p.Trusted || !p.Recent || p.Unit != "package" || len(p.Severities) != 2 {
		t.Fatalf("defaults wrong: %+v", p)
	}
	clause, arg := ecosystemClause("ecosystem", p.Ecosystem)
	if clause != "ecosystem LIKE %s" || arg != `Ubuntu:24.04%` {
		t.Fatalf("ecosystem clause: %s %v", clause, arg)
	}
	for _, bad := range []string{"?severity=urgent", "?from=2025-13", "?from=2025-05&to=2025-01", "?unit=file"} {
		if _, err := parseParams(httptest.NewRequest("GET", "/x"+bad, nil)); err == nil {
			t.Errorf("expected error for %s", bad)
		}
	}
	r = httptest.NewRequest("GET", "/x?basis=cve_month&scope=all", nil)
	p, _ = parseParams(r)
	if p.Trusted || p.Recent {
		t.Fatalf("cve_month/all should not force trusted or recent: %+v", p)
	}
}
