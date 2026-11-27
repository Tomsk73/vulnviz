package api

import (
	"fmt"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestParseRecordParams(t *testing.T) {
	rp, err := parseRecordParams(httptest.NewRequest("GET", "/api/v1/records", nil))
	if err != nil {
		t.Fatal(err)
	}
	if rp.Status != "fixed" || rp.Sort != "days" || !rp.Desc || rp.Limit != defaultRecordLimit || rp.Offset != 0 || rp.MinDays != nil || rp.MaxDays != nil {
		t.Fatalf("defaults wrong: %+v", rp)
	}

	rp, err = parseRecordParams(httptest.NewRequest("GET", "/x?status=open&min_days=90&max_days=365&sort=published&order=asc&limit=25&offset=50&q=openssl", nil))
	if err != nil {
		t.Fatal(err)
	}
	if rp.Status != "open" || *rp.MinDays != 90 || *rp.MaxDays != 365 || rp.Sort != "published" || rp.Desc || rp.Limit != 25 || rp.Offset != 50 || rp.PkgLike != "%openssl%" {
		t.Fatalf("parsed wrong: %+v", rp)
	}

	rp, err = parseRecordParams(httptest.NewRequest("GET", "/x?month=2025-01&max_days=0", nil))
	if err != nil {
		t.Fatal(err)
	}
	if rp.Month == nil || rp.Month.Format("2006-01-02") != "2025-01-01" || *rp.MaxDays != 0 || rp.MinDays != nil {
		t.Fatalf("month/negative range wrong: %+v", rp)
	}

	for _, bad := range []string{
		"?status=closed", "?min_days=abc", "?max_days=NaN", "?min_days=90&max_days=30", "?min_days=30&max_days=30",
		"?undated=true&min_days=1", "?status=open&month=2025-01", "?month=2025-13", "?sort=package", "?status=open&sort=fixed",
		"?order=up", "?limit=0", "?limit=5000", "?offset=-1", "?q=" + strings.Repeat("a", 201),
	} {
		if _, err := parseRecordParams(httptest.NewRequest("GET", "/x"+bad, nil)); err == nil {
			t.Errorf("expected error for %s", bad)
		}
	}
}

func TestRecordSearch(t *testing.T) {
	for _, c := range []struct{ q, cve, cveLike, pkgLike string }{
		{"", "", "", ""},
		{"  ", "", "", ""},
		{"CVE-2024-3094", "CVE-2024-3094", "", ""},
		{" cve-2024-3094 ", "CVE-2024-3094", "", ""},
		{"2024-3094", "CVE-2024-3094", "", ""},
		{"CVE-2024-30", "", "CVE-2024-30%", ""},
		{"cve-2024", "", "CVE-2024%", ""},
		{"2024-30", "", "CVE-2024-30%", ""},
		{"openssl", "", "", "%openssl%"},
		{"cve-bin-tool", "", "", "%cve-bin-tool%"},
		{"lib_x%", "", "", `%lib\_x\%%`},
		{"389-ds-base", "", "", "%389-ds-base%"},
	} {
		var rp recordParams
		rp.setSearch(c.q)
		if rp.CVE != c.cve || rp.CVELike != c.cveLike || rp.PkgLike != c.pkgLike {
			t.Errorf("setSearch(%q) = cve %q, cveLike %q, pkgLike %q", c.q, rp.CVE, rp.CVELike, rp.PkgLike)
		}
	}
}

func TestEdgeBounds(t *testing.T) {
	show := func(v *float64) string {
		if v == nil {
			return "-"
		}
		return strconv.FormatFloat(*v, 'f', -1, 64)
	}
	var got []string
	for i := range ttrBucketNames {
		lo, hi := edgeBounds(ttrEdges, i)
		got = append(got, show(lo)+":"+show(hi))
	}
	if s := strings.Join(got, " "); s != "-:0 0:1 1:7 7:30 30:90 90:365 365:-" {
		t.Errorf("ttr bounds: %s", s)
	}
	got = nil
	for i := 0; i < ageUndated; i++ {
		lo, hi := edgeBounds(ageEdges, i)
		got = append(got, show(lo)+":"+show(hi))
	}
	if s := strings.Join(got, " "); s != "-:30 30:90 90:365 365:-" {
		t.Errorf("age bounds: %s", s)
	}
}

var placeholderRe = regexp.MustCompile(`\$(\d+)`)

// Each statement must reference exactly the arguments it is sent: PostgreSQL
// rejects a bind with unused or missing parameters.
func TestRecordQueriesBindEveryArg(t *testing.T) {
	check := func(name, q string, args []any) {
		t.Helper()
		seen := map[int]bool{}
		for _, m := range placeholderRe.FindAllStringSubmatch(q, -1) {
			n, _ := strconv.Atoi(m[1])
			seen[n] = true
		}
		for i := 1; i <= len(args); i++ {
			if !seen[i] {
				t.Errorf("%s: $%d is never used\n%s", name, i, q)
			}
		}
		if len(seen) != len(args) {
			t.Errorf("%s: %d placeholders for %d args\n%s", name, len(seen), len(args), q)
		}
	}
	for _, status := range []string{"fixed", "open"} {
		for _, unit := range []string{"cve", "package"} {
			for _, extra := range []string{
				"", "&ecosystem=Ubuntu:24.04*", "&q=openssl", "&q=CVE-2024-3094", "&q=cve-2024-3", "&min_days=90", "&min_days=30&max_days=90",
				"&undated=true", "&severity=critical,high", "&scope=all&basis=cve_month", "&ecosystem=Debian:12&q=ssl&max_days=0&sort=severity&order=asc",
			} {
				url := fmt.Sprintf("/api/v1/records?distros=debian,ubuntu&from=2025-01&to=2025-12&status=%s&unit=%s%s", status, unit, extra)
				if status == "fixed" {
					url += "&month=2025-03"
				}
				r := httptest.NewRequest("GET", url, nil)
				p, err := parseParams(r)
				if err != nil {
					t.Fatal(err)
				}
				rp, err := parseRecordParams(r)
				if err != nil {
					t.Fatal(err)
				}
				countQ, countArgs, pageQ, pageArgs := recordQueries(p, rp)
				check(url+" count", countQ, countArgs)
				check(url+" page", pageQ, pageArgs)
			}
		}
	}
}

func TestRecordOrder(t *testing.T) {
	for _, c := range []struct{ url, want string }{
		{"?status=fixed", "(CASE WHEN fix_time_trusted THEN ttr_days END) DESC NULLS LAST, distro, cve_id, severity"},
		{"?status=open", "cve_published ASC NULLS LAST, distro, cve_id, severity"},
		{"?status=open&order=asc", "cve_published DESC NULLS LAST, distro, cve_id, severity"},
		{"?status=fixed&sort=fixed&order=asc&unit=package", "fix_time ASC NULLS LAST, distro, cve_id, severity, ecosystem, package"},
	} {
		r := httptest.NewRequest("GET", "/x"+c.url, nil)
		p, _ := parseParams(r)
		rp, err := parseRecordParams(r)
		if err != nil {
			t.Fatal(err)
		}
		if got := recordOrder(p, rp); got != c.want {
			t.Errorf("%s: order %q, want %q", c.url, got, c.want)
		}
	}
}
