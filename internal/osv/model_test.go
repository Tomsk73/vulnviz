package osv

import (
	"testing"

	"vulnviz/internal/config"
)

func TestKind(t *testing.T) {
	for id, want := range map[string]string{
		"RHSA-2024:1234": "RHSA", "DEBIAN-CVE-2024-1": "DEBIAN-CVE", "USN-6913-1": "USN",
		"CGA-2222-46jc-4hmg": "CGA", "CGA-cfgh-abcd-xyzw": "CGA", "LSN-0065-1": "LSN", "ALPINE-CVE-2006-20001": "ALPINE-CVE", "CVE-2004-2462": "CVE", "ECHO-35af-8dfc-9fee": "ECHO",
	} {
		if got := Kind(id); got != want {
			t.Errorf("%s: %s != %s", id, got, want)
		}
	}
	if IDYear("RHSA-2003:315") != 2003 || IDYear("USN-6913-1") != 0 || IDYear("DEBIAN-CVE-2024-1") != 2024 {
		t.Error("IDYear")
	}
}

const rhsa = `{"id":"RHSA-2003:315","published":"2024-09-12T22:06:45Z","modified":"2026-06-26T10:00:51Z","upstream":["CVE-2003-0858"],
"affected":[{"package":{"name":"quagga","ecosystem":"Red Hat:enterprise_linux:3::as"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:0.96.2-8.3E"}]}]}]}`

const cga = `{"id":"CGA-1","published":"2026-04-03T13:57:32Z","modified":"2026-04-04T03:29:29Z","upstream":["CVE-2026-34986","GHSA-x"],
"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
"affected":[{"package":{"name":"p","ecosystem":"Chainguard"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.19.0-r5"}]}],
"ecosystem_specific":{"components":[{"latest_event_status":"fixed","latest_event_timestamp":"2026-04-04T03:29:29Z"}]}},
{"package":{"name":"p","ecosystem":"Wolfi"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.19.0-r5"}]}]}]}`

const ucve = `{"id":"UBUNTU-CVE-2001-1593","published":"2014-04-05T21:55:00Z","modified":"2025-07-16T07:30:37Z","upstream":["CVE-2001-1593"],
"affected":[{"package":{"name":"a2ps","ecosystem":"Ubuntu:14.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:4.14-1.2"}]}]}],
"severity":[{"type":"Ubuntu","score":"low"}]}`

func TestParseRules(t *testing.T) {
	gap := 0
	rh := config.Distro{ID: "redhat", Rules: config.Rules{FixTimeBasis: "published", MaxIDYearGap: &gap}}
	a, err := Parse([]byte(rhsa), rh)
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasFix || a.FixTimeTrusted || a.CVEs[0] != "CVE-2003-0858" || a.Kind != "RHSA" {
		t.Fatalf("redhat backfill rule failed: %+v", a)
	}

	cg := config.Distro{ID: "chainguard", Rules: config.Rules{FixTimeBasis: "component_event", EcosystemPrefix: "Chainguard"}}
	a, err = Parse([]byte(cga), cg)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Packages) != 1 || a.FixTime == nil || a.FixTime.Day() != 4 || !a.FixTimeTrusted || a.Severity != "high" || a.CVSSScore != 7.5 {
		t.Fatalf("chainguard rules failed: %+v fix=%v", a, a.FixTime)
	}
	if len(a.CVEs) != 1 {
		t.Fatalf("expected one CVE, got %v", a.CVEs)
	}

	ub := config.Distro{ID: "ubuntu", Rules: config.Rules{FixTimeBasis: "published", TrustedKinds: []string{"USN", "LSN"}}}
	a, err = Parse([]byte(ucve), ub)
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasFix || a.FixTimeTrusted || a.Severity != "low" || a.Kind != "UBUNTU-CVE" {
		t.Fatalf("ubuntu rules failed: %+v", a)
	}
}
