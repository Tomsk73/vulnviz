package cve

import "testing"

const sample = `{"cveMetadata":{"cveId":"CVE-2024-0001","state":"PUBLISHED","datePublished":"2024-01-02T03:04:05.000Z","dateUpdated":"2024-02-01T00:00:00Z","assignerShortName":"test"},
"containers":{"cna":{"title":"t","descriptions":[{"lang":"en","value":"desc"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}],
"metrics":[{"cvssV3_1":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"cvssV3_1":{"baseScore":9.8,"baseSeverity":"CRITICAL"}},{"other":{"type":"kev","content":{}}}]}]}}`

func TestParse(t *testing.T) {
	r, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "CVE-2024-0001" || r.Published == nil || r.Published.Year() != 2024 {
		t.Fatalf("bad metadata: %+v", r)
	}
	if r.Chosen == nil || r.Chosen.Source != "cna" || r.Chosen.Score != 7.5 || r.Severity() != "high" {
		t.Fatalf("expected CNA metric chosen, got %+v", r.Chosen)
	}
	if len(r.Metrics) != 2 || !r.KEV || len(r.CWEs) != 1 {
		t.Fatalf("metrics/kev/cwe wrong: %+v", r)
	}
}
