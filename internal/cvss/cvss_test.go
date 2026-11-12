package cvss

import "testing"

func TestScoreV3(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H": 7.5,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H": 8.0,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 8.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N": 3.7,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		_, got, ok := Score(vec)
		if !ok || got != want {
			t.Errorf("%s: got %v ok=%v want %v", vec, got, ok, want)
		}
	}
}

func TestScoreV2(t *testing.T) {
	_, got, ok := Score("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	if !ok || got != 7.5 {
		t.Errorf("v2: got %v ok=%v", got, ok)
	}
}

func TestBucket(t *testing.T) {
	if Bucket(9.8) != "critical" || Bucket(7.0) != "high" || Bucket(4.0) != "medium" || Bucket(0.1) != "low" || Bucket(0) != "none" || Bucket(-1) != "unknown" {
		t.Fatal("bucket mapping wrong")
	}
}
