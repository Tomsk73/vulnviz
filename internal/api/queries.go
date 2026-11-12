package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
)

// argBuilder numbers SQL placeholders.
type argBuilder struct{ args []any }

func (b *argBuilder) add(v any) string {
	b.args = append(b.args, v)
	return fmt.Sprintf("$%d", len(b.args))
}

// factSource returns a subquery exposing one row per fix for the requested
// unit and ecosystem filter, with the columns the analytics queries need.
func factSource(p params, b *argBuilder) string {
	where := []string{"1=1"}
	if len(p.Distros) > 0 {
		where = append(where, "distro = ANY("+b.add(pq.Array(p.Distros))+")")
	}
	if p.Recent {
		where = append(where, "cve_published >= "+b.add(p.From), "cve_published < "+b.add(p.To))
	}
	if p.Ecosystem == "" {
		table := "fact_fixes_cve"
		if p.Unit == "package" {
			table = "fact_fixes_pkg"
		}
		return fmt.Sprintf("(SELECT distro, cve_id, fix_time, fix_time_trusted, cve_published, severity, ttr_days FROM %s WHERE %s)", table, strings.Join(where, " AND "))
	}
	clause, arg := ecosystemClause("ecosystem", p.Ecosystem)
	where = append(where, fmt.Sprintf(clause, b.add(arg)))
	if p.Unit == "package" {
		return fmt.Sprintf("(SELECT distro, cve_id, fix_time, fix_time_trusted, cve_published, severity, ttr_days FROM fact_fixes_pkg WHERE %s)", strings.Join(where, " AND "))
	}
	return fmt.Sprintf(`(SELECT DISTINCT ON (distro, cve_id) distro, cve_id, fix_time, fix_time_trusted, cve_published, severity, ttr_days
	                    FROM fact_fixes_pkg WHERE %s ORDER BY distro, cve_id, fix_time_trusted DESC, fix_time)`, strings.Join(where, " AND "))
}

func timeCol(p params) string {
	if p.Basis == "cve_month" {
		return "cve_published"
	}
	return "fix_time"
}

// MonthlyFix is one (distro, month, severity) count.
type MonthlyFix struct {
	Distro   string `json:"distro"`
	Month    string `json:"month"`
	Severity string `json:"severity"`
	Fixes    int64  `json:"fixes"`
}

func (s *Server) fixesMonthly(ctx context.Context, p params) ([]MonthlyFix, error) {
	b := &argBuilder{}
	var q string
	if p.Ecosystem == "" && !p.Recent {
		where := []string{"unit = " + b.add(p.Unit), "basis = " + b.add(p.Basis), "month >= " + b.add(p.From), "month < " + b.add(p.To)}
		if len(p.Distros) > 0 {
			where = append(where, "distro = ANY("+b.add(pq.Array(p.Distros))+")")
		}
		if len(p.Severities) > 0 {
			where = append(where, "severity = ANY("+b.add(pq.Array(p.Severities))+")")
		} else {
			where = append(where, "severity <> 'all'")
		}
		if p.Trusted {
			where = append(where, "trusted")
		}
		q = fmt.Sprintf(`SELECT distro, to_char(month, 'YYYY-MM'), severity, sum(fixes)::bigint FROM agg_monthly WHERE %s GROUP BY 1,2,3 ORDER BY 1,2,3`, strings.Join(where, " AND "))
	} else {
		src := factSource(p, b)
		col := timeCol(p)
		where := []string{col + " >= " + b.add(p.From), col + " < " + b.add(p.To)}
		sevExpr := "severity"
		if len(p.Severities) == 1 && p.Severities[0] == "all" {
			sevExpr = "'all'"
		} else if len(p.Severities) > 0 {
			where = append(where, "severity = ANY("+b.add(pq.Array(p.Severities))+")")
		}
		if p.Trusted {
			where = append(where, "fix_time_trusted")
		}
		q = fmt.Sprintf(`SELECT distro, to_char(date_trunc('month', %s), 'YYYY-MM'), %s, count(*) FROM %s f WHERE %s GROUP BY 1,2,3 ORDER BY 1,2,3`, col, sevExpr, src, strings.Join(where, " AND "))
	}
	rows, err := s.db.QueryContext(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MonthlyFix{}
	for rows.Next() {
		var m MonthlyFix
		if err := rows.Scan(&m.Distro, &m.Month, &m.Severity, &m.Fixes); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MTTRPoint is one (distro, month, severity) set of time-to-remediate stats in days.
type MTTRPoint struct {
	Distro   string   `json:"distro"`
	Month    string   `json:"month,omitempty"`
	Severity string   `json:"severity"`
	N        int64    `json:"n"`
	Median   *float64 `json:"median"`
	Mean     *float64 `json:"mean"`
	P25      *float64 `json:"p25"`
	P75      *float64 `json:"p75"`
	P90      *float64 `json:"p90"`
}

const pctCols = `ROUND((percentile_cont(0.5) WITHIN GROUP (ORDER BY ttr_days))::numeric,2), ROUND(avg(ttr_days)::numeric,2),
                 ROUND((percentile_cont(0.25) WITHIN GROUP (ORDER BY ttr_days))::numeric,2),
                 ROUND((percentile_cont(0.75) WITHIN GROUP (ORDER BY ttr_days))::numeric,2),
                 ROUND((percentile_cont(0.9) WITHIN GROUP (ORDER BY ttr_days))::numeric,2)`

func (s *Server) mttrMonthly(ctx context.Context, p params) ([]MTTRPoint, error) {
	b := &argBuilder{}
	sevs := p.Severities
	if len(sevs) == 0 {
		sevs = []string{"all"}
	}
	var q string
	if p.Ecosystem == "" && !p.Recent {
		where := []string{"unit = " + b.add(p.Unit), "basis = " + b.add(p.Basis), "trusted", "month >= " + b.add(p.From), "month < " + b.add(p.To), "severity = ANY(" + b.add(pq.Array(sevs)) + ")"}
		if len(p.Distros) > 0 {
			where = append(where, "distro = ANY("+b.add(pq.Array(p.Distros))+")")
		}
		q = fmt.Sprintf(`SELECT distro, to_char(month,'YYYY-MM'), severity, fixes, ttr_median, ttr_mean, ttr_p25, ttr_p75, ttr_p90 FROM agg_monthly WHERE %s ORDER BY 1,2,3`, strings.Join(where, " AND "))
	} else {
		src := factSource(p, b)
		col := timeCol(p)
		where := []string{"fix_time_trusted", "ttr_days IS NOT NULL", col + " >= " + b.add(p.From), col + " < " + b.add(p.To)}
		sevExpr := "severity"
		if len(sevs) == 1 && sevs[0] == "all" {
			sevExpr = "'all'"
		} else {
			where = append(where, "severity = ANY("+b.add(pq.Array(sevs))+")")
		}
		q = fmt.Sprintf(`SELECT distro, to_char(date_trunc('month', %s),'YYYY-MM'), %s, count(*), %s FROM %s f WHERE %s GROUP BY 1,2,3 ORDER BY 1,2,3`, col, sevExpr, pctCols, src, strings.Join(where, " AND "))
	}
	return s.scanMTTR(ctx, q, b.args, true)
}

func (s *Server) mttrSummary(ctx context.Context, p params) ([]MTTRPoint, error) {
	b := &argBuilder{}
	src := factSource(p, b)
	col := timeCol(p)
	where := []string{"fix_time_trusted", "ttr_days IS NOT NULL", col + " >= " + b.add(p.From), col + " < " + b.add(p.To)}
	if len(p.Severities) > 0 && !(len(p.Severities) == 1 && p.Severities[0] == "all") {
		where = append(where, "severity = ANY("+b.add(pq.Array(p.Severities))+")")
	}
	q := fmt.Sprintf(`SELECT distro, COALESCE(severity,'all'), count(*), %s FROM %s f WHERE %s GROUP BY distro, GROUPING SETS ((severity), ()) ORDER BY 1,2`, pctCols, src, strings.Join(where, " AND "))
	return s.scanMTTR(ctx, q, b.args, false)
}

func (s *Server) scanMTTR(ctx context.Context, q string, args []any, withMonth bool) ([]MTTRPoint, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MTTRPoint{}
	for rows.Next() {
		var m MTTRPoint
		var med, mean, p25, p75, p90 sql.NullFloat64
		var dest []any
		if withMonth {
			dest = []any{&m.Distro, &m.Month, &m.Severity, &m.N, &med, &mean, &p25, &p75, &p90}
		} else {
			dest = []any{&m.Distro, &m.Severity, &m.N, &med, &mean, &p25, &p75, &p90}
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		m.Median, m.Mean, m.P25, m.P75, m.P90 = nf(med), nf(mean), nf(p25), nf(p75), nf(p90)
		out = append(out, m)
	}
	return out, rows.Err()
}

func nf(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

// Bucket is one histogram bar.
type Bucket struct {
	Distro string `json:"distro"`
	Bucket string `json:"bucket"`
	Order  int    `json:"order"`
	N      int64  `json:"n"`
}

const ttrBucketExpr = `CASE WHEN ttr_days < 0 THEN 0 WHEN ttr_days < 1 THEN 1 WHEN ttr_days < 7 THEN 2 WHEN ttr_days < 30 THEN 3
                            WHEN ttr_days < 90 THEN 4 WHEN ttr_days < 365 THEN 5 ELSE 6 END`

var ttrBucketNames = []string{"before publication", "under 1 day", "1 to 7 days", "7 to 30 days", "30 to 90 days", "90 days to 1 year", "over 1 year"}

func (s *Server) mttrDistribution(ctx context.Context, p params) ([]Bucket, error) {
	b := &argBuilder{}
	src := factSource(p, b)
	col := timeCol(p)
	where := []string{"fix_time_trusted", "ttr_days IS NOT NULL", col + " >= " + b.add(p.From), col + " < " + b.add(p.To)}
	if len(p.Severities) > 0 && !(len(p.Severities) == 1 && p.Severities[0] == "all") {
		where = append(where, "severity = ANY("+b.add(pq.Array(p.Severities))+")")
	}
	q := fmt.Sprintf(`SELECT distro, %s AS b, count(*) FROM %s f WHERE %s GROUP BY 1,2 ORDER BY 1,2`, ttrBucketExpr, src, strings.Join(where, " AND "))
	rows, err := s.db.QueryContext(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bucket{}
	for rows.Next() {
		var r Bucket
		if err := rows.Scan(&r.Distro, &r.Order, &r.N); err != nil {
			return nil, err
		}
		r.Bucket = ttrBucketNames[r.Order]
		out = append(out, r)
	}
	return out, rows.Err()
}

// OpenRow is one backlog cell.
type OpenRow struct {
	Distro   string `json:"distro"`
	Severity string `json:"severity"`
	Age      string `json:"age"`
	Order    int    `json:"order"`
	N        int64  `json:"n"`
}

var ageNames = []string{"under 30 days", "30 to 90 days", "90 days to 1 year", "over 1 year", "no CVE date"}

func (s *Server) backlog(ctx context.Context, p params) ([]OpenRow, error) {
	b := &argBuilder{}
	where := []string{"1=1"}
	if len(p.Distros) > 0 {
		where = append(where, "distro = ANY("+b.add(pq.Array(p.Distros))+")")
	}
	if p.Ecosystem != "" {
		clause, arg := ecosystemClause("ecosystem", p.Ecosystem)
		where = append(where, fmt.Sprintf(clause, b.add(arg)))
	}
	if len(p.Severities) > 0 && !(len(p.Severities) == 1 && p.Severities[0] == "all") {
		where = append(where, "severity = ANY("+b.add(pq.Array(p.Severities))+")")
	}
	// Backlog is counted per CVE per distro (a CVE open in several packages counts once).
	q := fmt.Sprintf(`
		WITH o AS (SELECT DISTINCT distro, cve_id, severity, cve_published FROM fact_open WHERE %s)
		SELECT distro, severity,
		       CASE WHEN cve_published IS NULL THEN 4 WHEN cve_published > now() - interval '30 days' THEN 0
		            WHEN cve_published > now() - interval '90 days' THEN 1 WHEN cve_published > now() - interval '365 days' THEN 2 ELSE 3 END AS age,
		       count(*) FROM o GROUP BY 1,2,3 ORDER BY 1,2,3`, strings.Join(where, " AND "))
	rows, err := s.db.QueryContext(ctx, q, b.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OpenRow{}
	for rows.Next() {
		var r OpenRow
		if err := rows.Scan(&r.Distro, &r.Severity, &r.Order, &r.N); err != nil {
			return nil, err
		}
		r.Age = ageNames[r.Order]
		out = append(out, r)
	}
	return out, rows.Err()
}

// CVEMonth is one month of CVE publications by severity.
type CVEMonth struct {
	Month    string `json:"month"`
	Severity string `json:"severity"`
	CVEs     int64  `json:"cves"`
}

func (s *Server) cvesMonthly(ctx context.Context, p params) ([]CVEMonth, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT to_char(month,'YYYY-MM'), severity, cves FROM agg_cves_monthly WHERE month >= $1 AND month < $2 ORDER BY 1,2`, p.From, p.To)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CVEMonth{}
	for rows.Next() {
		var r CVEMonth
		if err := rows.Scan(&r.Month, &r.Severity, &r.CVEs); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Distro is the reference row plus counts.
type Distro struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Homepage      *string         `json:"homepage"`
	Notes         *string         `json:"notes"`
	Rules         json.RawMessage `json:"rules"`
	Advisories    int64           `json:"advisories"`
	FixedCVEs     int64           `json:"fixed_cves"`
	TrustedCVEs   int64           `json:"trusted_fixed_cves"`
	OpenCVEs      int64           `json:"open_cves"`
	FirstFix      *time.Time      `json:"first_trusted_fix"`
	LastFix       *time.Time      `json:"last_fix"`
	LastIngest    *time.Time      `json:"last_ingest"`
	LastIngestOK  *bool           `json:"last_ingest_ok"`
}

func (s *Server) distros(ctx context.Context) ([]Distro, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT d.id, d.name, d.homepage, d.notes, d.rules,
		       (SELECT count(*) FROM advisories a WHERE a.distro = d.id),
		       (SELECT count(*) FROM fact_fixes_cve f WHERE f.distro = d.id),
		       (SELECT count(*) FROM fact_fixes_cve f WHERE f.distro = d.id AND f.fix_time_trusted),
		       (SELECT count(DISTINCT cve_id) FROM fact_open o WHERE o.distro = d.id),
		       (SELECT min(fix_time) FROM fact_fixes_cve f WHERE f.distro = d.id AND f.fix_time_trusted),
		       (SELECT max(fix_time) FROM fact_fixes_cve f WHERE f.distro = d.id),
		       r.finished_at, r.status = 'ok'
		FROM distros d
		LEFT JOIN LATERAL (SELECT finished_at, status FROM ingest_runs WHERE source = d.id AND finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1) r ON true
		ORDER BY d.sort_order`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Distro{}
	for rows.Next() {
		var d Distro
		var rules []byte
		var ok sql.NullBool
		var last sql.NullTime
		if err := rows.Scan(&d.ID, &d.Name, &d.Homepage, &d.Notes, &rules, &d.Advisories, &d.FixedCVEs, &d.TrustedCVEs, &d.OpenCVEs, &d.FirstFix, &d.LastFix, &last, &ok); err != nil {
			return nil, err
		}
		d.Rules = json.RawMessage(rules)
		if last.Valid {
			t := last.Time
			d.LastIngest = &t
		}
		if ok.Valid {
			v := ok.Bool
			d.LastIngestOK = &v
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Ecosystem is a release/variant within a distro.
type Ecosystem struct {
	Ecosystem string `json:"ecosystem"`
	Fixes     int64  `json:"fixes"`
}

func (s *Server) ecosystems(ctx context.Context, distro string) ([]Ecosystem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ecosystem, count(*) FROM fact_fixes_pkg WHERE distro = $1 GROUP BY 1 ORDER BY 2 DESC, 1`, distro)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ecosystem{}
	for rows.Next() {
		var e Ecosystem
		if err := rows.Scan(&e.Ecosystem, &e.Fixes); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CVEDetail is a CVE plus its per-distro remediation state.
type CVEDetail struct {
	ID          string          `json:"id"`
	State       string          `json:"state"`
	Published   *time.Time      `json:"published"`
	Title       *string         `json:"title"`
	Description *string         `json:"description"`
	Severity    string          `json:"severity"`
	CVSSScore   *float64        `json:"cvss_score"`
	CVSSVector  *string         `json:"cvss_vector"`
	CVSSSource  *string         `json:"cvss_source"`
	KEV         bool            `json:"kev"`
	CWEs        []string        `json:"cwes"`
	Metrics     json.RawMessage `json:"metrics"`
	Fixes       []CVEFix        `json:"fixes"`
	Open        []CVEOpen       `json:"open"`
}

// CVEFix is one distro's fix for a CVE.
type CVEFix struct {
	Distro     string     `json:"distro"`
	Ecosystem  string     `json:"ecosystem"`
	Package    string     `json:"package"`
	AdvisoryID string     `json:"advisory_id"`
	FixTime    time.Time  `json:"fix_time"`
	Trusted    bool       `json:"fix_time_trusted"`
	TTRDays    *float64   `json:"ttr_days"`
}

// CVEOpen is one unfixed package.
type CVEOpen struct {
	Distro     string `json:"distro"`
	Ecosystem  string `json:"ecosystem"`
	Package    string `json:"package"`
	AdvisoryID string `json:"advisory_id"`
}

func (s *Server) cveDetail(ctx context.Context, id string) (*CVEDetail, error) {
	d := &CVEDetail{}
	var metrics []byte
	var score sql.NullFloat64
	err := s.db.QueryRowContext(ctx, `SELECT id, state, published, title, description, severity, cvss_score, cvss_vector, cvss_source, kev, cwes, metrics FROM cves WHERE id = $1`, id).
		Scan(&d.ID, &d.State, &d.Published, &d.Title, &d.Description, &d.Severity, &score, &d.CVSSVector, &d.CVSSSource, &d.KEV, pq.Array(&d.CWEs), &metrics)
	if err != nil {
		return nil, err
	}
	d.CVSSScore = nf(score)
	d.Metrics = json.RawMessage(metrics)
	if d.CWEs == nil {
		d.CWEs = []string{}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT distro, ecosystem, package, advisory_id, fix_time, fix_time_trusted, ttr_days FROM fact_fixes_pkg WHERE cve_id = $1 ORDER BY distro, fix_time, ecosystem, package`, id)
	if err != nil {
		return nil, err
	}
	d.Fixes = []CVEFix{}
	for rows.Next() {
		var f CVEFix
		var ttr sql.NullFloat64
		if err := rows.Scan(&f.Distro, &f.Ecosystem, &f.Package, &f.AdvisoryID, &f.FixTime, &f.Trusted, &ttr); err != nil {
			rows.Close()
			return nil, err
		}
		f.TTRDays = nf(ttr)
		d.Fixes = append(d.Fixes, f)
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `SELECT distro, ecosystem, package, advisory_id FROM fact_open WHERE cve_id = $1 ORDER BY distro, ecosystem, package`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d.Open = []CVEOpen{}
	for rows.Next() {
		var o CVEOpen
		if err := rows.Scan(&o.Distro, &o.Ecosystem, &o.Package, &o.AdvisoryID); err != nil {
			return nil, err
		}
		d.Open = append(d.Open, o)
	}
	return d, rows.Err()
}

// Status summarises the datasets and recent ingest runs.
type Status struct {
	CVEs         int64      `json:"cves"`
	CVEFirst     *time.Time `json:"cve_first_published"`
	CVELast      *time.Time `json:"cve_last_published"`
	LastCVELoad  *time.Time `json:"last_cve_load"`
	LastRebuild  *time.Time `json:"last_rebuild"`
	Runs         []Run      `json:"runs"`
}

// Run is one ingest run.
type Run struct {
	ID         int64      `json:"id"`
	Source     string     `json:"source"`
	Mode       string     `json:"mode"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Status     string     `json:"status"`
	Records    int64      `json:"records"`
	Detail     *string    `json:"detail"`
}

func (s *Server) status(ctx context.Context) (*Status, error) {
	st := &Status{Runs: []Run{}}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*), min(published), max(published) FROM cves WHERE state='PUBLISHED'`).Scan(&st.CVEs, &st.CVEFirst, &st.CVELast); err != nil {
		return nil, err
	}
	_ = s.db.QueryRowContext(ctx, `SELECT max(finished_at) FROM ingest_runs WHERE source='cve' AND status='ok'`).Scan(&st.LastCVELoad)
	_ = s.db.QueryRowContext(ctx, `SELECT max(finished_at) FROM ingest_runs WHERE source='aggregate' AND status='ok'`).Scan(&st.LastRebuild)
	rows, err := s.db.QueryContext(ctx, `SELECT id, source, mode, started_at, finished_at, status, records, detail FROM ingest_runs ORDER BY started_at DESC LIMIT 30`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Run
		if err := rows.Scan(&r.ID, &r.Source, &r.Mode, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Records, &r.Detail); err != nil {
			return nil, err
		}
		st.Runs = append(st.Runs, r)
	}
	return st, rows.Err()
}
