package api

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
)

const (
	defaultRecordLimit = 50
	maxRecordLimit     = 200
)

// recordParams are the record browser's own query parameters. The shared
// analytics params scope the list exactly as they scope the charts, so a list
// opened from a chart bar has as many rows as the bar counted.
type recordParams struct {
	Status  string     // fixed | open
	MinDays *float64   // days from CVE publication to the fix, or to now when open; inclusive
	MaxDays *float64   // exclusive
	Undated bool       // only CVEs without a publication date
	Month   *time.Time // one month of the range, on the charts' month basis (fixed only)
	CVE     string     // exact CVE ID
	CVELike string     // LIKE pattern on the CVE ID
	PkgLike string     // ILIKE pattern on the package name
	Sort    string     // days | published | fixed | severity
	Desc    bool
	Limit   int
	Offset  int
}

var (
	cveFullRe   = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
	cvePrefixRe = regexp.MustCompile(`^CVE-[0-9-]*$`)
	cveBareRe   = regexp.MustCompile(`^[0-9]{4}-[0-9]+$`)
)

// setSearch routes the free-text query. Text shaped like a CVE ID matches IDs,
// exactly once it is complete and as a prefix before that; anything else is a
// case-insensitive substring of the package name.
func (rp *recordParams) setSearch(q string) {
	q = strings.TrimSpace(q)
	if q == "" {
		return
	}
	id := strings.ToUpper(q)
	if cveBareRe.MatchString(id) {
		id = "CVE-" + id
	}
	switch {
	case cveFullRe.MatchString(id):
		rp.CVE = id
	case cvePrefixRe.MatchString(id):
		rp.CVELike = id + "%" // digits and dashes only, nothing to escape
	default:
		rp.PkgLike = "%" + likeEscape.Replace(q) + "%"
	}
}

func parseDays(s string) (*float64, error) {
	if s == "" {
		return nil, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, fmt.Errorf("%q is not a number of days", s)
	}
	return &v, nil
}

func parseRecordParams(r *http.Request) (recordParams, error) {
	q := r.URL.Query()
	rp := recordParams{Status: "fixed", Sort: "days", Desc: true, Limit: defaultRecordLimit}
	if v := q.Get("status"); v != "" {
		if v != "fixed" && v != "open" {
			return rp, fmt.Errorf("status must be fixed or open")
		}
		rp.Status = v
	}
	var err error
	if rp.MinDays, err = parseDays(q.Get("min_days")); err != nil {
		return rp, fmt.Errorf("bad min_days: %w", err)
	}
	if rp.MaxDays, err = parseDays(q.Get("max_days")); err != nil {
		return rp, fmt.Errorf("bad max_days: %w", err)
	}
	if rp.MinDays != nil && rp.MaxDays != nil && *rp.MinDays >= *rp.MaxDays {
		return rp, fmt.Errorf("min_days must be below max_days")
	}
	rp.Undated = q.Get("undated") == "true" || q.Get("undated") == "1"
	if rp.Undated && (rp.MinDays != nil || rp.MaxDays != nil) {
		return rp, fmt.Errorf("undated cannot be combined with min_days or max_days")
	}
	if v := q.Get("month"); v != "" {
		if rp.Status != "fixed" {
			return rp, fmt.Errorf("month applies to fixed records only")
		}
		m, err := parseMonth(v, false)
		if err != nil {
			return rp, err
		}
		rp.Month = &m
	}
	search := q.Get("q")
	if len(search) > 200 {
		return rp, fmt.Errorf("q is too long")
	}
	rp.setSearch(search)
	if v := q.Get("sort"); v != "" {
		switch {
		case v == "days" || v == "published" || v == "severity":
		case v == "fixed" && rp.Status == "fixed":
		default:
			return rp, fmt.Errorf("bad sort %q for %s records", v, rp.Status)
		}
		rp.Sort = v
	}
	switch q.Get("order") {
	case "", "desc":
	case "asc":
		rp.Desc = false
	default:
		return rp, fmt.Errorf("order must be asc or desc")
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxRecordLimit {
			return rp, fmt.Errorf("limit must be between 1 and %d", maxRecordLimit)
		}
		rp.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return rp, fmt.Errorf("offset must not be negative")
		}
		rp.Offset = n
	}
	return rp, nil
}

// Record is one row of the browser: a CVE as one distribution fixed it or
// still lists it. In CVE mode Packages counts the distinct package names
// behind the row and PackageNames holds the first few; in package mode the
// row is one package in one release.
type Record struct {
	Distro       string     `json:"distro"`
	CVE          string     `json:"cve_id"`
	Severity     string     `json:"severity"`
	CVSSScore    *float64   `json:"cvss_score"`
	CVEPublished *time.Time `json:"cve_published"`
	FixTime      *time.Time `json:"fix_time"`
	Trusted      bool       `json:"fix_time_trusted"`
	Days         *float64   `json:"days"` // publication to fix, or to now when open; null when it cannot be measured
	AdvisoryID   string     `json:"advisory_id"`
	Ecosystem    string     `json:"ecosystem,omitempty"`
	Package      string     `json:"package,omitempty"`
	Packages     int64      `json:"packages"`
	PackageNames []string   `json:"package_names"`
}

// RecordPage is one page of records and the size of the whole selection.
type RecordPage struct {
	Rows   []Record `json:"rows"`
	Total  int64    `json:"total"`
	Limit  int      `json:"limit"`
	Offset int      `json:"offset"`
}

func severityFilter(p params, b *argBuilder) (string, bool) {
	if len(p.Severities) == 0 || (len(p.Severities) == 1 && p.Severities[0] == "all") {
		return "", false
	}
	return "severity = ANY(" + b.add(pq.Array(p.Severities)) + ")", true
}

func (rp recordParams) cveFilter(b *argBuilder) (string, bool) {
	switch {
	case rp.CVE != "":
		return "cve_id = " + b.add(rp.CVE), true
	case rp.CVELike != "":
		return "cve_id LIKE " + b.add(rp.CVELike), true
	}
	return "", false
}

// fixedCore is the FROM/WHERE of the fixed-record list. It is the fact source
// and the predicates of the fixes and time-to-remediate charts, plus the
// browser's own narrowing.
func fixedCore(p params, rp recordParams, b *argBuilder) string {
	extra := "advisory_id, cvss_score"
	if p.Unit == "package" {
		extra += ", ecosystem, package"
	}
	src := factSourceWith(p, b, extra, rp.PkgLike)
	col := timeCol(p)
	where := []string{col + " >= " + b.add(p.From), col + " < " + b.add(p.To)}
	if rp.Month != nil {
		where = append(where, col+" >= "+b.add(*rp.Month), col+" < "+b.add(rp.Month.AddDate(0, 1, 0)))
	}
	if c, ok := severityFilter(p, b); ok {
		where = append(where, c)
	}
	// A duration only exists where the fix date is a real remediation date.
	if p.Trusted || rp.MinDays != nil || rp.MaxDays != nil {
		where = append(where, "fix_time_trusted")
	}
	if rp.MinDays != nil {
		where = append(where, "ttr_days >= "+b.add(*rp.MinDays))
	}
	if rp.MaxDays != nil {
		where = append(where, "ttr_days < "+b.add(*rp.MaxDays))
	}
	if rp.Undated {
		where = append(where, "cve_published IS NULL")
	}
	if c, ok := rp.cveFilter(b); ok {
		where = append(where, c)
	}
	return src + " f WHERE " + strings.Join(where, " AND ")
}

// openCore is the FROM of the open-record list: the backlog chart's selection
// (which the date range does not scope), one row per CVE or per package.
func openCore(p params, rp recordParams, b *argBuilder) string {
	where := []string{"1=1"}
	if len(p.Distros) > 0 {
		where = append(where, "distro = ANY("+b.add(pq.Array(p.Distros))+")")
	}
	if p.Ecosystem != "" {
		clause, arg := ecosystemClause("ecosystem", p.Ecosystem)
		where = append(where, fmt.Sprintf(clause, b.add(arg)))
	}
	if c, ok := severityFilter(p, b); ok {
		where = append(where, c)
	}
	// Age runs from the CVE's publication to now, on the backlog's boundaries.
	if rp.MinDays != nil {
		where = append(where, "cve_published <= now() - "+b.add(*rp.MinDays)+"::float8 * interval '1 day'")
	}
	if rp.MaxDays != nil {
		where = append(where, "cve_published > now() - "+b.add(*rp.MaxDays)+"::float8 * interval '1 day'")
	}
	if rp.Undated {
		where = append(where, "cve_published IS NULL")
	}
	if c, ok := rp.cveFilter(b); ok {
		where = append(where, c)
	}
	if rp.PkgLike != "" {
		where = append(where, "package ILIKE "+b.add(rp.PkgLike))
	}
	if p.Unit == "package" {
		return fmt.Sprintf(`(SELECT distro, cve_id, severity, cve_published, cvss_score, advisory_id, ecosystem, package
		                    FROM fact_open WHERE %s) f`, strings.Join(where, " AND "))
	}
	return fmt.Sprintf(`(SELECT distro, cve_id, severity, cve_published, max(cvss_score) AS cvss_score, min(advisory_id) AS advisory_id
	                    FROM fact_open WHERE %s GROUP BY distro, cve_id, severity, cve_published) f`, strings.Join(where, " AND "))
}

const sevRankExpr = `CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'none' THEN 1 ELSE 0 END`

// recordOrder returns the ORDER BY list. Every key ends in the row identity so
// paging is stable.
func recordOrder(p params, rp recordParams) string {
	dir, flipped := "ASC", "DESC"
	if rp.Desc {
		dir, flipped = flipped, dir
	}
	var keys []string
	switch rp.Sort {
	case "published":
		keys = []string{"cve_published " + dir + " NULLS LAST"}
	case "fixed":
		keys = []string{"fix_time " + dir + " NULLS LAST"}
	case "severity":
		keys = []string{sevRankExpr + " " + dir, "cvss_score " + dir + " NULLS LAST"}
	default: // days
		if rp.Status == "open" {
			keys = []string{"cve_published " + flipped + " NULLS LAST"} // the longest open is the earliest published
		} else {
			keys = []string{"(CASE WHEN fix_time_trusted THEN ttr_days END) " + dir + " NULLS LAST"}
		}
	}
	keys = append(keys, "distro", "cve_id", "severity")
	if p.Unit == "package" {
		keys = append(keys, "ecosystem", "package")
	}
	return strings.Join(keys, ", ")
}

// recordQueries builds the count and page statements for a selection.
func recordQueries(p params, rp recordParams) (countQ string, countArgs []any, pageQ string, pageArgs []any) {
	core, pkgTable := fixedCore, "fact_fixes_pkg"
	fixCols := "fix_time, fix_time_trusted, CASE WHEN fix_time_trusted THEN ttr_days END"
	if rp.Status == "open" {
		core, pkgTable = openCore, "fact_open"
		fixCols = "NULL::timestamptz, false, ROUND((EXTRACT(EPOCH FROM now() - cve_published) / 86400)::numeric, 1)"
	}
	cb := &argBuilder{}
	countQ = "SELECT count(*) FROM " + core(p, rp, cb)

	pb := &argBuilder{}
	from := core(p, rp, pb)
	order := recordOrder(p, rp)
	page := fmt.Sprintf("ORDER BY %s LIMIT %s OFFSET %s", order, pb.add(rp.Limit), pb.add(rp.Offset))
	cols := "distro, cve_id, severity, cvss_score, cve_published, " + fixCols + ", advisory_id"
	if p.Unit == "package" {
		pageQ = fmt.Sprintf("SELECT %s, ecosystem, package, 1::bigint, NULL::text[] FROM %s %s", cols, from, page)
		return countQ, cb.args, pageQ, pb.args
	}
	// CVE mode: name the packages behind each row of the page, within the
	// same release and package filters that selected it.
	scope := ""
	if p.Ecosystem != "" {
		clause, arg := ecosystemClause("x.ecosystem", p.Ecosystem)
		scope += " AND " + fmt.Sprintf(clause, pb.add(arg))
	}
	if rp.PkgLike != "" {
		scope += " AND x.package ILIKE " + pb.add(rp.PkgLike)
	}
	pageQ = fmt.Sprintf(`
		SELECT %s, '', '', pk.n, pk.names
		FROM (SELECT * FROM %s %s) r
		LEFT JOIN LATERAL (
			SELECT count(*) AS n, (array_agg(package ORDER BY package))[1:3] AS names
			FROM (SELECT DISTINCT x.package FROM %s x WHERE x.distro = r.distro AND x.cve_id = r.cve_id%s) d
		) pk ON true
		ORDER BY %s`, cols, from, page, pkgTable, scope, order)
	return countQ, cb.args, pageQ, pb.args
}

func (s *Server) records(ctx context.Context, p params, rp recordParams) (*RecordPage, error) {
	countQ, countArgs, pageQ, pageArgs := recordQueries(p, rp)
	out := &RecordPage{Rows: []Record{}, Limit: rp.Limit, Offset: rp.Offset}
	// The count scans the whole selection, so it runs alongside the page.
	counted := make(chan error, 1)
	go func() { counted <- s.db.QueryRowContext(ctx, countQ, countArgs...).Scan(&out.Total) }()
	err := func() error {
		rows, err := s.db.QueryContext(ctx, pageQ, pageArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Record
			var score, days sql.NullFloat64
			var names pq.StringArray
			if err := rows.Scan(&r.Distro, &r.CVE, &r.Severity, &score, &r.CVEPublished, &r.FixTime, &r.Trusted, &days,
				&r.AdvisoryID, &r.Ecosystem, &r.Package, &r.Packages, &names); err != nil {
				return err
			}
			r.CVSSScore, r.Days, r.PackageNames = nf(score), nf(days), names
			out.Rows = append(out.Rows, r)
		}
		return rows.Err()
	}()
	if cerr := <-counted; err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
