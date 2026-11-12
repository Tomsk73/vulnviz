// Package aggregate rebuilds the derived fact tables and monthly roll-ups from
// the raw CVE and advisory tables.
package aggregate

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"vulnviz/internal/ingestrun"
)

// Severity expression shared by the fact builders: the CVE record's own CVSS
// rating wins, then the distro's stated severity, else unknown.
const sevExpr = `CASE WHEN c.severity IS NOT NULL AND c.severity <> 'unknown' THEN c.severity
                      WHEN a.severity IS NOT NULL AND a.severity <> '' THEN a.severity
                      ELSE 'unknown' END`
const sevSrcExpr = `CASE WHEN c.severity IS NOT NULL AND c.severity <> 'unknown' THEN 'cve'
                         WHEN a.severity IS NOT NULL AND a.severity <> '' THEN 'distro'
                         ELSE 'unknown' END`

var steps = []struct {
	name string
	sql  string
}{
	{"fact_fixes_pkg", `
		TRUNCATE fact_fixes_pkg;
		INSERT INTO fact_fixes_pkg (distro, cve_id, ecosystem, package, advisory_id, kind, fix_time, fix_time_trusted,
		                            cve_published, severity, severity_source, cvss_score, ttr_days)
		SELECT DISTINCT ON (a.distro, ac.cve_id, p.ecosystem, p.package)
		       a.distro, ac.cve_id, p.ecosystem, p.package, a.id, a.kind,
		       COALESCE(p.fix_time, a.fix_time), a.fix_time_trusted,
		       c.published, ` + sevExpr + `, ` + sevSrcExpr + `,
		       COALESCE(c.cvss_score, a.cvss_score),
		       ROUND((EXTRACT(EPOCH FROM COALESCE(p.fix_time, a.fix_time) - c.published) / 86400)::numeric, 3)
		FROM advisories a
		JOIN advisory_cves ac ON ac.distro = a.distro AND ac.advisory_id = a.id
		JOIN advisory_packages p ON p.distro = a.distro AND p.advisory_id = a.id
		LEFT JOIN cves c ON c.id = ac.cve_id
		WHERE a.withdrawn IS NULL AND p.fixed IS NOT NULL AND COALESCE(p.fix_time, a.fix_time) IS NOT NULL
		ORDER BY a.distro, ac.cve_id, p.ecosystem, p.package, a.fix_time_trusted DESC, COALESCE(p.fix_time, a.fix_time);
		ANALYZE fact_fixes_pkg;`},
	{"fact_fixes_cve", `
		TRUNCATE fact_fixes_cve;
		INSERT INTO fact_fixes_cve (distro, cve_id, advisory_id, kind, fix_time, fix_time_trusted, cve_published,
		                            severity, severity_source, cvss_score, ttr_days, packages)
		SELECT DISTINCT ON (distro, cve_id) distro, cve_id, advisory_id, kind, fix_time, fix_time_trusted, cve_published,
		       severity, severity_source, cvss_score, ttr_days, count(*) OVER (PARTITION BY distro, cve_id)
		FROM fact_fixes_pkg
		ORDER BY distro, cve_id, fix_time_trusted DESC, fix_time;
		ANALYZE fact_fixes_cve;`},
	{"fact_open", `
		TRUNCATE fact_open;
		INSERT INTO fact_open (distro, cve_id, ecosystem, package, advisory_id, kind, advisory_published, cve_published, severity, cvss_score)
		SELECT DISTINCT ON (a.distro, ac.cve_id, p.ecosystem, p.package)
		       a.distro, ac.cve_id, p.ecosystem, p.package, a.id, a.kind, a.published, c.published,
		       ` + sevExpr + `, COALESCE(c.cvss_score, a.cvss_score)
		FROM advisories a
		JOIN advisory_cves ac ON ac.distro = a.distro AND ac.advisory_id = a.id
		JOIN advisory_packages p ON p.distro = a.distro AND p.advisory_id = a.id
		LEFT JOIN cves c ON c.id = ac.cve_id
		WHERE a.withdrawn IS NULL AND p.fixed IS NULL
		  AND NOT EXISTS (SELECT 1 FROM fact_fixes_pkg f
		                  WHERE f.distro = a.distro AND f.cve_id = ac.cve_id AND f.ecosystem = p.ecosystem AND f.package = p.package)
		ORDER BY a.distro, ac.cve_id, p.ecosystem, p.package, a.published;
		ANALYZE fact_open;`},
	{"agg_monthly", `
		TRUNCATE agg_monthly;
		-- CVE unit, by fix month and by CVE publication month; severity 'all' via grouping sets.
		INSERT INTO agg_monthly (distro, unit, basis, month, severity, trusted, fixes, ttr_median, ttr_mean, ttr_p25, ttr_p75, ttr_p90)
		SELECT distro, 'cve', 'fix_month', date_trunc('month', fix_time)::date, COALESCE(severity, 'all'), fix_time_trusted, count(*),
		       ROUND((percentile_cont(0.5) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2), ROUND(avg(ttr_days)::numeric, 2),
		       ROUND((percentile_cont(0.25) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.75) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.9) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2)
		FROM fact_fixes_cve
		GROUP BY distro, date_trunc('month', fix_time), fix_time_trusted, GROUPING SETS ((severity), ());
		INSERT INTO agg_monthly (distro, unit, basis, month, severity, trusted, fixes, ttr_median, ttr_mean, ttr_p25, ttr_p75, ttr_p90)
		SELECT distro, 'cve', 'cve_month', date_trunc('month', cve_published)::date, COALESCE(severity, 'all'), fix_time_trusted, count(*),
		       ROUND((percentile_cont(0.5) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2), ROUND(avg(ttr_days)::numeric, 2),
		       ROUND((percentile_cont(0.25) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.75) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.9) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2)
		FROM fact_fixes_cve WHERE cve_published IS NOT NULL
		GROUP BY distro, date_trunc('month', cve_published), fix_time_trusted, GROUPING SETS ((severity), ());
		-- Package unit (one fix per package per release).
		INSERT INTO agg_monthly (distro, unit, basis, month, severity, trusted, fixes, ttr_median, ttr_mean, ttr_p25, ttr_p75, ttr_p90)
		SELECT distro, 'package', 'fix_month', date_trunc('month', fix_time)::date, COALESCE(severity, 'all'), fix_time_trusted, count(*),
		       ROUND((percentile_cont(0.5) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2), ROUND(avg(ttr_days)::numeric, 2),
		       ROUND((percentile_cont(0.25) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.75) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.9) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2)
		FROM fact_fixes_pkg
		GROUP BY distro, date_trunc('month', fix_time), fix_time_trusted, GROUPING SETS ((severity), ());
		INSERT INTO agg_monthly (distro, unit, basis, month, severity, trusted, fixes, ttr_median, ttr_mean, ttr_p25, ttr_p75, ttr_p90)
		SELECT distro, 'package', 'cve_month', date_trunc('month', cve_published)::date, COALESCE(severity, 'all'), fix_time_trusted, count(*),
		       ROUND((percentile_cont(0.5) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2), ROUND(avg(ttr_days)::numeric, 2),
		       ROUND((percentile_cont(0.25) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.75) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2),
		       ROUND((percentile_cont(0.9) WITHIN GROUP (ORDER BY ttr_days))::numeric, 2)
		FROM fact_fixes_pkg WHERE cve_published IS NOT NULL
		GROUP BY distro, date_trunc('month', cve_published), fix_time_trusted, GROUPING SETS ((severity), ());
		ANALYZE agg_monthly;`},
	{"agg_cves_monthly", `
		TRUNCATE agg_cves_monthly;
		INSERT INTO agg_cves_monthly (month, severity, cves)
		SELECT date_trunc('month', published)::date, COALESCE(severity, 'all'), count(*)
		FROM cves WHERE published IS NOT NULL AND state = 'PUBLISHED'
		GROUP BY date_trunc('month', published), GROUPING SETS ((severity), ());`},
}

// Rebuild recomputes every derived table. Each step runs in its own
// transaction so readers never see a half-built table.
func Rebuild(ctx context.Context, conn *sql.DB) error {
	run, err := ingestrun.Start(ctx, conn, "aggregate", "aggregate")
	if err != nil {
		return err
	}
	var total int64
	err = func() error {
		for _, s := range steps {
			start := time.Now()
			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, s.sql); err != nil {
				tx.Rollback()
				return fmt.Errorf("%s: %w", s.name, err)
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			var n int64
			_ = conn.QueryRowContext(ctx, `SELECT count(*) FROM `+s.name).Scan(&n)
			total += n
			slog.Info("aggregate: rebuilt", "table", s.name, "rows", n, "took", time.Since(start).Round(time.Millisecond))
		}
		return nil
	}()
	run.Finish(total, err)
	return err
}
