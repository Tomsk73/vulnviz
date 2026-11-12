package ingest

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"vulnviz/internal/config"
	"vulnviz/internal/ingestrun"
	"vulnviz/internal/osv"
)

// SyncDistros upserts the distro reference rows from config.
func SyncDistros(ctx context.Context, conn *sql.DB, cfg *config.Config) error {
	for i, d := range cfg.Distros {
		rules, _ := json.Marshal(d.Rules)
		if _, err := conn.ExecContext(ctx, `
			INSERT INTO distros (id, name, homepage, notes, sort_order, rules, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,now())
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, homepage=EXCLUDED.homepage, notes=EXCLUDED.notes,
			  sort_order=EXCLUDED.sort_order, rules=EXCLUDED.rules, updated_at=now()`,
			d.ID, d.Name, nullStr(d.Homepage), nullStr(d.Notes), i, string(rules)); err != nil {
			return err
		}
	}
	return nil
}

// staging holds the three COPY statements for a batch.
type staging struct {
	tx       *sql.Tx
	adv      *sql.Stmt
	advCVEs  *sql.Stmt
	advPkgs  *sql.Stmt
	ctx      context.Context
	rows     int64
	pkgRows  int64
	batchMax int
	buf      []*osv.Advisory
}

const stageDDL = `
CREATE TEMP TABLE adv_stage (LIKE advisories INCLUDING DEFAULTS) ON COMMIT DROP;
CREATE TEMP TABLE advc_stage (LIKE advisory_cves) ON COMMIT DROP;
CREATE TEMP TABLE advp_stage (LIKE advisory_packages) ON COMMIT DROP;`

func newStaging(ctx context.Context, tx *sql.Tx) (*staging, error) {
	if _, err := tx.ExecContext(ctx, stageDDL); err != nil {
		return nil, err
	}
	return &staging{tx: tx, ctx: ctx, batchMax: 2000}, nil
}

func (s *staging) add(a *osv.Advisory) error {
	s.buf = append(s.buf, a)
	if len(s.buf) >= s.batchMax {
		return s.flush()
	}
	return nil
}

// flush writes the buffered advisories with three COPY statements. lib/pq
// allows only one COPY at a time per connection, so they run back to back.
func (s *staging) flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	ctx := s.ctx
	st, err := s.tx.PrepareContext(ctx, pq.CopyIn("adv_stage", "distro", "id", "kind", "published", "modified", "withdrawn", "summary", "cvss_vector", "cvss_score", "severity", "has_fix", "fix_time", "fix_time_trusted"))
	if err != nil {
		return err
	}
	for _, a := range s.buf {
		var score any
		if a.CVSSScore >= 0 {
			score = a.CVSSScore
		}
		if _, err := st.ExecContext(ctx, a.Distro, a.ID, a.Kind, nullTime(a.Published), nullTime(a.Modified), nullTime(a.Withdrawn),
			nullStr(a.Summary), nullStr(a.CVSSVector), score, nullStr(a.Severity), a.HasFix, nullTime(a.FixTime), a.FixTimeTrusted); err != nil {
			return err
		}
	}
	if _, err := st.ExecContext(ctx); err != nil {
		return err
	}
	st.Close()

	st, err = s.tx.PrepareContext(ctx, pq.CopyIn("advc_stage", "distro", "advisory_id", "cve_id"))
	if err != nil {
		return err
	}
	for _, a := range s.buf {
		for _, c := range a.CVEs {
			if _, err := st.ExecContext(ctx, a.Distro, a.ID, c); err != nil {
				return err
			}
		}
	}
	if _, err := st.ExecContext(ctx); err != nil {
		return err
	}
	st.Close()

	st, err = s.tx.PrepareContext(ctx, pq.CopyIn("advp_stage", "distro", "advisory_id", "ecosystem", "package", "introduced", "fixed", "fix_time"))
	if err != nil {
		return err
	}
	for _, a := range s.buf {
		for _, p := range a.Packages {
			if _, err := st.ExecContext(ctx, a.Distro, a.ID, p.Ecosystem, p.Name, nullStr(p.Introduced), nullStr(p.Fixed), nullTime(p.FixTime)); err != nil {
				return err
			}
			s.pkgRows++
		}
	}
	if _, err := st.ExecContext(ctx); err != nil {
		return err
	}
	st.Close()
	s.rows += int64(len(s.buf))
	s.buf = s.buf[:0]
	return nil
}

// mergeReplace swaps a distro's advisories for the staged set.
func (s *staging) mergeReplace(distro string) error {
	ctx := s.ctx
	for _, q := range []string{
		`DELETE FROM advisory_packages WHERE distro=$1`,
		`DELETE FROM advisory_cves WHERE distro=$1`,
		`DELETE FROM advisories WHERE distro=$1`,
	} {
		if _, err := s.tx.ExecContext(ctx, q, distro); err != nil {
			return err
		}
	}
	return s.insertFromStage()
}

// mergeUpsert replaces only the staged advisory IDs (incremental mode).
func (s *staging) mergeUpsert() error {
	ctx := s.ctx
	for _, q := range []string{
		`DELETE FROM advisory_packages p USING (SELECT DISTINCT distro, id FROM adv_stage) a WHERE p.distro=a.distro AND p.advisory_id=a.id`,
		`DELETE FROM advisory_cves c USING (SELECT DISTINCT distro, id FROM adv_stage) a WHERE c.distro=a.distro AND c.advisory_id=a.id`,
		`DELETE FROM advisories x USING (SELECT DISTINCT distro, id FROM adv_stage) a WHERE x.distro=a.distro AND x.id=a.id`,
	} {
		if _, err := s.tx.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return s.insertFromStage()
}

func (s *staging) insertFromStage() error {
	ctx := s.ctx
	for _, q := range []string{
		`INSERT INTO advisories (distro, id, kind, published, modified, withdrawn, summary, cvss_vector, cvss_score, severity, has_fix, fix_time, fix_time_trusted, ingested_at)
		 SELECT DISTINCT ON (distro, id) distro, id, kind, published, modified, withdrawn, summary, cvss_vector, cvss_score, severity, has_fix, fix_time, fix_time_trusted, now()
		 FROM adv_stage ORDER BY distro, id, modified DESC NULLS LAST`,
		`INSERT INTO advisory_cves SELECT DISTINCT distro, advisory_id, cve_id FROM advc_stage`,
		`INSERT INTO advisory_packages (distro, advisory_id, ecosystem, package, introduced, fixed, fix_time)
		 SELECT DISTINCT distro, advisory_id, ecosystem, package, introduced, fixed, fix_time FROM advp_stage`,
	} {
		if _, err := s.tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("merge: %w", err)
		}
	}
	return nil
}

// LoadDistroBulk replaces a distro's advisories from its bulk zip source.
func LoadDistroBulk(ctx context.Context, conn *sql.DB, client *Client, d config.Distro) (int64, error) {
	run, err := ingestrun.Start(ctx, conn, d.ID, "full")
	if err != nil {
		return 0, err
	}
	n, err := loadDistroBulk(ctx, conn, client, d)
	run.Finish(n, err)
	return n, err
}

func loadDistroBulk(ctx context.Context, conn *sql.DB, client *Client, d config.Distro) (int64, error) {
	if d.Bulk == nil {
		return 0, fmt.Errorf("distro %s has no bulk source", d.ID)
	}
	slog.Info("osv: fetching bundle", "distro", d.ID, "url", d.Bulk.URL)
	p, err := client.Download(ctx, d.Bulk.URL)
	if err != nil {
		return 0, err
	}
	if client.IsTemp(p, d.Bulk.URL) {
		defer os.Remove(p)
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	st, err := newStaging(ctx, tx)
	if err != nil {
		return 0, err
	}
	var mu sync.Mutex
	var parseErrs int64
	start := time.Now()
	n, err := WalkZip(ctx, zr, func(name string) bool { return strings.HasSuffix(name, ".json") }, runtime.NumCPU(), func(e Entry) error {
		a, err := osv.Parse(e.Data, d)
		if err != nil || a.ID == "" {
			mu.Lock()
			parseErrs++
			mu.Unlock()
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if err := st.add(a); err != nil {
			return err
		}
		if st.rows > 0 && st.rows%200000 == 0 && len(st.buf) == 0 {
			slog.Info("osv: staged", "distro", d.ID, "records", st.rows, "elapsed", time.Since(start).Round(time.Second))
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if err := st.flush(); err != nil {
		return 0, err
	}
	slog.Info("osv: parsed", "distro", d.ID, "records", n, "packages", st.pkgRows, "parse_errors", parseErrs, "took", time.Since(start).Round(time.Second))
	if n == 0 {
		return 0, fmt.Errorf("distro %s: bundle contained no records; refusing to replace existing data", d.ID)
	}
	if err := st.mergeReplace(d.ID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	slog.Info("osv: replaced", "distro", d.ID, "records", n, "took", time.Since(start).Round(time.Second))
	return n, nil
}

type indexEntry struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// SyncDistroIncremental fetches the distro's index, compares modified
// timestamps with what is stored, and re-fetches only changed advisories.
func SyncDistroIncremental(ctx context.Context, conn *sql.DB, client *Client, d config.Distro, workers int) (int64, error) {
	run, err := ingestrun.Start(ctx, conn, d.ID, "incremental")
	if err != nil {
		return 0, err
	}
	n, err := syncDistroIncremental(ctx, conn, client, d, workers)
	run.Finish(n, err)
	return n, err
}

func syncDistroIncremental(ctx context.Context, conn *sql.DB, client *Client, d config.Distro, workers int) (int64, error) {
	if d.Incremental == nil {
		return 0, fmt.Errorf("distro %s has no incremental source", d.ID)
	}
	body, err := client.Get(ctx, d.Incremental.URL)
	if err != nil {
		return 0, fmt.Errorf("index: %w", err)
	}
	var index []indexEntry
	if err := json.Unmarshal(body, &index); err != nil {
		// Some feeds wrap the array: {"vulns": [...]}.
		var wrapped struct {
			Vulns []indexEntry `json:"vulns"`
		}
		if err2 := json.Unmarshal(body, &wrapped); err2 != nil || wrapped.Vulns == nil {
			return 0, fmt.Errorf("index: %w", err)
		}
		index = wrapped.Vulns
	}
	// Index entries with full records inline (some feeds ship them) are handled
	// the same way: we still fetch by ID for a uniform code path.

	existing := map[string]time.Time{}
	rows, err := conn.QueryContext(ctx, `SELECT id, COALESCE(modified, 'epoch'::timestamptz) FROM advisories WHERE distro=$1`, d.ID)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id string
		var mod time.Time
		if err := rows.Scan(&id, &mod); err != nil {
			rows.Close()
			return 0, err
		}
		existing[id] = mod
	}
	rows.Close()

	var todo []string
	for _, e := range index {
		mod, _ := time.Parse(time.RFC3339Nano, e.Modified)
		if cur, ok := existing[e.ID]; !ok || mod.After(cur.Add(time.Second)) {
			todo = append(todo, e.ID)
		}
	}
	slog.Info("osv: index compared", "distro", d.ID, "index", len(index), "stored", len(existing), "changed", len(todo))
	if len(todo) == 0 {
		return 0, nil
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	st, err := newStaging(ctx, tx)
	if err != nil {
		return 0, err
	}
	ids := make(chan string)
	results := make(chan *osv.Advisory, workers*2)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range ids {
				url := strings.ReplaceAll(d.Incremental.RecordURL, "{id}", id)
				data, err := client.Get(ctx, url)
				if err == ErrNotFound {
					continue
				}
				if err != nil {
					errs <- fmt.Errorf("%s: %w", id, err)
					return
				}
				a, err := osv.Parse(data, d)
				if err != nil {
					slog.Warn("osv: parse failed", "id", id, "err", err)
					continue
				}
				results <- a
			}
		}()
	}
	go func() {
		defer close(ids)
		for _, id := range todo {
			select {
			case ids <- id:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()

	var n int64
	start := time.Now()
	for a := range results {
		if err := st.add(a); err != nil {
			return 0, err
		}
		n++
		if n%5000 == 0 {
			slog.Info("osv: fetched", "distro", d.ID, "records", n, "of", len(todo), "elapsed", time.Since(start).Round(time.Second))
		}
	}
	select {
	case err := <-errs:
		return 0, err
	default:
	}
	if err := st.flush(); err != nil {
		return 0, err
	}
	if err := st.mergeUpsert(); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	slog.Info("osv: incremental merged", "distro", d.ID, "records", n, "took", time.Since(start).Round(time.Second))
	return n, nil
}
