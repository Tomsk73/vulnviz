package ingest

import (
	"archive/zip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"vulnviz/internal/config"
	"vulnviz/internal/cve"
	"vulnviz/internal/ingestrun"
)

type release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

// LatestCVEBundleURL asks the GitHub releases API for the newest
// "all CVEs at midnight" archive.
func (c *Client) LatestCVEBundleURL(ctx context.Context, releasesAPI string) (string, error) {
	body, err := c.Get(ctx, strings.TrimSuffix(releasesAPI, "/")+"/latest")
	if err != nil {
		return "", fmt.Errorf("list releases: %w", err)
	}
	var r release
	if err := json.Unmarshal(body, &r); err != nil {
		return "", err
	}
	for _, a := range r.Assets {
		if strings.Contains(a.Name, "all_CVEs_at_midnight") {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("release %s has no all_CVEs_at_midnight asset", r.TagName)
}

// LoadCVEs ingests the full CVE list archive (outer zip containing cves.zip,
// which contains cves/<year>/<block>/CVE-*.json) and upserts every record.
func LoadCVEs(ctx context.Context, conn *sql.DB, client *Client, cfg config.CVESource) (int64, error) {
	run, err := ingestrun.Start(ctx, conn, "cve", "full")
	if err != nil {
		return 0, err
	}
	n, err := loadCVEs(ctx, conn, client, cfg)
	run.Finish(n, err)
	return n, err
}

func loadCVEs(ctx context.Context, conn *sql.DB, client *Client, cfg config.CVESource) (int64, error) {
	url := cfg.BulkURL
	if url == "" {
		var err error
		if url, err = client.LatestCVEBundleURL(ctx, cfg.ReleasesAPI); err != nil {
			return 0, err
		}
	}
	slog.Info("cve: fetching bundle", "url", url)
	outerPath, err := client.Download(ctx, url)
	if err != nil {
		return 0, err
	}
	if client.IsTemp(outerPath, url) {
		defer os.Remove(outerPath)
	}
	zr, err := zip.OpenReader(outerPath)
	if err != nil {
		return 0, err
	}
	innerPath := outerPath
	// The release asset is a zip containing cves.zip; a plain cves.zip or an
	// unpacked layout also works.
	if len(zr.File) == 1 && strings.HasSuffix(zr.File[0].Name, ".zip") {
		innerPath, err = client.ExtractEntry(zr, zr.File[0].Name)
		zr.Close()
		if err != nil {
			return 0, err
		}
		defer os.Remove(innerPath)
		if zr, err = zip.OpenReader(innerPath); err != nil {
			return 0, err
		}
	}
	defer zr.Close()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE cves_stage (LIKE cves INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
		return 0, err
	}
	cols := []string{"id", "state", "published", "reserved", "updated", "assigner", "title", "description", "cwes", "cvss_score", "cvss_version", "cvss_vector", "cvss_source", "severity", "kev", "metrics"}
	stmt, err := tx.PrepareContext(ctx, pq.CopyIn("cves_stage", cols...))
	if err != nil {
		return 0, err
	}

	var mu sync.Mutex // serialises COPY writes
	var parseErrs int64
	start := time.Now()
	n, err := WalkZip(ctx, zr, func(name string) bool {
		base := path.Base(name)
		return strings.HasPrefix(base, "CVE-") && strings.HasSuffix(base, ".json")
	}, runtime.NumCPU(), func(e Entry) error {
		rec, err := cve.Parse(e.Data)
		if err != nil || rec.ID == "" {
			mu.Lock()
			parseErrs++
			mu.Unlock()
			return nil
		}
		metrics, _ := json.Marshal(rec.Metrics)
		var score, version, vector, source any
		if rec.Chosen != nil {
			score, version, vector, source = rec.Chosen.Score, rec.Chosen.Version, nullStr(rec.Chosen.Vector), rec.Chosen.Source
		}
		mu.Lock()
		defer mu.Unlock()
		_, err = stmt.ExecContext(ctx, rec.ID, rec.State, nullTime(rec.Published), nullTime(rec.Reserved), nullTime(rec.Updated),
			nullStr(rec.Assigner), nullStr(rec.Title), nullStr(rec.Description), pq.Array(nonNil(rec.CWEs)), score, version, vector, source,
			rec.Severity(), rec.KEV, string(metrics))
		return err
	})
	if err != nil {
		return 0, err
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		return 0, fmt.Errorf("flush copy: %w", err)
	}
	stmt.Close()
	slog.Info("cve: parsed", "records", n, "parse_errors", parseErrs, "took", time.Since(start).Round(time.Second))

	res, err := tx.ExecContext(ctx, `
		INSERT INTO cves (id, state, published, reserved, updated, assigner, title, description, cwes,
		                  cvss_score, cvss_version, cvss_vector, cvss_source, severity, kev, metrics, ingested_at)
		SELECT DISTINCT ON (id) id, state, published, reserved, updated, assigner, title, description, cwes,
		       cvss_score, cvss_version, cvss_vector, cvss_source, severity, kev, metrics, now()
		FROM cves_stage ORDER BY id, updated DESC NULLS LAST
		ON CONFLICT (id) DO UPDATE SET
		  state=EXCLUDED.state, published=EXCLUDED.published, reserved=EXCLUDED.reserved, updated=EXCLUDED.updated,
		  assigner=EXCLUDED.assigner, title=EXCLUDED.title, description=EXCLUDED.description, cwes=EXCLUDED.cwes,
		  cvss_score=EXCLUDED.cvss_score, cvss_version=EXCLUDED.cvss_version, cvss_vector=EXCLUDED.cvss_vector,
		  cvss_source=EXCLUDED.cvss_source, severity=EXCLUDED.severity, kev=EXCLUDED.kev, metrics=EXCLUDED.metrics,
		  ingested_at=now()
		WHERE cves.updated IS DISTINCT FROM EXCLUDED.updated OR cves.severity <> EXCLUDED.severity`)
	if err != nil {
		return 0, fmt.Errorf("merge: %w", err)
	}
	changed, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	slog.Info("cve: merged", "upserted", changed, "took", time.Since(start).Round(time.Second))
	return n, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
