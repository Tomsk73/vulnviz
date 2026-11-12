// Package ingestrun records ingest job executions in the database.
package ingestrun

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Run is one row in ingest_runs.
type Run struct {
	ID      int64
	conn    *sql.DB
	started time.Time
}

// Start inserts a running row.
func Start(ctx context.Context, conn *sql.DB, source, mode string) (*Run, error) {
	r := &Run{conn: conn, started: time.Now()}
	err := conn.QueryRowContext(ctx, `INSERT INTO ingest_runs (source, mode) VALUES ($1,$2) RETURNING id`, source, mode).Scan(&r.ID)
	return r, err
}

// Finish marks the row done or failed.
func (r *Run) Finish(records int64, err error) {
	status, detail := "ok", fmt.Sprintf("%d records in %s", records, time.Since(r.started).Round(time.Second))
	if err != nil {
		status, detail = "failed", err.Error()
	}
	_, _ = r.conn.ExecContext(context.Background(), `UPDATE ingest_runs SET finished_at=now(), status=$2, records=$3, detail=$4 WHERE id=$1`, r.ID, status, records, detail)
}
