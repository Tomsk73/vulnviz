// Command ingest loads CVE records and distribution advisories into the
// vulnviz database and rebuilds the derived analytics tables.
//
//	ingest cve                  full CVE list load (latest cve.org release)
//	ingest advisories [ids...]  bulk load of every (or the named) distro(s)
//	ingest sync [ids...]        incremental refresh where the distro has an index feed
//	ingest aggregate            rebuild fact tables and monthly roll-ups
//	ingest all                  cve + advisories + aggregate
//	ingest migrate              apply schema migrations only
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vulnviz/internal/aggregate"
	"vulnviz/internal/config"
	"vulnviz/internal/db"
	"vulnviz/internal/ingest"
)

func main() {
	cfgPath := flag.String("config", envOr("VULNVIZ_CONFIG", "configs/sources.yaml"), "path to sources.yaml")
	dsn := flag.String("database-url", "", "PostgreSQL DSN (default $DATABASE_URL)")
	workers := flag.Int("fetch-workers", 32, "concurrent record fetches for incremental sync")
	tempDir := flag.String("temp-dir", envOr("VULNVIZ_TEMP", os.TempDir()), "scratch directory for downloads")
	skipAgg := flag.Bool("no-aggregate", false, "do not rebuild derived tables after loading")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ingest [flags] <cve|advisories|sync|aggregate|all|migrate> [distro ids...]")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	conn, err := db.Open(ctx, *dsn, 2*time.Minute)
	if err != nil {
		fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(ctx, conn); err != nil {
		fatal(fmt.Errorf("migrate: %w", err))
	}
	if err := ingest.SyncDistros(ctx, conn, cfg); err != nil {
		fatal(err)
	}
	client := ingest.NewClient()
	client.TempDir = *tempDir

	cmd, args := flag.Arg(0), flag.Args()[1:]
	selected := func() []config.Distro {
		var out []config.Distro
		for _, d := range cfg.Distros {
			if len(args) == 0 && !d.IsEnabled() {
				continue
			}
			if len(args) > 0 && !contains(args, d.ID) {
				continue
			}
			out = append(out, d)
		}
		for _, a := range args {
			if _, ok := cfg.Find(a); !ok {
				fatal(fmt.Errorf("unknown distro %q", a))
			}
		}
		return out
	}

	var failed bool
	switch cmd {
	case "migrate":
		slog.Info("migrations applied")
		return
	case "cve":
		if _, err := ingest.LoadCVEs(ctx, conn, client, cfg.CVE); err != nil {
			fatal(err)
		}
	case "advisories":
		for _, d := range selected() {
			if _, err := ingest.LoadDistroBulk(ctx, conn, client, d); err != nil {
				slog.Error("bulk load failed", "distro", d.ID, "err", err)
				failed = true
			}
		}
	case "sync":
		for _, d := range selected() {
			if d.Incremental == nil {
				slog.Info("no incremental source; using bulk", "distro", d.ID)
				if _, err := ingest.LoadDistroBulk(ctx, conn, client, d); err != nil {
					slog.Error("bulk load failed", "distro", d.ID, "err", err)
					failed = true
				}
				continue
			}
			if _, err := ingest.SyncDistroIncremental(ctx, conn, client, d, *workers); err != nil {
				slog.Error("incremental sync failed", "distro", d.ID, "err", err)
				failed = true
			}
		}
	case "aggregate":
		*skipAgg = false
	case "all":
		if _, err := ingest.LoadCVEs(ctx, conn, client, cfg.CVE); err != nil {
			fatal(err)
		}
		for _, d := range selected() {
			if _, err := ingest.LoadDistroBulk(ctx, conn, client, d); err != nil {
				slog.Error("bulk load failed", "distro", d.ID, "err", err)
				failed = true
			}
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
	if !*skipAgg {
		if err := aggregate.Rebuild(ctx, conn); err != nil {
			fatal(err)
		}
	}
	if failed {
		os.Exit(1)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(err error) {
	slog.Error(err.Error())
	os.Exit(1)
}
