// Command api serves the vulnviz analytics REST API.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vulnviz/internal/api"
	"vulnviz/internal/db"
)

func main() {
	addr := flag.String("addr", envOr("VULNVIZ_ADDR", ":8080"), "listen address")
	dsn := flag.String("database-url", "", "PostgreSQL DSN (default $DATABASE_URL)")
	migrate := flag.Bool("migrate", true, "apply schema migrations on start")
	flag.Parse()
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	conn, err := db.Open(ctx, *dsn, 2*time.Minute)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	defer conn.Close()
	if *migrate {
		if err := db.Migrate(ctx, conn); err != nil {
			slog.Error("migrate", "err", err)
			os.Exit(1)
		}
	}
	srv := &http.Server{Addr: *addr, Handler: api.New(conn).Handler(), ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 90 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	slog.Info("api listening", "addr", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
