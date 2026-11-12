package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Server holds the database handle and a small response cache.
type Server struct {
	db    *sql.DB
	cache struct {
		sync.Mutex
		stamp   time.Time
		checked time.Time
		items   map[string]cached
	}
}

type cached struct {
	body  []byte
	stamp time.Time
}

// New builds a Server.
func New(conn *sql.DB) *Server {
	s := &Server{db: conn}
	s.cache.items = map[string]cached{}
	return s
}

// Handler returns the HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := s.db.PingContext(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ready"))
	})
	mux.HandleFunc("GET /api/v1/distros", s.cachedJSON(func(ctx context.Context, r *http.Request) (any, error) { return s.distros(ctx) }))
	mux.HandleFunc("GET /api/v1/status", s.json(func(ctx context.Context, r *http.Request) (any, error) { return s.status(ctx) }))
	mux.HandleFunc("GET /api/v1/ecosystems", s.cachedJSON(func(ctx context.Context, r *http.Request) (any, error) {
		d := r.URL.Query().Get("distro")
		if d == "" {
			return nil, badRequest("distro is required")
		}
		return s.ecosystems(ctx, d)
	}))
	mux.HandleFunc("GET /api/v1/fixes/monthly", s.analytics(func(ctx context.Context, p params) (any, error) { return s.fixesMonthly(ctx, p) }))
	mux.HandleFunc("GET /api/v1/mttr/monthly", s.analytics(func(ctx context.Context, p params) (any, error) { return s.mttrMonthly(ctx, p) }))
	mux.HandleFunc("GET /api/v1/mttr/summary", s.analytics(func(ctx context.Context, p params) (any, error) { return s.mttrSummary(ctx, p) }))
	mux.HandleFunc("GET /api/v1/mttr/distribution", s.analytics(func(ctx context.Context, p params) (any, error) { return s.mttrDistribution(ctx, p) }))
	mux.HandleFunc("GET /api/v1/backlog", s.analytics(func(ctx context.Context, p params) (any, error) { return s.backlog(ctx, p) }))
	mux.HandleFunc("GET /api/v1/cves/monthly", s.analytics(func(ctx context.Context, p params) (any, error) { return s.cvesMonthly(ctx, p) }))
	mux.HandleFunc("GET /api/v1/cve/{id}", s.cachedJSON(func(ctx context.Context, r *http.Request) (any, error) {
		id := strings.ToUpper(strings.TrimSpace(r.PathValue("id")))
		d, err := s.cveDetail(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, notFound("CVE not found")
		}
		return d, err
	}))
	return logging(mux)
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }
func badRequest(m string) error  { return httpError{http.StatusBadRequest, m} }
func notFound(m string) error    { return httpError{http.StatusNotFound, m} }

type handlerFn func(ctx context.Context, r *http.Request) (any, error)

func (s *Server) json(fn handlerFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		v, err := fn(ctx, r)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": v})
	}
}

// analytics parses the shared params and wraps the response with them.
func (s *Server) analytics(fn func(ctx context.Context, p params) (any, error)) http.HandlerFunc {
	return s.cachedJSON(func(ctx context.Context, r *http.Request) (any, error) {
		p, err := parseParams(r)
		if err != nil {
			return nil, badRequest(err.Error())
		}
		v, err := fn(ctx, p)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"rows": v,
			"params": map[string]any{
				"distros": p.Distros, "from": p.From.Format("2006-01"), "to": p.To.AddDate(0, -1, 0).Format("2006-01"),
				"severity": p.Severities, "unit": p.Unit, "basis": p.Basis, "ecosystem": p.Ecosystem, "trusted": p.Trusted, "scope": map[bool]string{true: "recent", false: "all"}[p.Recent],
			},
		}, nil
	})
}

// dataStamp returns the time of the last successful aggregate rebuild; the
// cache is invalidated whenever it changes. The lookup itself is rate-limited.
func (s *Server) dataStamp(ctx context.Context) time.Time {
	s.cache.Lock()
	defer s.cache.Unlock()
	if time.Since(s.cache.checked) < 15*time.Second {
		return s.cache.stamp
	}
	var t sql.NullTime
	_ = s.db.QueryRowContext(ctx, `SELECT max(finished_at) FROM ingest_runs WHERE status='ok'`).Scan(&t)
	s.cache.checked = time.Now()
	if t.Valid && !t.Time.Equal(s.cache.stamp) {
		s.cache.stamp = t.Time
		s.cache.items = map[string]cached{}
	}
	return s.cache.stamp
}

func (s *Server) cachedJSON(fn handlerFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		key := r.URL.RequestURI()
		stamp := s.dataStamp(ctx)
		s.cache.Lock()
		c, ok := s.cache.items[key]
		s.cache.Unlock()
		if ok && c.stamp.Equal(stamp) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Cache", "hit")
			w.Write(c.body)
			return
		}
		v, err := fn(ctx, r)
		if err != nil {
			writeErr(w, err)
			return
		}
		body, err := json.Marshal(map[string]any{"data": v, "data_as_of": stamp})
		if err != nil {
			writeErr(w, err)
			return
		}
		s.cache.Lock()
		if len(s.cache.items) > 2000 {
			s.cache.items = map[string]cached{}
		}
		s.cache.items[key] = cached{body: body, stamp: stamp}
		s.cache.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cache", "miss")
		w.Write(body)
	}
}

func writeErr(w http.ResponseWriter, err error) {
	var he httpError
	if errors.As(err, &he) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(he.code)
		json.NewEncoder(w).Encode(map[string]string{"error": he.msg})
		return
	}
	slog.Error("request failed", "err", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		slog.Info("http", "method", r.Method, "path", r.URL.RequestURI(), "status", sw.code, "took", time.Since(start).Round(time.Millisecond))
	})
}
