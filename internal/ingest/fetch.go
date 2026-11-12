// Package ingest loads CVE records and distro advisories into PostgreSQL.
package ingest

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Client wraps HTTP access with a user agent and retry.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	TempDir   string
}

// NewClient builds a client with sane timeouts.
func NewClient() *Client {
	return &Client{
		HTTP: &http.Client{
			Timeout: 30 * time.Minute,
			Transport: &http.Transport{
				MaxIdleConns:        64,
				MaxIdleConnsPerHost: 64,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		UserAgent: "vulnviz-ingest/1.0 (+https://github.com/chainguard-dev)",
		TempDir:   os.TempDir(),
	}
}

func isRemote(u string) bool { return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") }

// Get fetches a URL body with retries. Small responses only.
func (c *Client) Get(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		req.Header.Set("Accept", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, ErrNotFound
		}
		if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("GET %s: %s", url, resp.Status)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
		}
		return body, nil
	}
	return nil, lastErr
}

// ErrNotFound is returned for HTTP 404.
var ErrNotFound = fmt.Errorf("not found")

// Download streams a URL (or copies a local path / file:// URL) to a temp file
// and returns its path. The caller removes it.
func (c *Client) Download(ctx context.Context, url string) (string, error) {
	if !isRemote(url) {
		p := strings.TrimPrefix(url, "file://")
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.CreateTemp(c.TempDir, "vulnviz-*"+filepath.Ext(url))
	if err != nil {
		return "", err
	}
	start := time.Now()
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	slog.Info("downloaded", "url", url, "bytes", n, "took", time.Since(start).Round(time.Second))
	return f.Name(), nil
}

// IsTemp reports whether Download produced a temp file (vs. returning a local path).
func (c *Client) IsTemp(path, url string) bool { return isRemote(url) }

// ExtractEntry copies one entry from a zip to a temp file (used for the
// nested cves.zip inside the CVE Program's release archive).
func (c *Client) ExtractEntry(zr *zip.ReadCloser, name string) (string, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		out, err := os.CreateTemp(c.TempDir, "vulnviz-*.zip")
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			os.Remove(out.Name())
			return "", err
		}
		out.Close()
		return out.Name(), nil
	}
	return "", fmt.Errorf("entry %q not found in archive", name)
}

// Entry is one file handed to a worker.
type Entry struct {
	Name string
	Data []byte
}

// WalkZip reads every matching file in the archive using a pool of readers
// and calls handle for each. handle runs concurrently and must be safe.
func WalkZip(ctx context.Context, zr *zip.ReadCloser, match func(name string) bool, workers int, handle func(Entry) error) (int64, error) {
	files := make(chan *zip.File, workers*4)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	var count int64
	var mu sync.Mutex
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range files {
				rc, err := f.Open()
				if err != nil {
					errs <- fmt.Errorf("%s: %w", f.Name, err)
					return
				}
				data, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					errs <- fmt.Errorf("%s: %w", f.Name, err)
					return
				}
				if err := handle(Entry{Name: f.Name, Data: data}); err != nil {
					errs <- err
					return
				}
				mu.Lock()
				count++
				mu.Unlock()
			}
		}()
	}
	var walkErr error
loop:
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !match(f.Name) {
			continue
		}
		select {
		case files <- f:
		case walkErr = <-errs:
			break loop
		case <-ctx.Done():
			walkErr = ctx.Err()
			break loop
		}
	}
	close(files)
	wg.Wait()
	if walkErr == nil {
		select {
		case walkErr = <-errs:
		default:
		}
	}
	return count, walkErr
}
