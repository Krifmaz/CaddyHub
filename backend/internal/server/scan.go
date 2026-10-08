package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/scan"
)

var scanMu sync.Mutex

type scanResult struct {
	scan.Found
	Upstream string `json:"upstream"`
}

// handleScan finds web apps for the upstream "quick fill". With an empty
// target it scans the networks the panel is attached to; otherwise a
// hostname, IP or /24 range. Private addresses only, one scan at a time.
func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if r.ContentLength > 0 && !readJSON(w, r, &req) {
		return
	}
	if !scanMu.TryLock() {
		writeErr(w, http.StatusTooManyRequests, "a scan is already running; try again in a few seconds")
		return
	}
	defer scanMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	var found []scan.Found
	var err error
	target := strings.TrimSpace(req.Target)
	if target == "" {
		found, err = scan.Network(ctx, scan.Options{})
	} else {
		ts, rerr := scan.Resolve(ctx, target)
		if rerr != nil {
			err = rerr
		} else {
			o := scan.Options{}
			if len(ts) > 1 { // a range: most addresses are empty, so fail fast
				o.DialTimeout, o.Concurrency = 250*time.Millisecond, 1024
			}
			found = scan.Hosts(ctx, ts, o)
		}
	}
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, scan.ErrPublic) {
			code = http.StatusForbidden
		}
		writeErr(w, code, err.Error())
		return
	}
	out := make([]scanResult, 0, len(found))
	for _, f := range found {
		out = append(out, scanResult{Found: f, Upstream: f.Upstream()})
	}
	s.audit(r, "scan", firstNonEmptyStr(target, "local networks"), "")
	writeJSON(w, http.StatusOK, map[string]any{"results": out, "timed_out": ctx.Err() != nil})
}

func firstNonEmptyStr(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
