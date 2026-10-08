package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/model"
)

// reachResult says whether an upstream accepts TCP connections.
type reachResult struct {
	Upstream string `json:"upstream"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

// upstreamAddr turns "https://host:port", "host:port" or "host" into host:port.
func upstreamAddr(u string) string {
	u = strings.TrimSpace(u)
	scheme := ""
	if i := strings.Index(u, "://"); i >= 0 {
		scheme = u[:i]
		if pu, err := url.Parse(u); err == nil {
			u = pu.Host
		}
	}
	if _, _, err := net.SplitHostPort(u); err == nil {
		return u
	}
	if scheme == "https" {
		return net.JoinHostPort(u, "443")
	}
	return net.JoinHostPort(u, "80")
}

// explainDial turns a dial error into advice a non-expert can act on.
func explainDial(addr string, err error) string {
	host, _, _ := net.SplitHostPort(addr)
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return "name “" + host + "” not found. If it's a Docker container, Caddy and CaddyHub must share a Docker network with it (or use the server's IP and published port instead)"
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
		return "found " + host + ", but nothing is listening on that port. Check the port number and that the app is running"
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "timeout"):
		return "no answer from " + host + " (wrong IP, app stopped, or a firewall)"
	}
	return err.Error()
}

// handleReach tests every proxy upstream of every site from the panel. The
// panel shares Caddy's networks in the shipped compose files, so this tells
// whether Caddy can reach the app; Caddy's own counters can't (they stay at
// zero unless health checks are configured).
func (s *Server) handleReach(w http.ResponseWriter, r *http.Request) {
	sites, err := s.Store.Sites()
	if err != nil {
		storeErr(w, err)
		return
	}
	seen := map[string]bool{}
	var ups []string
	add := func(p *model.ProxyConfig) {
		if p == nil {
			return
		}
		for _, u := range p.Upstreams {
			if u = strings.TrimSpace(u); u != "" && !seen[u] && !strings.HasPrefix(u, "unix/") {
				seen[u] = true
				ups = append(ups, u)
			}
		}
	}
	for _, st := range sites {
		if !st.Enabled {
			continue
		}
		add(st.Config.Proxy)
		for _, rt := range st.Config.Routes {
			add(rt.Proxy)
		}
	}
	out := make([]reachResult, len(ups))
	var wg sync.WaitGroup
	for i, u := range ups {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			addr := upstreamAddr(u)
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
			defer cancel()
			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				out[i] = reachResult{Upstream: u, Error: explainDial(addr, err)}
				return
			}
			conn.Close()
			out[i] = reachResult{Upstream: u, OK: true}
		}(i, u)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, out)
}
