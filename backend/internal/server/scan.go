package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
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
	var scanned []string
	target := strings.TrimSpace(req.Target)
	if target == "" {
		found, scanned, err = s.scanEverywhere(ctx, r)
	} else {
		scanned = []string{target}
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
		if f.Source == "" {
			f.Source = "lan"
		}
		out = append(out, scanResult{Found: f, Upstream: f.Upstream()})
	}
	s.audit(r, "scan", firstNonEmptyStr(target, "local networks"), "")
	writeJSON(w, http.StatusOK, map[string]any{"results": out, "scanned": scanned, "timed_out": ctx.Err() != nil})
}

// lanRanges are the LAN ranges to scan by default: the configured ones, plus
// the /24 of the address the panel was opened at when that's a private IP
// (e.g. http://10.0.1.5:8080 -> 10.0.1.0/24). That address is the Docker
// host, so its published ports are found too.
func (s *Server) lanRanges(r *http.Request) (ranges []netip.Prefix, hostIP netip.Addr) {
	seen := map[netip.Prefix]bool{}
	add := func(p netip.Prefix) {
		if p = p.Masked(); !seen[p] && p.Addr().Is4() && p.Bits() >= 24 && scan.Allowed(p.Addr()) {
			seen[p] = true
			ranges = append(ranges, p)
		}
	}
	for _, c := range s.Store.Settings().ScanRanges {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			add(p)
		} else if a, err := netip.ParseAddr(strings.TrimSpace(c)); err == nil {
			add(netip.PrefixFrom(a, 32))
		}
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && a.Is4() && a.IsPrivate() {
		hostIP = a
		p, _ := a.Prefix(24)
		add(p)
	}
	return ranges, hostIP
}

// scanEverywhere scans the Docker networks and the LAN in parallel.
func (s *Server) scanEverywhere(ctx context.Context, r *http.Request) ([]scan.Found, []string, error) {
	lan, hostIP := s.lanRanges(r)
	covered := false
	for _, p := range lan {
		covered = covered || (hostIP.IsValid() && p.Contains(hostIP))
	}
	var docker, onLAN []scan.Found
	var dockerErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		docker, dockerErr = scan.Network(ctx, scan.Options{}, covered)
	}()
	go func() {
		defer wg.Done()
		for _, p := range lan {
			ts, err := scan.Resolve(ctx, p.String())
			if err != nil {
				continue
			}
			onLAN = append(onLAN, scan.Hosts(ctx, ts, scan.Options{DialTimeout: 250 * time.Millisecond, Concurrency: 1024})...)
		}
		scan.NameResults(ctx, onLAN)
	}()
	wg.Wait()

	scanned := []string{}
	if dockerErr == nil {
		scanned = append(scanned, "Docker networks")
	}
	for _, p := range lan {
		scanned = append(scanned, p.String())
	}
	if dockerErr != nil && len(lan) == 0 {
		return nil, nil, dockerErr
	}
	seen := map[string]bool{}
	var out []scan.Found
	for _, list := range []struct {
		src string
		fs  []scan.Found
	}{{"docker", docker}, {"lan", onLAN}} {
		for _, f := range list.fs {
			k := f.IP + ":" + strconv.Itoa(f.Port)
			if seen[k] {
				continue
			}
			seen[k] = true
			f.Source = list.src
			out = append(out, f)
		}
	}
	return out, scanned, nil
}

func firstNonEmptyStr(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
