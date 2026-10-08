// Package scan finds web apps on the local network so the UI can fill in a
// reverse-proxy upstream: it TCP-connects to common self-hosted app ports,
// identifies HTTP(S) services by their page title, and names Docker
// containers via reverse DNS. Only private addresses are ever scanned.
package scan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Ports are common ports of self-hosted apps, checked by default.
var Ports = []int{
	80, 81, 443, 1880, 2283, 2342, 3000, 3001, 3002, 3579, 4000, 4533, 5000, 5001, 5005, 5006, 5055,
	5076, 5173, 5678, 5690, 6767, 6789, 6875, 7474, 7575, 7878, 8000, 8001, 8006, 8008, 8080, 8081,
	8082, 8083, 8084, 8085, 8086, 8088, 8090, 8091, 8096, 8112, 8123, 8181, 8191, 8200, 8265, 8384,
	8443, 8686, 8787, 8800, 8880, 8888, 8920, 8989, 9000, 9001, 9080, 9090, 9091, 9117, 9200, 9443,
	9696, 9925, 10000, 11000, 13378, 19999, 32400, 61208,
}

// KnownPorts guesses the app behind a port when the page title doesn't say.
var KnownPorts = map[int]string{
	1880: "Node-RED", 2283: "Immich", 2342: "PhotoPrism", 3579: "Ombi", 4533: "Navidrome", 5055: "Overseerr / Jellyseerr",
	5076: "NZBHydra", 5690: "Wizarr", 6767: "Bazarr", 6875: "BookStack", 7878: "Radarr", 8006: "Proxmox VE",
	8096: "Jellyfin", 8112: "Deluge", 8123: "Home Assistant", 8181: "Tautulli", 8191: "FlareSolverr",
	8265: "Tdarr", 8384: "Syncthing", 8686: "Lidarr", 8787: "Readarr", 8920: "Jellyfin (HTTPS)", 8989: "Sonarr",
	9091: "Transmission", 9117: "Jackett", 9443: "Portainer", 9696: "Prowlarr", 9925: "Mealie",
	13378: "Audiobookshelf", 19999: "Netdata", 32400: "Plex", 61208: "Glances",
}

// Found is one open port.
type Found struct {
	Host   string `json:"host"`   // container name if known, else IP or the hostname given
	IP     string `json:"ip"`     // address that answered
	Port   int    `json:"port"`   // TCP port
	Scheme string `json:"scheme"` // "http", "https" or "" (not a web server)
	Title  string `json:"title,omitempty"`
	Server string `json:"server,omitempty"`
	Guess  string `json:"guess,omitempty"` // likely app name
}

// Upstream renders the value for a reverse-proxy upstream field.
func (f Found) Upstream() string {
	hp := net.JoinHostPort(f.Host, fmt.Sprint(f.Port))
	if f.Scheme == "https" {
		return "https://" + hp
	}
	return hp
}

// Options tune a scan.
type Options struct {
	Ports       []int
	DialTimeout time.Duration
	Concurrency int
	SkipIPs     map[netip.Addr]bool // e.g. the panel itself
}

func (o *Options) defaults() {
	if len(o.Ports) == 0 {
		o.Ports = Ports
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = 400 * time.Millisecond
	}
	if o.Concurrency == 0 {
		o.Concurrency = 512
	}
}

// ErrPublic is returned for targets outside private address space.
var ErrPublic = errors.New("only private network addresses (LAN, Docker) can be scanned")

// Allowed reports whether an address may be scanned.
func Allowed(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// target is one host to scan with its display name.
type target struct {
	name string
	ip   netip.Addr
}

// Resolve turns user input into scan targets: a hostname or container name,
// an IP, or a CIDR (at most /24). Every resolved address must be private.
func Resolve(ctx context.Context, input string) ([]target, error) {
	input = strings.TrimSpace(input)
	if p, err := netip.ParsePrefix(input); err == nil {
		p = p.Masked()
		if !p.Addr().Is4() || p.Bits() < 24 {
			return nil, errors.New("scan at most a /24 IPv4 range, e.g. 10.0.1.0/24")
		}
		if !Allowed(p.Addr()) {
			return nil, ErrPublic
		}
		var out []target
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if b := a.As4(); b[3] == 0 || b[3] == 255 {
				continue
			}
			out = append(out, target{name: a.String(), ip: a})
		}
		return out, nil
	}
	if a, err := netip.ParseAddr(input); err == nil {
		if !Allowed(a) {
			return nil, ErrPublic
		}
		return []target{{name: a.String(), ip: a.Unmap()}}, nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", input)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("can't find %q on the network", input)
	}
	for _, a := range ips {
		if !Allowed(a) {
			return nil, ErrPublic
		}
	}
	return []target{{name: input, ip: ips[0].Unmap()}}, nil
}

// LocalNetworks returns the /24 around each private IPv4 address of this
// machine (in Docker: the networks the panel container is attached to).
func LocalNetworks() (nets []netip.Prefix, self map[netip.Addr]bool) {
	self = map[netip.Addr]bool{}
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			a, ok := netip.AddrFromSlice(ipn.IP)
			if !ok || !a.Unmap().Is4() || !a.IsPrivate() {
				continue
			}
			a = a.Unmap()
			self[a] = true
			p, _ := a.Prefix(24)
			dup := false
			for _, n := range nets {
				dup = dup || n == p
			}
			if !dup {
				nets = append(nets, p)
			}
		}
	}
	return nets, self
}

// Network scans the local networks. Inside Docker, live containers are found
// through reverse DNS first, so only real hosts are port-scanned.
func Network(ctx context.Context, o Options) ([]Found, error) {
	nets, self := LocalNetworks()
	if len(nets) == 0 {
		return nil, errors.New("no private network found to scan; enter an IP or range instead")
	}
	if o.SkipIPs == nil {
		o.SkipIPs = map[netip.Addr]bool{}
	}
	for a := range self {
		o.SkipIPs[a] = true
	}
	// Look up every network in parallel; Docker's DNS answers instantly,
	// other resolvers may take up to the lookup timeout.
	var mu sync.Mutex
	var wg sync.WaitGroup
	var targets []target
	for _, n := range nets {
		wg.Add(1)
		go func(n netip.Prefix) {
			defer wg.Done()
			ts, _ := Resolve(ctx, n.String())
			named := lookupNames(ctx, ts)
			mu.Lock()
			defer mu.Unlock()
			targets = append(targets, named...)
			if gw := n.Addr().Next(); !o.SkipIPs[gw] {
				targets = append(targets, target{name: gw.String(), ip: gw})
			}
		}(n)
	}
	wg.Wait()
	return Hosts(ctx, targets, o), nil
}

// lookupNames returns the targets that have a PTR record, named by it.
func lookupNames(ctx context.Context, ts []target) []target {
	var mu sync.Mutex
	var out []target
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256)
	for _, t := range ts {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(lctx, t.ip.String())
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			out = append(out, target{name: shortName(names[0]), ip: t.ip})
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return out
}

// shortName turns Docker's "jellyfin.mystack_default." into "jellyfin".
func shortName(n string) string {
	n = strings.TrimSuffix(n, ".")
	if i := strings.IndexByte(n, '.'); i > 0 {
		return n[:i]
	}
	return n
}

// Hosts scans the given targets and identifies web servers.
func Hosts(ctx context.Context, targets []target, o Options) []Found {
	o.defaults()
	type job struct {
		t    target
		port int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var found []Found
	var wg sync.WaitGroup
	workers := o.Concurrency
	if n := len(targets) * len(o.Ports); n < workers {
		workers = n
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: o.DialTimeout}
			for j := range jobs {
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.t.ip.String(), fmt.Sprint(j.port)))
				if err != nil {
					continue
				}
				conn.Close()
				f := Found{Host: j.t.name, IP: j.t.ip.String(), Port: j.port}
				identify(ctx, &f)
				mu.Lock()
				found = append(found, f)
				mu.Unlock()
			}
		}()
	}
feed:
	for _, t := range targets {
		if o.SkipIPs[t.ip] {
			continue
		}
		for _, p := range o.Ports {
			select {
			case jobs <- job{t, p}:
			case <-ctx.Done():
				break feed
			}
		}
	}
	close(jobs)
	wg.Wait()
	sort.Slice(found, func(i, j int) bool {
		if (found[i].Scheme != "") != (found[j].Scheme != "") {
			return found[i].Scheme != "" // web servers first
		}
		if found[i].Host != found[j].Host {
			return found[i].Host < found[j].Host
		}
		return found[i].Port < found[j].Port
	})
	return found
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// identify checks whether the port speaks HTTP or HTTPS and reads the title.
func identify(ctx context.Context, f *Found) {
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // self-signed apps are normal on a LAN
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	order := []string{"http", "https"}
	if f.Port == 443 || f.Port == 8443 || f.Port == 9443 || f.Port == 8006 || f.Port == 8920 {
		order = []string{"https", "http"}
	}
	for _, scheme := range order {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(f.IP, fmt.Sprint(f.Port))+"/", nil)
		req.Header.Set("User-Agent", "CaddyHub-scan")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusBadRequest && scheme == "http" && strings.Contains(strings.ToLower(string(body)), "https") {
			continue // "plain HTTP request sent to HTTPS port"
		}
		f.Scheme = scheme
		f.Server = resp.Header.Get("Server")
		if m := titleRe.FindSubmatch(body); m != nil {
			f.Title = strings.Join(strings.Fields(htmlUnescape(string(m[1]))), " ")
			if len(f.Title) > 80 {
				f.Title = f.Title[:80]
			}
		}
		break
	}
	f.Guess = guess(*f)
}

func guess(f Found) string {
	if f.Title != "" && !strings.EqualFold(f.Title, "index") {
		return f.Title
	}
	if g, ok := KnownPorts[f.Port]; ok {
		return g
	}
	if f.Host != f.IP {
		return f.Host
	}
	return ""
}

var unescaper = strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&nbsp;", " ")

func htmlUnescape(s string) string { return unescaper.Replace(s) }
