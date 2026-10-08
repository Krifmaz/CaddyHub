package scan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
)

func TestHostsFindsWebApp(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title> My &amp; App </title></head></html>"))
	}))
	defer ts.Close()
	_, portS, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portS)

	targets, err := Resolve(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	found := Hosts(context.Background(), targets, Options{Ports: []int{port, 1}})
	if len(found) != 1 {
		t.Fatalf("found %+v", found)
	}
	f := found[0]
	if f.Scheme != "http" || f.Title != "My & App" || f.Guess != "My & App" || f.Upstream() != "127.0.0.1:"+portS {
		t.Fatalf("got %+v", f)
	}
}

func TestResolveRejectsPublic(t *testing.T) {
	for _, in := range []string{"8.8.8.8", "1.1.1.0/24", "10.0.0.0/16"} {
		if _, err := Resolve(context.Background(), in); err == nil {
			t.Errorf("%s should be rejected", in)
		}
	}
	ts, err := Resolve(context.Background(), "192.168.1.0/24")
	if err != nil || len(ts) != 254 {
		t.Fatalf("/24: %d %v", len(ts), err)
	}
	if !Allowed(netip.MustParseAddr("172.18.0.5")) {
		t.Error("docker range should be allowed")
	}
}

func TestShortName(t *testing.T) {
	if shortName("jellyfin.media_default.") != "jellyfin" {
		t.Fatal(shortName("jellyfin.media_default."))
	}
}
