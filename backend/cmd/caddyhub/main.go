// Command caddyhub runs the CaddyHub panel: a web UI and API that owns a
// structured config, generates a Caddyfile from it and applies it to Caddy
// through the admin API with validation and automatic rollback.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/app"
	"github.com/Krifmaz/CaddyHub/internal/apply"
	"github.com/Krifmaz/CaddyHub/internal/auth"
	"github.com/Krifmaz/CaddyHub/internal/caddy"
	"github.com/Krifmaz/CaddyHub/internal/generator"
	"github.com/Krifmaz/CaddyHub/internal/notify"
	"github.com/Krifmaz/CaddyHub/internal/registry"
	"github.com/Krifmaz/CaddyHub/internal/secrets"
	"github.com/Krifmaz/CaddyHub/internal/server"
	"github.com/Krifmaz/CaddyHub/internal/store"
	"github.com/Krifmaz/CaddyHub/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	healthcheck := flag.Bool("healthcheck", false, "probe the local panel and exit (for Docker HEALTHCHECK)")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	cfg := app.LoadConfig()
	if *healthcheck {
		os.Exit(probe(cfg.Listen))
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(cfg, log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfg app.Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	key, keySrc, err := secrets.LoadKey(cfg.SecretKey, cfg.SecretKeyFile, cfg.DataDir)
	if err != nil {
		return err
	}
	box, err := secrets.NewBox(key)
	if err != nil {
		return err
	}
	if keySrc == "generated" {
		log.Warn("using a generated secret key stored in the data dir; set CADDYHUB_SECRET_KEY to keep backups restorable on another host")
	}
	st, err := store.Open(cfg.Path("caddyhub.db"), box)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	if err := initialAdmin(cfg, st, log); err != nil {
		return err
	}

	runner := caddy.NewRunner(cfg.CaddyBin)
	admin := caddy.NewAdmin(cfg.CaddyAdmin)
	notifier := notify.New(st, log)

	var capsMu sync.RWMutex
	var caps registry.Capabilities
	getCaps := func() registry.Capabilities {
		capsMu.RLock()
		defer capsMu.RUnlock()
		return caps
	}
	detect := func(ctx context.Context) bool {
		c, err := runner.Capabilities(ctx)
		if err != nil {
			return false
		}
		capsMu.Lock()
		changed := caps.VersionS != c.VersionS || len(caps.Modules) != len(c.Modules)
		caps = c
		capsMu.Unlock()
		if changed {
			log.Info("detected caddy", "version", c.VersionS, "modules", len(c.Modules))
		}
		return true
	}

	pipeline := &apply.Pipeline{
		Store:     st,
		Validator: runner,
		Admin:     admin,
		Health:    &apply.DefaultHealth{Admin: admin, ProbeAddrs: cfg.ProbeAddrs, Settle: 500 * time.Millisecond},
		Secrets:   &secrets.Materializer{Dir: cfg.SecretsDir},
		Env: generator.Env{
			AdminListen:   cfg.AdminListen,
			AdminOrigins:  cfg.AdminOrigins,
			LogDir:        cfg.LogDir,
			PanelUpstream: cfg.PanelUpstream,
		},
		PersistPath: cfg.CaddyfilePath,
		Caps:        getCaps,
		Notify:      func(event, msg string) { notifier.Send(event, "CaddyHub: config not applied", msg) },
	}

	srv := server.New(server.Options{
		Store: st, Pipeline: pipeline, Runner: runner, Admin: admin, Notifier: notifier,
		Caps: getCaps, Log: log, UI: web.FS(), Version: version,
		SetupTok:  cfg.SetupToken,
		TrustXFF:  cfg.TrustProxyHeaders,
		SecureCk:  strings.HasPrefix(cfg.BaseURL, "https://"),
		DevNoAuth: cfg.DevNoAuth,
	})
	if cfg.DevNoAuth {
		log.Warn("CADDYHUB_DEV_NO_AUTH is set: the panel has NO authentication. Never use this in production.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Background jobs: Caddy capability detection and session cleanup.
	go func() {
		for !detect(ctx) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				detect(ctx)
				st.PruneSessions()
			}
		}
	}()

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      3 * time.Minute, // apply can take a while (validate + health check)
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("CaddyHub listening", "addr", cfg.Listen, "version", version, "data", cfg.DataDir)
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
	return nil
}

// initialAdmin creates an admin from CADDYHUB_INITIAL_ADMIN_USER/PASSWORD
// on an empty database (for unattended installs). Otherwise the UI's
// first-run setup creates it.
func initialAdmin(cfg app.Config, st *store.Store, log *slog.Logger) error {
	if st.UserCount() > 0 || cfg.InitialAdminUser == "" || cfg.InitialAdminPass == "" {
		return nil
	}
	if err := auth.PasswordPolicy(cfg.InitialAdminPass); err != nil {
		return fmt.Errorf("CADDYHUB_INITIAL_ADMIN_PASSWORD: %w", err)
	}
	h, err := auth.HashPassword(cfg.InitialAdminPass)
	if err != nil {
		return err
	}
	if _, err := st.SaveUser(store.User{Username: cfg.InitialAdminUser, PasswordHash: h, Role: auth.RoleAdmin}); err != nil {
		return err
	}
	log.Info("created initial admin from environment", "user", cfg.InitialAdminUser)
	return nil
}

func probe(listen string) int {
	addr := listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/api/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
