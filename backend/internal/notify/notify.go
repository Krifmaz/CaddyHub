// Package notify delivers alerts to webhooks and preset services.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strings"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/store"
)

// Events the panel emits.
const (
	EventApplyFailed     = "apply_failed"
	EventCertExpiring    = "cert_expiring"
	EventCertError       = "cert_error"
	EventUpstreamDown    = "upstream_down"
	EventUpstreamUp      = "upstream_up"
	EventUpdateAvailable = "update_available"
	EventBackupFailed    = "backup_failed"
	EventDiscovery       = "discovery"
)

// AllEvents lists events for the UI.
var AllEvents = []string{EventApplyFailed, EventCertExpiring, EventCertError, EventUpstreamDown, EventUpstreamUp, EventUpdateAvailable, EventBackupFailed, EventDiscovery}

// Types lists supported channel types and their config fields.
var Types = map[string][]string{
	"webhook": {"url", "header"},
	"ntfy":    {"url", "token", "priority"},
	"gotify":  {"url", "token", "priority"},
	"discord": {"url"},
	"slack":   {"url"},
	"email":   {"host", "port", "username", "password", "from", "to", "tls"},
}

// SecretFields are redacted in API responses.
var SecretFields = map[string]bool{"token": true, "password": true, "header": true, "url": false}

// Notifier fans out messages to channels.
type Notifier struct {
	Store  *store.Store
	Client *http.Client
	Log    *slog.Logger
}

// New creates a notifier.
func New(s *store.Store, log *slog.Logger) *Notifier {
	return &Notifier{Store: s, Client: &http.Client{Timeout: 15 * time.Second}, Log: log}
}

// Message is a notification.
type Message struct {
	Event   string    `json:"event"`
	Title   string    `json:"title"`
	Message string    `json:"message"`
	Time    time.Time `json:"time"`
}

// Send delivers asynchronously to subscribed, enabled channels.
func (n *Notifier) Send(event, title, msg string) {
	if n == nil || n.Store == nil {
		return
	}
	chans, err := n.Store.Channels()
	if err != nil {
		return
	}
	m := Message{Event: event, Title: title, Message: msg, Time: time.Now().UTC()}
	for _, c := range chans {
		if !c.Enabled || !subscribed(c.Events, event) {
			continue
		}
		go func(c store.Channel) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := n.Deliver(ctx, c, m); err != nil && n.Log != nil {
				n.Log.Warn("notification failed", "channel", c.Name, "type", c.Type, "err", err)
			}
		}(c)
	}
}

func subscribed(events []string, e string) bool {
	if len(events) == 0 {
		return true
	}
	for _, x := range events {
		if x == e || x == "*" {
			return true
		}
	}
	return false
}

// Test sends a test message synchronously.
func (n *Notifier) Test(ctx context.Context, c store.Channel) error {
	return n.Deliver(ctx, c, Message{Event: "test", Title: "CaddyHub test", Message: "If you can read this, notifications work.", Time: time.Now().UTC()})
}

// Deliver sends one message to one channel.
func (n *Notifier) Deliver(ctx context.Context, c store.Channel, m Message) error {
	cfg := c.Config
	switch c.Type {
	case "webhook":
		body, _ := json.Marshal(m)
		h := map[string]string{"Content-Type": "application/json"}
		if hv := cfg["header"]; hv != "" {
			if k, v, ok := strings.Cut(hv, ":"); ok {
				h[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		return n.post(ctx, cfg["url"], body, h)
	case "ntfy":
		h := map[string]string{"Title": m.Title, "Tags": tagFor(m.Event)}
		if p := cfg["priority"]; p != "" {
			h["Priority"] = p
		}
		if t := cfg["token"]; t != "" {
			h["Authorization"] = "Bearer " + t
		}
		return n.post(ctx, cfg["url"], []byte(m.Message), h)
	case "gotify":
		u, err := url.Parse(strings.TrimRight(cfg["url"], "/") + "/message")
		if err != nil {
			return err
		}
		pr := 5
		fmt.Sscanf(cfg["priority"], "%d", &pr)
		body, _ := json.Marshal(map[string]any{"title": m.Title, "message": m.Message, "priority": pr})
		return n.post(ctx, u.String(), body, map[string]string{"Content-Type": "application/json", "X-Gotify-Key": cfg["token"]})
	case "discord":
		body, _ := json.Marshal(map[string]string{"content": "**" + m.Title + "**\n" + m.Message})
		return n.post(ctx, cfg["url"], body, map[string]string{"Content-Type": "application/json"})
	case "slack":
		body, _ := json.Marshal(map[string]string{"text": "*" + m.Title + "*\n" + m.Message})
		return n.post(ctx, cfg["url"], body, map[string]string{"Content-Type": "application/json"})
	case "email":
		return sendMail(ctx, cfg, m)
	}
	return fmt.Errorf("unknown channel type %q", c.Type)
}

func tagFor(event string) string {
	switch event {
	case EventApplyFailed, EventCertError, EventUpstreamDown, EventBackupFailed:
		return "warning"
	case EventUpstreamUp:
		return "white_check_mark"
	case EventUpdateAvailable:
		return "package"
	}
	return "bell"
}

func (n *Notifier) post(ctx context.Context, u string, body []byte, h map[string]string) error {
	if u == "" {
		return fmt.Errorf("url is required")
	}
	pu, err := url.Parse(u)
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
		return fmt.Errorf("invalid url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := n.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func sendMail(ctx context.Context, cfg map[string]string, m Message) error {
	host, port := cfg["host"], cfg["port"]
	if port == "" {
		port = "587"
	}
	if host == "" || cfg["from"] == "" || cfg["to"] == "" {
		return fmt.Errorf("host, from and to are required")
	}
	to := strings.Split(cfg["to"], ",")
	for i := range to {
		to[i] = strings.TrimSpace(to[i])
	}
	msg := "From: " + cfg["from"] + "\r\nTo: " + strings.Join(to, ", ") + "\r\nSubject: [CaddyHub] " + sanitizeHeader(m.Title) +
		"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + m.Message + "\r\n"
	addr := net.JoinHostPort(host, port)
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if cfg["tls"] == "implicit" || port == "465" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok && cfg["tls"] != "none" && cfg["tls"] != "implicit" {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return err
		}
	}
	if cfg["username"] != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg["username"], cfg["password"], host)); err != nil {
			return err
		}
	}
	if err := c.Mail(cfg["from"]); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}
