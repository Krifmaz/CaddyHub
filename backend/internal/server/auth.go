package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Krifmaz/CaddyHub/internal/auth"
	"github.com/Krifmaz/CaddyHub/internal/store"
)

type meResponse struct {
	User          *store.User `json:"user"`
	CSRF          string      `json:"csrf,omitempty"`
	Pending2FA    bool        `json:"pending_2fa"`
	NeedsSetup    bool        `json:"needs_setup"`
	SetupToken    bool        `json:"setup_token_required"`
	SetupComplete bool        `json:"setup_complete"`
	Version       string      `json:"version"`
}

// handleMe reports who is logged in. It never fails with 401 so the UI can
// decide between the setup wizard, the login form and the app.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	res := meResponse{
		NeedsSetup:    s.Store.UserCount() == 0,
		SetupToken:    s.SetupTok != "",
		SetupComplete: s.Store.Settings().SetupComplete,
		Version:       s.Version,
	}
	if p, err := s.authenticate(r); err == nil {
		u := p.User
		res.User = &u
		if p.Session != nil {
			res.CSRF = p.Session.CSRF
			res.Pending2FA = p.Session.Pending2FA
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// handleSetup creates the first admin account. It only works while no user
// exists, and requires the setup token when one is configured.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ip := s.clientIP(r)
	if s.limiter.blocked("setup:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return
	}
	if s.Store.UserCount() > 0 {
		writeErr(w, http.StatusConflict, "setup has already been completed")
		return
	}
	if s.SetupTok != "" && req.Token != s.SetupTok {
		s.limiter.fail("setup:" + ip)
		writeErr(w, http.StatusForbidden, "wrong setup token (see CADDYHUB_SETUP_TOKEN)")
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		writeErr(w, http.StatusBadRequest, "username is required")
		return
	}
	if err := auth.PasswordPolicy(req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, err := s.Store.SaveUser(store.User{Username: req.Username, PasswordHash: hash, Role: auth.RoleAdmin})
	if err != nil {
		storeErr(w, err)
		return
	}
	s.Store.Audit(u.Username, "setup.admin_created", u.Username, "", ip)
	s.startSession(w, r, u, false)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ip := s.clientIP(r)
	key := "login:" + ip
	if s.limiter.blocked(key) {
		writeErr(w, http.StatusTooManyRequests, "too many failed logins; try again in a few minutes")
		return
	}
	u, err := s.Store.UserByName(strings.TrimSpace(req.Username))
	if err != nil || u.PasswordHash == "" {
		auth.VerifyDummy(req.Password) // equalize timing for unknown users
		s.limiter.fail(key)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		s.limiter.fail(key)
		s.Store.Audit(u.Username, "login.failed", u.Username, "", ip)
		writeErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if u.Disabled {
		writeErr(w, http.StatusForbidden, "this account is disabled")
		return
	}
	s.limiter.reset(key)
	s.startSession(w, r, u, u.TOTPEnabled)
}

// startSession issues a session cookie. With pending2FA the session can only
// be used to submit a TOTP code.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u store.User, pending2FA bool) {
	tok := auth.RandomToken(32)
	now := time.Now().UTC()
	se := store.Session{
		ID: auth.TokenHash(tok), UserID: u.ID, CSRF: auth.RandomToken(24),
		CreatedAt: now, ExpiresAt: now.Add(sessionAbsolute), LastSeen: now,
		IP: s.clientIP(r), UserAgent: truncate(r.UserAgent(), 200), Pending2FA: pending2FA,
	}
	if err := s.Store.CreateSession(se); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: s.SecureCk,
		SameSite: http.SameSiteLaxMode, Expires: se.ExpiresAt,
	})
	if !pending2FA {
		s.Store.TouchLogin(u.ID)
		s.Store.Audit(u.Username, "login", u.Username, "", se.IP)
	}
	writeJSON(w, http.StatusOK, meResponse{User: &u, CSRF: se.CSRF, Pending2FA: pending2FA, Version: s.Version,
		SetupComplete: s.Store.Settings().SetupComplete})
}

// handleLoginTOTP completes a login that is waiting for a 2FA code.
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "log in first")
		return
	}
	se, err := s.Store.GetSession(auth.TokenHash(c.Value))
	if err != nil || !se.Pending2FA || time.Since(se.CreatedAt) > 10*time.Minute {
		writeErr(w, http.StatusUnauthorized, "login expired; start again")
		return
	}
	key := fmt.Sprintf("totp:%d", se.UserID)
	if s.limiter.blocked(key) {
		writeErr(w, http.StatusTooManyRequests, "too many wrong codes; try again later")
		return
	}
	u, err := s.Store.UserByID(se.UserID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "account not found")
		return
	}
	if !s.checkTOTP(u, req.Code) {
		s.limiter.fail(key)
		writeErr(w, http.StatusUnauthorized, "wrong code")
		return
	}
	s.limiter.reset(key)
	if err := s.Store.CompleteSession2FA(se.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Store.TouchLogin(u.ID)
	s.Store.Audit(u.Username, "login", u.Username, "with 2FA", s.clientIP(r))
	writeJSON(w, http.StatusOK, meResponse{User: &u, CSRF: se.CSRF, Version: s.Version, SetupComplete: s.Store.Settings().SetupComplete})
}

// checkTOTP verifies a code and rejects reuse of an already-used time step.
func (s *Server) checkTOTP(u store.User, code string) bool {
	if u.TOTPSecret == "" {
		return false
	}
	step, ok := auth.VerifyTOTP(u.TOTPSecret, strings.ReplaceAll(code, " ", ""), time.Now())
	if !ok {
		return false
	}
	k := fmt.Sprintf("totp_last_step:%d", u.ID)
	var last uint64
	s.Store.KVGetJSON(k, &last)
	if step <= last {
		return false
	}
	s.Store.KVSetJSON(k, step)
	return true
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		s.Store.DeleteSession(auth.TokenHash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.SecureCk, SameSite: http.SameSiteLaxMode})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := who(r)
	u, err := s.Store.UserByID(p.User.ID)
	if err != nil {
		storeErr(w, err)
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Current) {
		writeErr(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := auth.PasswordPolicy(req.New); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.PasswordHash, err = auth.HashPassword(req.New); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := s.Store.SaveUser(u); err != nil {
		storeErr(w, err)
		return
	}
	except := ""
	if p.Session != nil {
		except = p.Session.ID
	}
	s.Store.DeleteUserSessions(u.ID, except)
	s.audit(r, "user.password_changed", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTOTPBegin creates a pending secret for enrollment.
func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	p := who(r)
	secret := auth.NewTOTPSecret()
	enc, err := s.Store.Box().Seal([]byte(secret))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.Store.KVSetJSON(fmt.Sprintf("totp_pending:%d", p.User.ID), enc)
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "uri": auth.TOTPURI("CaddyHub", p.User.Username, secret)})
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := who(r)
	var enc []byte
	if !s.Store.KVGetJSON(fmt.Sprintf("totp_pending:%d", p.User.ID), &enc) {
		writeErr(w, http.StatusBadRequest, "start 2FA setup first")
		return
	}
	plain, err := s.Store.Box().Open(enc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u, err := s.Store.UserByID(p.User.ID)
	if err != nil {
		storeErr(w, err)
		return
	}
	u.TOTPSecret = string(plain)
	if !s.checkTOTP(u, req.Code) {
		writeErr(w, http.StatusBadRequest, "that code doesn't match; check your phone's clock")
		return
	}
	u.TOTPEnabled = true
	if _, err := s.Store.SaveUser(u); err != nil {
		storeErr(w, err)
		return
	}
	s.Store.KVSet(fmt.Sprintf("totp_pending:%d", p.User.ID), "null")
	s.audit(r, "user.2fa_enabled", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	u, err := s.Store.UserByID(who(r).User.ID)
	if err != nil {
		storeErr(w, err)
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.Password) {
		writeErr(w, http.StatusForbidden, "password is wrong")
		return
	}
	u.TOTPEnabled, u.TOTPSecret = false, ""
	if _, err := s.Store.SaveUser(u); err != nil {
		storeErr(w, err)
		return
	}
	s.audit(r, "user.2fa_disabled", u.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
