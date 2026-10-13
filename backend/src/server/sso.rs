//! Sign-in in front of sites ("login wall" set to sign-in on the Security
//! page). Caddy's forward_auth asks `/api/sso/verify` on every request to a
//! protected site; without a valid sign-in the visitor is sent to the
//! sign-in page, which the panel serves under `/sso` on its own host (the
//! portal, proxied by Caddy). Signing in sets a cookie for the shared parent
//! domain, so one sign-in covers every protected site.
//!
//! Accounts are the panel's users; members can only sign in here. With
//! "require two-factor" on, an account without an authenticator sets one
//! up on its first sign-in.

use axum::Form;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::{AppState, cookie, header_str};
use crate::auth;
use crate::model::SecuritySettings;
use crate::store::{SsoSession, User};

pub const SSO_COOKIE: &str = "caddymium_sso";
const CSRF_COOKIE: &str = "caddymium_sso_csrf";
const ENROLL_PREFIX: &str = "sso_enroll:";

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || v.to_ipv4_mapped()
                    .is_some_and(|m| m.is_loopback() || m.is_private())
        }
    }
}

/// The visitor's address. Requests arrive through Caddy (loopback or the
/// internal network), which sets X-Forwarded-For to the real client.
fn client_ip(h: &HeaderMap, remote: SocketAddr) -> String {
    if is_private(remote.ip()) {
        let xff = header_str(h, "x-forwarded-for");
        if let Some(first) = xff
            .split(',')
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return first.to_string();
        }
    }
    remote.ip().to_string()
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Only redirects back to sites under the sign-in cookie's domain.
fn safe_rd(rd: &str, cookie_domain: &str) -> Option<String> {
    let u = url::Url::parse(rd.trim()).ok()?;
    if !matches!(u.scheme(), "https" | "http") {
        return None;
    }
    let host = u.host_str()?.to_ascii_lowercase();
    let d = cookie_domain.to_ascii_lowercase();
    if d.is_empty() || !(host == d || host.ends_with(&format!(".{d}"))) {
        return None;
    }
    Some(u.to_string())
}

fn secure_request(h: &HeaderMap) -> bool {
    header_str(h, "x-forwarded-proto") != "http"
}

fn sso_cookie(sec: &SecuritySettings, value: &str, max_age: i64, secure: bool) -> HeaderValue {
    let domain = sec.sso.effective_cookie_domain();
    let mut c = format!("{SSO_COOKIE}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if !domain.is_empty() {
        c.push_str(&format!("; Domain={domain}"));
    }
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn csrf_cookie(value: &str, secure: bool) -> HeaderValue {
    let mut c =
        format!("{CSRF_COOKIE}={value}; Path=/sso; HttpOnly; SameSite=Strict; Max-Age=1800");
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// A complete, self-contained page (no scripts, no external resources).
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{t}</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--text:#14171c;--muted:#5b6472;--line:#dfe3e8;--accent:#0f8a6a;--err:#b42318;--errbg:#fdecea}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0d0f12;--card:#16191e;--text:#e8eaed;--muted:#9aa3ad;--line:#2a2f36;--accent:#3ccf9f;--err:#ff8a7a;--errbg:#3a1a17}}}}
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}}
main{{width:100%;max-width:380px;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:26px 24px}}
h1{{font-size:20px;margin:0 0 4px}}p{{color:var(--muted);margin:0 0 16px}}label{{display:block;font-weight:600;font-size:13px;margin:12px 0 5px}}
input{{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:transparent;color:var(--text);font:inherit}}input:focus{{outline:2px solid var(--accent);outline-offset:1px}}
button,.btn{{display:inline-block;width:100%;margin-top:18px;padding:11px;border:0;border-radius:9px;background:var(--accent);color:#fff;font:inherit;font-weight:650;cursor:pointer;text-align:center;text-decoration:none}}
.err{{background:var(--errbg);color:var(--err);border-radius:9px;padding:9px 12px;margin:0 0 12px;font-size:14px}}.brand{{font-weight:700;color:var(--accent);font-size:13px;letter-spacing:.02em;margin-bottom:12px}}
.qr{{background:#fff;border-radius:10px;padding:10px;display:grid;place-items:center;margin:8px 0}}.qr svg{{width:190px;height:190px}}code{{word-break:break-all;font-size:13px}}a{{color:var(--accent)}}
</style></head><body><main><div class="brand">Caddymium</div>{body}</main></body></html>"#,
        t = esc(title),
    );
    let mut r = (status, html).into_response();
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(
        "x-robots-tag",
        HeaderValue::from_static("noindex, nofollow"),
    );
    r
}

fn redirect(to: &str) -> Response {
    let mut r = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(to) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The signed-in user, if the cookie is a valid, current sign-in.
fn signed_in(st: &AppState, h: &HeaderMap, sec: &SecuritySettings) -> Option<(User, SsoSession)> {
    let tok = cookie(h, SSO_COOKIE)?;
    let se = st.store.get_sso_session(&auth::token_hash(&tok)).ok()?;
    if se.expires_at <= Utc::now() {
        st.store.delete_sso_session(&se.id);
        return None;
    }
    if sec.sso.require_2fa && !se.mfa {
        return None;
    }
    let u = st.store.user_by_id(se.user_id).ok()?;
    if u.disabled {
        return None;
    }
    Some((u, se))
}

// ---------------------------------------------------------------- verify

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct VerifyQuery {
    site: i64,
}

/// Caddy's forward_auth target: 200 with the user in Remote-* headers, a
/// redirect to the sign-in page, or 403 when the account may not use the
/// site.
pub async fn verify(
    State(st): State<Arc<AppState>>,
    Query(q): Query<VerifyQuery>,
    h: HeaderMap,
) -> Response {
    let sec = st.store.settings().security;
    match signed_in(&st, &h, &sec) {
        Some((u, se)) => {
            if q.site > 0 {
                if let Ok(site) = st.store.site(q.site) {
                    let allowed = &site.config.access.shields.sso_users;
                    if !allowed.is_empty()
                        && !allowed
                            .iter()
                            .any(|n| n.trim().eq_ignore_ascii_case(&u.username))
                    {
                        return page(
                            StatusCode::FORBIDDEN,
                            "No access",
                            &format!(
                                "<h1>No access</h1><p>You're signed in as <strong>{}</strong>, but this account can't use this site.</p><a class=\"btn\" href=\"{}\">Sign in as someone else</a>",
                                esc(&u.username),
                                esc(&portal_url(&sec, "/sso/logout", None)),
                            ),
                        );
                    }
                }
            }
            if Utc::now() - se.last_seen > chrono::Duration::minutes(5) {
                st.store.touch_sso_session(&se.id, Utc::now());
            }
            let mut r = StatusCode::OK.into_response();
            let hm = r.headers_mut();
            for (k, v) in [
                ("remote-user", u.username.as_str()),
                ("remote-name", u.username.as_str()),
                ("remote-groups", u.role.as_str()),
            ] {
                if let Ok(v) = HeaderValue::from_str(v) {
                    hm.insert(k, v);
                }
            }
            r
        }
        None => {
            let host = header_str(&h, "x-forwarded-host");
            if host.is_empty() || sec.sso.portal_host.trim().is_empty() {
                return (StatusCode::UNAUTHORIZED, "sign-in required").into_response();
            }
            let proto = match header_str(&h, "x-forwarded-proto").as_str() {
                "http" => "http",
                _ => "https",
            };
            let uri = header_str(&h, "x-forwarded-uri");
            let uri = if uri.starts_with('/') {
                uri
            } else {
                "/".to_string()
            };
            let original = format!("{proto}://{host}{uri}");
            let mut r = redirect(&portal_url(&sec, "/sso/login", Some(&original)));
            *r.status_mut() = StatusCode::FOUND;
            r
        }
    }
}

fn portal_url(sec: &SecuritySettings, path: &str, rd: Option<&str>) -> String {
    let host = sec.sso.portal_host.trim().to_ascii_lowercase();
    let mut u = format!("https://{host}{path}");
    if let Some(rd) = rd {
        let q: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("rd", rd)
            .finish();
        u.push('?');
        u.push_str(&q);
    }
    u
}

// ---------------------------------------------------------------- sign-in page

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct RdQuery {
    rd: String,
}

fn login_form(sec: &SecuritySettings, rd: &str, csrf: &str, user: &str, err: &str) -> String {
    let code = if sec.sso.require_2fa {
        "<label for=\"c\">Code from your authenticator app</label><input id=\"c\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9 ]*\" placeholder=\"123456\">"
    } else {
        "<label for=\"c\">Two-factor code <span style=\"font-weight:400\">(if you use one)</span></label><input id=\"c\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9 ]*\">"
    };
    let e = if err.is_empty() {
        String::new()
    } else {
        format!("<div class=\"err\">{}</div>", esc(err))
    };
    format!(
        r#"<h1>Sign in</h1><p>to continue to your sites</p>{e}<form method="post" action="/sso/login"><input type="hidden" name="rd" value="{rd}"><input type="hidden" name="csrf" value="{csrf}"><label for="u">Username</label><input id="u" name="username" autocomplete="username" required autofocus value="{user}"><label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>{code}<button type="submit">Sign in</button></form>"#,
        rd = esc(rd),
        csrf = esc(csrf),
        user = esc(user),
    )
}

fn with_csrf(mut r: Response, csrf: &str, secure: bool) -> Response {
    r.headers_mut()
        .append(header::SET_COOKIE, csrf_cookie(csrf, secure));
    r
}

pub async fn login_page(
    State(st): State<Arc<AppState>>,
    Query(q): Query<RdQuery>,
    h: HeaderMap,
) -> Response {
    let sec = st.store.settings().security;
    let domain = sec.sso.effective_cookie_domain();
    if let Some((u, _)) = signed_in(&st, &h, &sec) {
        if let Some(rd) = safe_rd(&q.rd, &domain) {
            return redirect(&rd);
        }
        return signed_in_page(&u, &sec);
    }
    let csrf = auth::random_token(18);
    with_csrf(
        page(
            StatusCode::OK,
            "Sign in",
            &login_form(&sec, &q.rd, &csrf, "", ""),
        ),
        &csrf,
        secure_request(&h),
    )
}

fn signed_in_page(u: &User, sec: &SecuritySettings) -> Response {
    page(
        StatusCode::OK,
        "Signed in",
        &format!(
            "<h1>You're signed in</h1><p>as <strong>{}</strong>. Your protected sites under {} open without signing in again.</p><a class=\"btn\" href=\"/sso/logout\">Sign out</a>",
            esc(&u.username),
            esc(&sec.sso.effective_cookie_domain()),
        ),
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct LoginForm {
    username: String,
    password: String,
    code: String,
    rd: String,
    csrf: String,
}

pub async fn login_submit(
    State(st): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    let sec = st.store.settings().security;
    let secure = secure_request(&h);
    let ip = client_ip(&h, remote);
    let fresh = auth::random_token(18);
    let fail = |msg: &str| {
        with_csrf(
            page(
                StatusCode::UNAUTHORIZED,
                "Sign in",
                &login_form(&sec, &f.rd, &fresh, &f.username, msg),
            ),
            &fresh,
            secure,
        )
    };
    if f.csrf.is_empty() || cookie(&h, CSRF_COOKIE).as_deref() != Some(f.csrf.as_str()) {
        return fail("This form expired. Please try again.");
    }
    let key = format!("sso:{ip}");
    if st.limiter().blocked(&key) {
        return fail("Too many failed attempts. Try again in a few minutes.");
    }
    let u = match st.store.user_by_name(f.username.trim()) {
        Ok(u) if !u.password_hash.is_empty() => u,
        _ => {
            let pw = f.password.clone();
            tokio::task::spawn_blocking(move || auth::verify_dummy(&pw))
                .await
                .ok();
            st.limiter().fail(&key);
            return fail("Wrong username or password.");
        }
    };
    let (hash, pw) = (u.password_hash.clone(), f.password.clone());
    let okay = tokio::task::spawn_blocking(move || auth::verify_password(&hash, &pw))
        .await
        .unwrap_or(false);
    if !okay {
        st.limiter().fail(&key);
        st.store
            .audit(&u.username, "sso.login_failed", &u.username, "", &ip);
        return fail("Wrong username or password.");
    }
    if u.disabled {
        return fail("This account is disabled.");
    }
    let mut mfa = false;
    if u.totp_enabled {
        if f.code.trim().is_empty() {
            return fail("Enter the code from your authenticator app.");
        }
        if !super::auth_handlers::check_totp(&st, &u, &f.code) {
            st.limiter().fail(&key);
            st.store.audit(
                &u.username,
                "sso.login_failed",
                &u.username,
                "wrong code",
                &ip,
            );
            return fail("That code is wrong or was already used.");
        }
        mfa = true;
    } else if sec.sso.require_2fa {
        st.limiter().reset(&key);
        return enroll_page(&st, &u, &f.rd, secure, "");
    }
    st.limiter().reset(&key);
    start(&st, &sec, &u, mfa, &ip, &h, &f.rd)
}

/// Creates the sign-in and sends the visitor on.
fn start(
    st: &AppState,
    sec: &SecuritySettings,
    u: &User,
    mfa: bool,
    ip: &str,
    h: &HeaderMap,
    rd: &str,
) -> Response {
    let tok = auth::random_token(32);
    let now = Utc::now();
    let hours = sec.sso.session_hours.clamp(1, 24 * 90);
    let se = SsoSession {
        id: auth::token_hash(&tok),
        user_id: u.id,
        created_at: now,
        expires_at: now + chrono::Duration::hours(hours),
        last_seen: now,
        ip: ip.to_string(),
        user_agent: header_str(h, "user-agent").chars().take(200).collect(),
        mfa,
    };
    if st.store.create_sso_session(&se).is_err() {
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error",
            "<h1>Something went wrong</h1><p>Please try again.</p>",
        );
    }
    st.store.audit(
        &u.username,
        "sso.login",
        &u.username,
        if mfa { "with 2FA" } else { "" },
        ip,
    );
    let mut r = match safe_rd(rd, &sec.sso.effective_cookie_domain()) {
        Some(to) => redirect(&to),
        None => signed_in_page(u, sec),
    };
    r.headers_mut().append(
        header::SET_COOKIE,
        sso_cookie(sec, &tok, hours * 3600, secure_request(h)),
    );
    r
}

pub async fn logout(State(st): State<Arc<AppState>>, h: HeaderMap) -> Response {
    let sec = st.store.settings().security;
    if let Some(tok) = cookie(&h, SSO_COOKIE) {
        st.store.delete_sso_session(&auth::token_hash(&tok));
    }
    let mut r = page(
        StatusCode::OK,
        "Signed out",
        "<h1>Signed out</h1><p>You're signed out of your protected sites.</p><a class=\"btn\" href=\"/sso/login\">Sign in again</a>",
    );
    r.headers_mut().append(
        header::SET_COOKIE,
        sso_cookie(&sec, "", 0, secure_request(&h)),
    );
    r
}

pub async fn status_page(State(st): State<Arc<AppState>>, h: HeaderMap) -> Response {
    let sec = st.store.settings().security;
    match signed_in(&st, &h, &sec) {
        Some((u, _)) => signed_in_page(&u, &sec),
        None => redirect("/sso/login"),
    }
}

// ---------------------------------------------------------------- 2FA setup

#[derive(Serialize, Deserialize)]
struct Enrollment {
    user_id: i64,
    /// sealed TOTP secret
    secret: Vec<u8>,
    created: chrono::DateTime<Utc>,
}

/// First sign-in of an account without two-factor while it is required:
/// shows a QR code and asks for a code to confirm.
fn enroll_page(st: &AppState, u: &User, rd: &str, secure: bool, err: &str) -> Response {
    let secret = auth::new_totp_secret();
    let Ok(sealed) = st.store.secret_box().seal(secret.as_bytes()) else {
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error",
            "<h1>Something went wrong</h1>",
        );
    };
    let id = auth::random_token(24);
    let _ = st.store.kv_set_json(
        &format!("{ENROLL_PREFIX}{}", auth::token_hash(&id)),
        &Enrollment {
            user_id: u.id,
            secret: sealed,
            created: Utc::now(),
        },
    );
    let uri = auth::totp_uri("Caddymium", &u.username, &secret);
    let qr = qrcode::QrCode::new(uri.as_bytes())
        .map(|c| {
            c.render::<qrcode::render::svg::Color>()
                .min_dimensions(190, 190)
                .quiet_zone(false)
                .build()
        })
        .unwrap_or_default();
    let csrf = auth::random_token(18);
    let e = if err.is_empty() {
        String::new()
    } else {
        format!("<div class=\"err\">{}</div>", esc(err))
    };
    with_csrf(
        page(
            StatusCode::OK,
            "Set up two-factor",
            &format!(
                r#"<h1>Set up two-factor</h1><p>Your sites require a code from an authenticator app. Scan this with Google Authenticator, Aegis, 1Password, Bitwarden or similar, or <a href="{uri}">open it on this phone</a>.</p>{e}<div class="qr">{qr}</div><p>Or enter this key: <code>{secret}</code></p><form method="post" action="/sso/enroll"><input type="hidden" name="id" value="{id}"><input type="hidden" name="rd" value="{rd}"><input type="hidden" name="csrf" value="{csrf}"><label for="c">Code from the app</label><input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus><button type="submit">Confirm and sign in</button></form>"#,
                uri = esc(&uri),
                secret = esc(&secret),
                id = esc(&id),
                rd = esc(rd),
                csrf = esc(&csrf),
            ),
        ),
        &csrf,
        secure,
    )
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct EnrollForm {
    id: String,
    code: String,
    rd: String,
    csrf: String,
}

pub async fn enroll_submit(
    State(st): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    h: HeaderMap,
    Form(f): Form<EnrollForm>,
) -> Response {
    let sec = st.store.settings().security;
    let secure = secure_request(&h);
    let ip = client_ip(&h, remote);
    let expired = || {
        redirect(&format!(
            "/sso/login?rd={}",
            url::form_urlencoded::byte_serialize(f.rd.as_bytes()).collect::<String>()
        ))
    };
    if f.csrf.is_empty() || cookie(&h, CSRF_COOKIE).as_deref() != Some(f.csrf.as_str()) {
        return expired();
    }
    let key = format!("{ENROLL_PREFIX}{}", auth::token_hash(&f.id));
    let Some(en) = st.store.kv_get_json::<Enrollment>(&key) else {
        return expired();
    };
    if Utc::now() - en.created > chrono::Duration::minutes(15) {
        let _ = st.store.kv_set(&key, "null");
        return expired();
    }
    let limit = format!("sso_enroll:{}", en.user_id);
    if st.limiter().blocked(&limit) {
        return page(
            StatusCode::TOO_MANY_REQUESTS,
            "Try later",
            "<h1>Too many wrong codes</h1><p>Wait a few minutes and sign in again.</p>",
        );
    }
    let Ok(mut u) = st.store.user_by_id(en.user_id) else {
        return expired();
    };
    if u.disabled {
        return expired();
    }
    let Ok(plain) = st.store.secret_box().open(&en.secret) else {
        return expired();
    };
    u.totp_secret = String::from_utf8_lossy(&plain).to_string();
    if !super::auth_handlers::check_totp(&st, &u, &f.code) {
        st.limiter().fail(&limit);
        // Same secret again, so the app entry they just added keeps working.
        let csrf = auth::random_token(18);
        return with_csrf(
            page(
                StatusCode::UNAUTHORIZED,
                "Set up two-factor",
                &format!(
                    r#"<h1>Set up two-factor</h1><div class="err">That code doesn't match. Check that your phone's clock is right and try the newest code.</div><form method="post" action="/sso/enroll"><input type="hidden" name="id" value="{id}"><input type="hidden" name="rd" value="{rd}"><input type="hidden" name="csrf" value="{csrf}"><label for="c">Code from the app</label><input id="c" name="code" inputmode="numeric" autocomplete="one-time-code" required autofocus><button type="submit">Confirm and sign in</button></form>"#,
                    id = esc(&f.id),
                    rd = esc(&f.rd),
                    csrf = esc(&csrf),
                ),
            ),
            &csrf,
            secure,
        );
    }
    st.limiter().reset(&limit);
    u.totp_enabled = true;
    let Ok(u) = st.store.save_user(u) else {
        return page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Error",
            "<h1>Something went wrong</h1>",
        );
    };
    let _ = st.store.kv_set(&key, "null");
    st.store.audit(
        &u.username,
        "user.2fa_enabled",
        &u.username,
        "at sign-in",
        &ip,
    );
    start(&st, &sec, &u, true, &ip, &h, &f.rd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_stay_on_the_domain() {
        assert_eq!(
            safe_rd("https://jellyfin.example.com/web/", "example.com").as_deref(),
            Some("https://jellyfin.example.com/web/")
        );
        assert!(safe_rd("https://example.com/", "example.com").is_some());
        assert!(safe_rd("https://evil.com/", "example.com").is_none());
        assert!(safe_rd("https://example.com.evil.com/", "example.com").is_none());
        assert!(safe_rd("https://notexample.com/", "example.com").is_none());
        assert!(safe_rd("javascript:alert(1)", "example.com").is_none());
        assert!(safe_rd("//evil.com/", "example.com").is_none());
        assert!(safe_rd("https://a.example.com/", "").is_none());
    }

    #[test]
    fn forwarded_ip_only_from_private_peers() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 10.0.0.1"),
        );
        assert_eq!(
            client_ip(&h, "127.0.0.1:5000".parse().unwrap()),
            "203.0.113.7"
        );
        assert_eq!(
            client_ip(&h, "172.18.0.3:5000".parse().unwrap()),
            "203.0.113.7"
        );
        assert_eq!(
            client_ip(&h, "198.51.100.2:5000".parse().unwrap()),
            "198.51.100.2"
        );
    }

    #[test]
    fn escaping() {
        assert_eq!(
            esc("<a href=\"x\">'&"),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;"
        );
    }
}
