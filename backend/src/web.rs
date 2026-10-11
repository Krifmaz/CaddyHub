//! The built web UI, embedded into the binary. The UI is built into ui/dist
//! (see frontend/vite.config.js); without a build the server still runs and
//! shows a hint instead of the UI.

use axum::body::Body;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "ui/dist"]
struct Ui;

/// Reports whether a UI build is embedded.
pub fn available() -> bool {
    Ui::get("index.html").is_some()
}

/// Serves the built UI, falling back to index.html for client routes.
pub async fn spa(uri: Uri) -> Response {
    let p = uri.path().trim_start_matches('/');
    if !p.is_empty() {
        if let Some(f) = Ui::get(p) {
            let mime = mime_guess::from_path(p).first_or_octet_stream();
            let cache = if p.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            return Response::builder()
                .header(header::CONTENT_TYPE, mime.as_ref())
                .header(header::CACHE_CONTROL, cache)
                .body(Body::from(f.data.into_owned()))
                .unwrap();
        }
    }
    match Ui::get("index.html") {
        Some(f) => Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(f.data.into_owned()))
            .unwrap(),
        None => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "CaddyHub API is running, but the web UI was not built into this binary.\nBuild it with: cd frontend && npm ci && npm run build\n",
        )
            .into_response(),
    }
}
