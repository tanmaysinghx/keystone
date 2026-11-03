//! The Angular console, compiled into the binary so a release is one self-contained file (like
//! Portal SSO's single jar). `ui.dir` serves a directory instead, for console development.
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../ui/dist/keystone-ui/browser"]
#[allow_missing = true]
struct Console;

pub fn embedded() -> bool {
    Console::get("index.html").is_some()
}

/// Serves an asset, or index.html for client-side routes such as /docs/spring-boot.
pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let (file, name) = match Console::get(path).filter(|_| !path.is_empty()) {
        Some(file) => (file, path),
        None => match Console::get("index.html") {
            Some(index) => (index, "index.html"),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    "The console is not built into this binary. Run `npm run build:ui` and rebuild, or set ui.dir.",
                )
                    .into_response();
            }
        },
    };
    let mut response = Response::new(Body::from(file.data.into_owned()));
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    if let Ok(value) = HeaderValue::from_str(mime.as_ref()) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}
