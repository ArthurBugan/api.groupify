use crate::SharedState;

use axum::body::{to_bytes, Body};
use axum::Extension;
use axum::{
    http::{HeaderMap, StatusCode},
    response::Html,
};

pub async fn handle_post(
    Extension(state): Extension<SharedState>,
    headers: HeaderMap,
    body: Body,
) -> StatusCode {
    let body_bytes = to_bytes(body, usize::MAX).await.unwrap();

    let mut state = state.write().unwrap();

    for (key, value) in headers.iter() {
        state.headers.append(key, value.clone());
    }

    state.body.extend_from_slice(&body_bytes);

    StatusCode::OK
}

pub async fn handle_get(Extension(state): Extension<SharedState>) -> Html<String> {
    let state = state.read().unwrap();
    let headers = match &state.headers {
        headers => format!("{:?}", headers),
    };
    let body = match &state.body {
        body => String::from_utf8_lossy(body).to_string(),
    };

    Html(format!(
        "<h1>Headers</h1><pre>{}</pre><h1>Body</h1><pre>{}</pre>",
        headers, body
    ))
}
