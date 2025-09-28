use axum::response::IntoResponse;
use axum::http::StatusCode;

pub async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}
