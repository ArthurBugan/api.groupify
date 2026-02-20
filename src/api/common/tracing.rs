//! Custom tracing utilities for HTTP requests
//!
//! This module provides custom tracing functions for detailed HTTP request/response logging
//! with a single span that gets enriched throughout the request lifecycle.

use axum::http::{Request, Response};
use std::collections::HashMap;
use std::time::Duration;
use tower_http::classify::ServerErrorsFailureClass;
use tracing::{info_span, Level, Span};

/// Extract user ID from auth-token cookie
fn extract_user_id<B>(request: &Request<B>) -> Option<String> {
    let auth_token = request
        .headers()
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|cookie_str| cookie_str.split(';'))
        .find_map(|cookie| {
            let cookie = cookie.trim();
            if cookie.starts_with("auth-token=") {
                Some(cookie.trim_start_matches("auth-token=").to_string())
            } else {
                None
            }
        })?;

    let secret = std::env::var("PAS_TKN").ok()?;

    #[derive(serde::Deserialize)]
    struct Claims {
        user_id: String,
    }

    let token_data = jsonwebtoken::decode::<Claims>(
        &auth_token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_ref()),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
    )
    .ok()?;

    Some(token_data.claims.user_id)
}

/// Creates a custom tracing span for HTTP requests with detailed context
pub fn make_custom_span<B>(request: &Request<B>) -> Span {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    let correlation_id = request
        .headers()
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    let user_id = extract_user_id(request).unwrap_or_else(|| "anonymous".to_string());
    let method = request.method().as_str();
    let uri = request.uri();

    tracing::debug!("Creating custom span for request: {}", request_id);

    let span = info_span!(
        "http_request",
        method = method,
        uri = %uri.path(),
        query = ?uri.query(),
        version = ?request.version(),
        request_id = request_id,
        correlation_id = correlation_id,
        user_id = %user_id,
        user_agent = ?request.headers().get("user-agent"),
        content_type = ?request.headers().get("content-type"),
        content_length = ?request.headers().get("content-length"),
        request_headers = tracing::field::Empty,
        request_body = tracing::field::Empty,
        route_params = tracing::field::Empty,
        response_status = tracing::field::Empty,
        response_headers = tracing::field::Empty,
        response_body = tracing::field::Empty,
        latency_ms = tracing::field::Empty,
        error = tracing::field::Empty,
        error_type = tracing::field::Empty,
    );

    span
}

/// Enriches the span with incoming HTTP request details
pub fn on_custom_request<B>(request: &Request<B>, span: &Span) {
    let headers: HashMap<String, String> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            if name.as_str().to_lowercase().contains("authorization")
                || name.as_str().to_lowercase().contains("cookie")
                || name.as_str().to_lowercase().contains("token")
            {
                Some((name.to_string(), "[REDACTED]".to_string()))
            } else {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_string()))
            }
        })
        .collect();

    span.record("request_headers", tracing::field::debug(&headers));

    let _guard = span.enter();

    tracing::info!(
        method = %request.method(),
        uri = %request.uri(),
        headers = ?headers,
        "Incoming HTTP request"
    );
}

/// Enriches the span with HTTP response details and latency
pub fn on_custom_response<B>(response: &Response<B>, latency: Duration, span: &Span) {
    let status = response.status();
    let latency_ms = latency.as_millis() as u64;

    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    span.record("response_status", status.as_u16());
    span.record("response_headers", tracing::field::debug(&headers));
    span.record("latency_ms", latency_ms);

    let log_level = match status.as_u16() {
        200..=299 => Level::INFO,
        300..=399 => Level::INFO,
        400..=499 => Level::WARN,
        500..=599 => Level::ERROR,
        _ => Level::INFO,
    };

    let _guard = span.enter();

    match log_level {
        Level::INFO => tracing::info!(
            status = %status,
            latency_ms = latency_ms,
            headers = ?headers,
            "HTTP request completed successfully"
        ),
        Level::WARN => tracing::warn!(
            status = %status,
            latency_ms = latency_ms,
            headers = ?headers,
            "HTTP request completed with client error"
        ),
        Level::ERROR => tracing::error!(
            status = %status,
            latency_ms = latency_ms,
            headers = ?headers,
            "HTTP request completed with server error"
        ),
        _ => {}
    }
}

/// Enriches the span with failure details
pub fn on_custom_failure(error: ServerErrorsFailureClass, latency: Duration, span: &Span) {
    let latency_ms = latency.as_millis() as u64;

    let error_type = match &error {
        ServerErrorsFailureClass::StatusCode(code) => {
            format!("HTTP {}", code.as_u16())
        }
        ServerErrorsFailureClass::Error(_) => "Internal Error".to_string(),
    };

    span.record("error", tracing::field::debug(&error));
    span.record("error_type", &error_type);
    span.record("latency_ms", latency_ms);

    let _guard = span.enter();

    tracing::error!(
        error = ?error,
        latency_ms = latency_ms,
        error_type = error_type,
        "HTTP request failed"
    );
}

/// Enriches the current span with request body (call from body logger middleware)
pub fn enrich_with_request_body(body: &str) {
    let span = tracing::Span::current();
    if !span.is_none() {
        span.record("request_body", body);
    }
}

/// Enriches the current span with response body (call from body logger middleware)
pub fn enrich_with_response_body(body: &str) {
    let span = tracing::Span::current();
    if !span.is_none() {
        span.record("response_body", body);
    }
}

/// Enriches the current span with route parameters
pub fn enrich_with_route_params(params: &HashMap<String, String>) {
    let span = tracing::Span::current();
    if !span.is_none() {
        span.record("route_params", tracing::field::debug(params));
    }
}
