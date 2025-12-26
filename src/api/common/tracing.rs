//! Custom tracing utilities for HTTP requests
//! 
//! This module provides custom tracing functions for detailed HTTP request/response logging
//! with proper span creation and structured logging.

use axum::http::{Request, Response};
use std::collections::HashMap;
use std::time::Duration;
use tower_http::classify::ServerErrorsFailureClass;
use tracing::{info_span, Level, Span};

/// Creates a custom tracing span for HTTP requests with detailed context
#[tracing::instrument(name = "make_custom_span", skip(request))]
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

    tracing::debug!("Creating custom span for request: {}", request_id);

    info_span!(
        "http_request",
        method = %request.method(),
        uri = %request.uri().path(),
        query = ?request.uri().query(),
        version = ?request.version(),
        request_id = request_id,
        correlation_id = correlation_id,
        user_agent = ?request.headers().get("user-agent"),
        content_type = ?request.headers().get("content-type"),
        content_length = ?request.headers().get("content-length"),
    )
}

/// Handles custom logging for incoming HTTP requests
#[tracing::instrument(name = "on_custom_request", skip(request, _span))]
pub fn on_custom_request<B>(request: &Request<B>, _span: &Span) {
    let headers: HashMap<String, String> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            // Filter sensitive headers for security
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

    tracing::info!(
        method = %request.method(),
        uri = %request.uri(),
        headers = ?headers,
        "Incoming HTTP request"
    );
}

/// Handles custom logging for HTTP responses with latency tracking
#[tracing::instrument(name = "on_custom_response", skip(response, _span))]
pub fn on_custom_response<B>(
    response: &Response<B>,
    latency: Duration,
    _span: &Span,
) {
    let status = response.status();
    let latency_ms = latency.as_millis();

    // Determine log level based on status code
    let log_level = match status.as_u16() {
        200..=299 => Level::INFO,
        300..=399 => Level::INFO,
        400..=499 => Level::WARN,
        500..=599 => Level::ERROR,
        _ => Level::INFO,
    };

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

    // Log with appropriate level based on status
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

/// Handles custom logging for HTTP request failures
#[tracing::instrument(name = "on_custom_failure", skip(_span))]
pub fn on_custom_failure(
    error: ServerErrorsFailureClass,
    latency: Duration,
    _span: &Span,
) {
    let error_type = match error {
        ServerErrorsFailureClass::StatusCode(code) => {
            format!("HTTP {}", code.as_u16())
        }
        ServerErrorsFailureClass::Error(_) => {
            "Internal Error".to_string()
        }
    };

    tracing::error!(
        error = ?error,
        latency_ms = latency.as_millis(),
        error_type = error_type,
        "HTTP request failed"
    );
}
