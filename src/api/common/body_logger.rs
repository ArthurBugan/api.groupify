// src/api/common/body_logger.rs
use axum::{
    body::{Body, Bytes, HttpBody},
    extract::Request,
    middleware::Next,
    response::Response,
};
use http_body_util::{BodyExt, Full};
use tracing::{debug, error, info, warn};
use axum::http::StatusCode;

pub async fn log_request_response_body(
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();

    // --- Log Request Body ---
    let request_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to collect request body: {:?}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Failed to read request body: {}", e)))
                .unwrap();
        }
    };

    if !request_body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&request_body_bytes) {
            info!("Request Body: {}", body_str);
        } else {
            warn!("Request Body is not valid UTF-8, logging as bytes: {:?}", request_body_bytes);
        }
    } else {
        debug!("Request Body is empty.");
    }

    // Re-create the request with the body for the next middleware/handler
    let request = Request::from_parts(parts, Body::from(request_body_bytes));

    // Process the request
    let response = next.run(request).await;

    // --- Log Response Body ---
    let (parts, body) = response.into_parts();

    let response_body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            error!("Failed to collect response body: {:?}", e);
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!("Failed to read response body: {}", e)))
                .unwrap();
        }
    };

    if !response_body_bytes.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(&response_body_bytes) {
            info!("Response Body: {}", body_str);
        } else {
            warn!("Response Body is not valid UTF-8, logging as bytes: {:?}", response_body_bytes);
        }
    } else {
        debug!("Response Body is empty.");
    }

    // Re-create the response with the body for the client
    Response::from_parts(parts, Body::from(response_body_bytes))
}