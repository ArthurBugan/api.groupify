// src/api/common/body_logger.rs
use axum::{
    body::Body,
    extract::Request,
    middleware::Next,
    response::Response,
};
use http_body_util::BodyExt;
use tracing::{debug, error, info, warn};
use axum::http::StatusCode;
use super::tracing::{enrich_with_request_body, enrich_with_response_body};

pub async fn log_request_response_body(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let (parts, body) = request.into_parts();

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
            enrich_with_request_body(body_str);
            info!("Request Body: {}", body_str);
        } else {
            warn!("Request Body is not valid UTF-8, logging as bytes: {:?}", request_body_bytes);
        }
    } else {
        debug!("Request Body is empty.");
    }

    let request = Request::from_parts(parts, Body::from(request_body_bytes));

    let response = next.run(request).await;

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
            enrich_with_response_body(body_str);
            if method == "POST" || method == "PUT" || method == "PATCH" {
                info!("Response Body: {}", body_str);
            }
        } else {
            warn!("Response Body is not valid UTF-8, logging as bytes: {:?}", response_body_bytes);
        }
    } else {
        debug!("Response Body is empty.");
    }

    Response::from_parts(parts, Body::from(response_body_bytes))
}
