use axum::{
    http::{Request, StatusCode, header},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use cookie::Cookie;
use tracing::error;

use crate::api::v1::login::Claims;

pub async fn auth_middleware(
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let secret = std::env::var("TOKEN").map_err(|e| {
        error!("TOKEN not set: {:?}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let token = extract_token(&request).ok_or(StatusCode::UNAUTHORIZED)?;

    let validation = Validation::new(Algorithm::HS256);
    let token_data = decode::<Claims>(&token, &DecodingKey::from_secret(secret.as_ref()), &validation)
        .map_err(|e| {
            error!("JWT validation failed: {:?}", e);
            StatusCode::UNAUTHORIZED
        })?;

    request.extensions_mut().insert(token_data.claims);
    Ok(next.run(request).await)
}

/// Extracts JWT from either the `Authorization` header or `Cookie` header.
fn extract_token<B>(req: &Request<B>) -> Option<String> {
    // Check Authorization: Bearer <token>
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Check Cookie: access_token=<token>
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie in cookie_str.split(';') {
                if let Ok(parsed) = Cookie::parse(cookie.trim()) {
                    if parsed.name() == "auth-token" {
                        return Some(parsed.value().to_string());
                    }
                }
            }
        }
    }

    None
}
