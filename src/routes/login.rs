use crate::authentication::{validate_credentials, Credentials, AuthError};
use crate::InnerState;
use crate::errors::AppError;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
// StatusCode might not be needed directly in the return type anymore
// use reqwest::StatusCode; 

use axum::response::Html; // Keep if root() or other handlers use it
use axum_typed_multipart::{TryFromMultipart, TypedMultipart};
use cookie::time::{Duration, OffsetDateTime};
use cookie::SameSite;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_cookies::{Cookie, Cookies};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: String,
    role: String,
    exp: usize,
}

#[derive(Default, Deserialize, Serialize)]
pub struct Counter(pub(crate) usize);

#[derive(serde::Deserialize, TryFromMultipart)]
pub struct FormData {
    email: String,
    password: String,
}

pub async fn login_user(
    cookies: Cookies,
    State(inner): State<InnerState>,
    form: Json<FormData>,
) -> Result<Json<Value>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let credentials = Credentials {
        email: form.email.clone(),
        password: form.password.clone(),
    };

    let user_id = validate_credentials(&credentials, &db)
        .await
        .map_err(|auth_error| match auth_error {
            AuthError::InvalidCredentials(e) => AppError::Authentication(e.context("Invalid credentials supplied")),
            AuthError::UnexpectedError(e) => AppError::Unexpected(e.context("Credential validation failed")),
        })?;

    let token = generate_token(&credentials.email, &user_id)?;

    let mut now = OffsetDateTime::now_utc();
    now += Duration::days(60);

    let domain = std::env::var("GROUPIFY_HOST")
        .map_err(|e| AppError::Unexpected(anyhow::anyhow!(e).context("GROUPIFY_HOST env var not set")))?;
    let mut cookie = Cookie::new("auth-token", token);

    cookie.set_domain(domain);
    cookie.set_same_site(SameSite::None);
    cookie.set_secure(true);
    cookie.set_path("/");
    cookie.set_expires(now);
    cookies.add(cookie);

    Ok(Json(json!({ "data": "login completed" })))
}

pub async fn logout_user(cookies: Cookies) -> Result<Json<Value>, AppError> { // Changed return type
    let mut cookie = Cookie::named("auth-token");
    cookie.set_same_site(SameSite::None);
    cookie.make_removal();

    cookies.remove(cookie);
    Ok(Json(json!({ "data": "logout completed" })))
}

pub async fn root(headers: HeaderMap) -> Html<String> { // Keep Html if it's the correct response type
    Html(format!("<h1>{:?}</h1>", headers))
}

fn generate_token(username: &str, user_id: &str) -> Result<String, AppError> { // Changed return type
    let key = std::env::var("SECRET_TOKEN")
        .map_err(|e| AppError::Unexpected(anyhow::anyhow!(e).context("SECRET_TOKEN env var not set")))?;

    let claims = Claims {
        user_id: user_id.to_owned(),
        sub: username.to_owned(),
        role: "user".to_owned(), // Consider making this dynamic if roles are planned
        exp: (chrono::Utc::now() + chrono::Duration::days(90)).timestamp() as usize,
    };
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(key.as_bytes()))
        .map_err(|e| AppError::Unexpected(anyhow::Error::new(e).context("Failed to encode JWT token")))
}
