use crate::api::common::utils::setup_auth_cookie;
use crate::authentication::{validate_credentials, Credentials};
use crate::errors::AppError;
use crate::InnerState;

use axum::extract::State;
use axum::Json;

use axum_typed_multipart::TryFromMultipart;
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

#[tracing::instrument(name = "User login", skip(cookies, inner, form), fields(email = %form.email))]
pub async fn login_user(
    cookies: Cookies,
    State(inner): State<InnerState>,
    form: Json<FormData>,
) -> Result<Json<Value>, AppError> {
    tracing::info!("Starting login process for user: {}", form.email);
    let InnerState { db, .. } = inner;

    let credentials = Credentials {
        email: form.email.clone(),
        password: form.password.clone(),
    };

    tracing::debug!("Validating user credentials");
    let user_id = validate_credentials(&credentials, &db).await?;

    tracing::info!(
        "Credentials validated successfully for user: {}",
        form.email
    );

    tracing::debug!("Generating JWT token for user: {}", form.email);
    let token = generate_token(&credentials.email, &user_id)?;
    tracing::debug!("JWT token generated successfully");

    tracing::debug!("Retrieving GROUPIFY_HOST environment variable");
    let domain = std::env::var("GROUPIFY_HOST").map_err(|e| {
        tracing::error!("GROUPIFY_HOST environment variable not set: {:?}", e);
        AppError::Unexpected(anyhow::anyhow!(e).context("GROUPIFY_HOST env var not set"))
    })?;

    // Use the utility function instead of duplicated code
    setup_auth_cookie(&token, &domain, &cookies);

    tracing::info!("Login completed successfully for user: {}", form.email);
    Ok(Json(json!({ "data": "login completed" })))
}

#[tracing::instrument(name = "User logout", skip(cookies))]
pub async fn logout_user(cookies: Cookies) -> Result<Json<Value>, AppError> {
    tracing::info!("Starting logout process");

    tracing::debug!("Creating removal cookie for auth-token");
    let mut cookie = Cookie::named("auth-token");
    cookie.set_same_site(SameSite::None);
    cookie.make_removal();

    cookies.remove(cookie);
    tracing::info!("Logout completed successfully");
    Ok(Json(json!({ "data": "logout completed" })))
}

#[tracing::instrument(name = "Generate JWT token", skip(username, user_id), fields(username = %username, user_id = %user_id))]
pub fn generate_token(username: &str, user_id: &str) -> Result<String, AppError> {
    tracing::debug!("Starting JWT token generation for user: {}", username);

    tracing::debug!("Retrieving SECRET_TOKEN environment variable");
    let key = std::env::var("SECRET_TOKEN").map_err(|e| {
        tracing::error!("SECRET_TOKEN environment variable not set: {:?}", e);
        AppError::Unexpected(anyhow::anyhow!(e).context("SECRET_TOKEN env var not set"))
    })?;

    tracing::debug!("Creating JWT claims for user: {}", username);
    let claims = Claims {
        user_id: user_id.to_owned(),
        sub: username.to_owned(),
        role: "user".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::days(90)).timestamp() as usize,
    };

    tracing::debug!("Encoding JWT token");
    let header = Header::new(Algorithm::HS256);
    let token =
        encode(&header, &claims, &EncodingKey::from_secret(key.as_bytes())).map_err(|e| {
            tracing::error!("Failed to encode JWT token for user {}: {:?}", username, e);
            AppError::Unexpected(anyhow::Error::new(e).context("Failed to encode JWT token"))
        })?;

    tracing::debug!("JWT token generated successfully for user: {}", username);
    Ok(token)
}
