use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Redirect},
    Json,
};
use chrono::{Duration, Local};
use hyper::StatusCode;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, RedirectUrl, RefreshToken, TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgQueryResult, PgPool, Row};
use tower_cookies::Cookies;

use crate::{
    routes::get_email_from_token,
    utils::{internal_error, ApiError},
    InnerState,
};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
}

#[derive(Deserialize, sqlx::FromRow, Clone)]
pub struct UserProfile {
    email: String,
}

pub fn build_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    let redirect_url = "http://localhost:3001/auth/google_callback";

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .expect("Invalid authorization endpoint URL"),
        Some(
            TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
                .expect("Invalid token endpoint URL"),
        ),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string()).unwrap())
}

pub async fn google_callback(
    State(inner): State<InnerState>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let InnerState {
        db, oauth_client, ..
    } = inner;
    let domain = std::env::var("GROUPIFY_HOST").expect("GROUPIFY_HOST must be set.");

    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .map_err(|_| ApiError::OptionError)?;

    let profile = fetch_user_profile(&token.access_token().secret()).await?;
    let max_age = calculate_token_expiry(token.expires_in()).ok_or(ApiError::OptionError)?;

    let refresh_token = token.refresh_token().ok_or(ApiError::OptionError)?;

    update_user_session(
        &db,
        &profile.email,
        token.access_token().secret(),
        max_age,
        refresh_token.secret(),
    )
    .await?;

    let redirect_str = format!("https://{}/dashboard/groups", domain);

    Ok(Redirect::to(redirect_str.as_str()))
}

async fn fetch_user_profile(access_token: &str) -> Result<UserProfile, ApiError> {
    let req = Client::new();
    req.get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| ApiError::OptionError)?
        .json::<UserProfile>()
        .await
        .map_err(|_| ApiError::OptionError)
}

fn calculate_token_expiry(
    expires_in: Option<std::time::Duration>,
) -> Option<chrono::NaiveDateTime> {
    expires_in.and_then(|secs| {
        let duration = Duration::seconds(secs.as_secs().try_into().ok()?);
        Some(Local::now().naive_local() + duration)
    })
}

async fn update_user_session(
    db: &sqlx::PgPool,
    email: &str,
    access_token: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)")
        .bind(email)
        .execute(db)
        .await
        .map_err(|_| ApiError::OptionError)?;

    let result: PgQueryResult = sqlx::query(
        "INSERT INTO sessions (user_id, session_id, expires_at, refresh_token)
       VALUES (
           (SELECT id FROM users WHERE email = $1 LIMIT 1), $2, $3, $4
       )
       ON CONFLICT (user_id)
       DO UPDATE
       SET session_id = EXCLUDED.session_id,
           expires_at = EXCLUDED.expires_at",
    )
    .bind(email)
    .bind(access_token)
    .bind(expires_at)
    .bind(refresh_token)
    .execute(db)
    .await
    .map_err(|_| ApiError::OptionError)?;

    // Check how many rows were affected
    if result.rows_affected() == 0 {
        return Err(ApiError::OptionError); // No rows were affected, handle as needed
    }

    Ok(())
}

pub async fn renew_token(
    db: PgPool,
    oauth_client: BasicClient,
    email: String,
) -> Result<(), ApiError> {
    let refresh_token = fetch_refresh_token(&db, &email).await?;

    let token = oauth_client
        .exchange_refresh_token(&refresh_token)
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            tracing::error!("Request error: {:?}", err);
            ApiError::OptionError
        })?;

    let max_age = calculate_token_expiry(token.expires_in()).ok_or(ApiError::OptionError)?;

    update_user_session(
        &db,
        &email,
        token.access_token().secret(),
        max_age,
        refresh_token.secret(),
    )
    .await?;

    Ok(())
}

async fn fetch_refresh_token(db: &sqlx::PgPool, email: &str) -> Result<RefreshToken, ApiError> {
    let refresh_token: String = sqlx::query("SELECT refresh_token FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)")
      .bind(email)
      .fetch_one(db)
      .await
      .map_err(|_| ApiError::OptionError)?
      .get("refresh_token");

    Ok(RefreshToken::new(refresh_token))
}

pub async fn check_google_session(
    State(inner): State<InnerState>,
    cookies: Cookies,
) -> Result<Json<Value>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.clone().len() == 0 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Missing token" })).to_string(),
        ));
    }

    let email = get_email_from_token(auth_token).await;

    let session = sqlx::query(
        "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)",
    )
    .bind(email)
    .execute(&db)
    .await
    .map_err(internal_error)?;

    tracing::debug!("session {:?}", session);

    if session.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Session not found" })).to_string(),
        )); // No rows were affected, handle as needed
    }

    return Ok(Json(json!({ "success": "true" })));
}
