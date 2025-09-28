use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Json,
};
use chrono::Duration;
use cookie::{Cookie, SameSite};
use oauth2::{reqwest::async_http_client, AuthorizationCode, TokenResponse};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tower_cookies::Cookies;

use crate::{
    api::v1::oauth::{
        fetch_user_profile, update_user_session, AuthRequest, OAuthProvider, Session,
    },
    api::v1::login::{
        generate_token,
    },
    errors::AppError,
    InnerState,
};

#[tracing::instrument(name = "Discord OAuth callback", skip(cookies, inner, query), fields(code_length = query.code.len()))]
pub async fn discord_callback(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Processing Discord OAuth callback");

    let InnerState {
        db, oauth_clients, ..
    } = inner;

    tracing::debug!("Exchanging authorization code for access token");
    let token = oauth_clients
        .discord
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange Discord authorization code: {:?}", e);
            AppError::ExternalService(anyhow::anyhow!(
                "Failed to exchange authorization code: {}",
                e
            ))
        })?;

    let access_token = &token.access_token().secret();
    let refresh_token = token.refresh_token().map(|t| t.secret()).map_or("", |v| v);

    tracing::debug!("Successfully obtained Discord access token");

    let user_profile = fetch_user_profile(access_token, &OAuthProvider::Discord).await?;
    tracing::info!("Fetched Discord user profile for: {}", user_profile.email);

    let expires_at = crate::api::v1::auth::calculate_token_expiry(token.expires_in()).await;

    update_user_session(
        &db,
        &user_profile.email,
        access_token,
        expires_at,
        refresh_token,
        &OAuthProvider::Discord,
    )
    .await?;

    tracing::info!(
        "Discord OAuth callback completed successfully for: {}",
        user_profile.email
    );

    // Redirect to your frontend with success
    let frontend_url =
        std::env::var("GROUPIFY_HOST").unwrap_or_else(|_| "https://groupify.dev".to_string());

    tracing::debug!("Generating JWT token for user: {}", user_profile.email);
    let token = generate_token(&user_profile.email, user_profile.display_name.as_deref().unwrap_or(""))?;
    tracing::debug!("JWT token generated successfully");

    let mut now = OffsetDateTime::now_utc();
    now += time::Duration::days(60);

    tracing::debug!("Retrieving GROUPIFY_HOST environment variable");
    let domain = std::env::var("GROUPIFY_HOST")
        .map_err(|e| {
            tracing::error!("GROUPIFY_HOST environment variable not set: {:?}", e);
            AppError::Unexpected(anyhow::anyhow!(e).context("GROUPIFY_HOST env var not set"))
        })?;

    tracing::debug!("Setting up authentication cookie for domain: {}", domain);
    let mut cookie = Cookie::new("auth-token", token);

    // Check if we're in development mode
    let is_development = std::env::var("ENVIRONMENT")
        .unwrap_or_else(|_| "production".to_string())
        .to_lowercase() == "development";

    if is_development {
        // Development settings - works with HTTP
        cookie.set_domain("localhost".to_string());
        cookie.set_same_site(SameSite::Lax); // More permissive for development
        cookie.set_secure(false); // Allow HTTP in development
    } else {
        // Production settings - requires HTTPS
        let cookie_domain = if domain.starts_with('.') {
            domain
        } else {
            format!(".{}", domain)
        };
        cookie.set_domain(cookie_domain);
        cookie.set_same_site(SameSite::None);
        cookie.set_secure(true);
    }
    
    cookie.set_path("/");
    cookie.set_expires(now);
    cookie.set_http_only(true);
    cookies.add(cookie);

    let protocol = if is_development { "http" } else { "https" };
    let redirect_url = format!(
        "{}://{}/dashboard?auth=success&provider=discord",
        protocol,
        frontend_url
    );

    tracing::info!("Discord OAuth callback completed successfully for: {}", user_profile.email);
    Ok(Redirect::to(&redirect_url))
}

#[tracing::instrument(name = "Discord login initiation")]
pub async fn discord_login(State(inner): State<InnerState>) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Initiating Discord OAuth login");

    let auth_url = crate::api::v1::oauth::generate_auth_url(
        &inner.oauth_clients.discord,
        &OAuthProvider::Discord,
    );

    tracing::debug!("Generated Discord auth URL: {}", auth_url);
    Ok(Redirect::to(&auth_url))
}

#[tracing::instrument(name = "Check Discord session", skip(inner, cookies))]
pub async fn check_discord_session(
    State(inner): State<InnerState>,
    cookies: Cookies,
) -> Result<Json<Value>, AppError> {
    tracing::info!("Checking Discord session status");

    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .and_then(|cookie| Some(cookie.value().to_string()))
        .ok_or_else(|| {
            tracing::warn!("No auth token found in cookies");
            AppError::Authentication(anyhow::anyhow!("No authentication token"))
        })?;

    let email = crate::api::v1::user::get_email_from_token(auth_token).await?;

    let session: Option<Session> = sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)",
    )
    .bind(&email)
    .fetch_optional(&db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to query session: {:?}", e);
        AppError::Database(anyhow::Error::new(e).context("SQLx operation failed"))
    })?;

    match session {
        Some(session) => {
            let is_expired = session.expires_at < chrono::Utc::now();
            tracing::info!(
                "Discord session found for user: {}, expired: {}",
                email,
                is_expired
            );

            Ok(Json(json!({
                "connected": true,
                "provider": "discord",
                "expired": is_expired,
                "expires_at": session.expires_at
            })))
        }
        None => {
            tracing::info!("No Discord session found for user: {}", email);
            Ok(Json(json!({
                "connected": false,
                "provider": "discord"
            })))
        }
    }
}
