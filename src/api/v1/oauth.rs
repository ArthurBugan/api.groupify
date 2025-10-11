use chrono::{DateTime, Utc};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sqlx::FromRow;
use chrono::TimeZone;

use crate::errors::AppError;

#[derive(Debug, Clone)]
pub enum OAuthProvider {
    Google,
    Discord,
}

impl OAuthProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::Discord => "discord",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub code: String,
    pub state: Option<String>,
}

#[derive(Debug, Deserialize, FromRow)]
pub struct Session {
    pub id: i32,
    pub user_id: String,
    pub session_id: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub original_email: Option<String>,
}

#[derive(Deserialize, sqlx::FromRow, Clone)]
pub struct UserProfile {
    pub email: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct OAuthClients {
    pub google: BasicClient,
    pub discord: BasicClient,
}

#[tracing::instrument(name = "Build Google OAuth client", skip(client_id, client_secret))]
pub fn build_google_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    tracing::info!("Building Google OAuth client");

    let redirect_url = std::env::var("GOOGLE_REDIRECT_URL")
        .unwrap_or_else(|_| "https://coolify.groupify.dev/api/auth/google_callback".to_string());

    tracing::debug!("Using Google redirect URL: {}", redirect_url);

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .expect("Invalid Google authorization endpoint URL"),
        Some(
            TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
                .expect("Invalid Google token endpoint URL"),
        ),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

#[tracing::instrument(name = "Build Discord OAuth client", skip(client_id, client_secret))]
pub fn build_discord_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    tracing::info!("Building Discord OAuth client");

    let redirect_url = std::env::var("DISCORD_REDIRECT_URL")
        .unwrap_or_else(|_| "https://coolify.groupify.dev/api/auth/discord_callback".to_string());

    tracing::debug!("Using Discord redirect URL: {}", redirect_url);

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://discord.com/api/oauth2/authorize".to_string())
            .expect("Invalid Discord authorization endpoint URL"),
        Some(
            TokenUrl::new("https://discord.com/api/oauth2/token".to_string())
                .expect("Invalid Discord token endpoint URL"),
        ),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

#[tracing::instrument(name = "Generate OAuth authorization URL")]
pub fn generate_auth_url(client: &BasicClient, provider: &OAuthProvider) -> String {
    let mut auth_request = client.authorize_url(oauth2::CsrfToken::new_random);

    match provider {
        OAuthProvider::Google => {
            auth_request = auth_request
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("https://www.googleapis.com/auth/youtube.readonly".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .set_response_type(&oauth2::ResponseType::new("code".to_string()))
                .add_extra_param("prompt", "consent")
                .add_extra_param("access_type", "offline");
        }
        OAuthProvider::Discord => {
            auth_request = auth_request
                .add_scope(Scope::new("identify".to_string()))
                .add_scope(Scope::new("email".to_string()));
        }
    }

    let (auth_url, _csrf_token) = auth_request.url();
    auth_url.to_string()
}

#[tracing::instrument(name = "Fetch user profile", skip(access_token), fields(provider = %provider.as_str()))]
pub async fn fetch_user_profile(
    access_token: &str,
    provider: &OAuthProvider,
) -> Result<UserProfile, AppError> {
    let client = Client::new();

    let (url, auth_header) = match provider {
        OAuthProvider::Google => (
            "https://www.googleapis.com/oauth2/v2/userinfo",
            format!("Bearer {}", access_token),
        ),
        OAuthProvider::Discord => (
            "https://discord.com/api/users/@me",
            format!("Bearer {}", access_token),
        ),
    };

    tracing::debug!("Fetching user profile from: {}", url);

    let response = client
        .get(url)
        .header("Authorization", auth_header)
        .send()
        .await
        .map_err(|e| {
            AppError::ExternalService(anyhow::anyhow!("Failed to fetch user profile: {}", e))
        })?;

    if !response.status().is_success() {
        tracing::error!("Failed to fetch user profile: HTTP {}", response.status());
        return Err(AppError::ExternalService(anyhow::anyhow!(
            "Failed to fetch user profile: HTTP {}",
            response.status()
        )));
    }

    let user_data: Value = response.json().await.map_err(|e| {
        AppError::ExternalService(anyhow::anyhow!("Failed to fetch user profile: {}", e))
    })?;

    tracing::debug!("Received user data: {:?}", user_data);

    let profile = match provider {
        OAuthProvider::Google => UserProfile {
            email: user_data["email"]
                .as_str()
                .ok_or_else(|| {
                    AppError::ExternalService(anyhow::anyhow!("No email in Google profile"))
                })?
                .to_string(),
            display_name: user_data["name"].as_str().map(|s| s.to_string()),
            avatar_url: user_data["picture"].as_str().map(|s| s.to_string()),
        },
        OAuthProvider::Discord => UserProfile {
            email: user_data["email"]
                .as_str()
                .ok_or_else(|| {
                    AppError::ExternalService(anyhow::anyhow!("No email in Discord profile"))
                })?
                .to_string(),
            display_name: user_data["username"].as_str().map(|s| s.to_string()),
            avatar_url: user_data["avatar"].as_str().map(|avatar_hash| {
                let user_id = user_data["id"].as_str().unwrap_or("0");
                format!(
                    "https://cdn.discordapp.com/avatars/{}/{}.png",
                    user_id, avatar_hash
                )
            }),
        },
    };

    tracing::info!("Successfully fetched profile for: {}", profile.email);
    Ok(profile)
}

#[tracing::instrument(name = "Update user session", skip(db, access_token, refresh_token), fields(email = %email, provider = %provider.as_str()))]
pub async fn update_user_session(
    db: &sqlx::PgPool,
    email: &str,
    access_token: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
    provider: &OAuthProvider,
    original_email: &str,
) -> Result<(), AppError> {
    tracing::info!("Updating user session for provider: {}", provider.as_str());

    // First, get or create the user
    let user_id = get_or_create_user(db, email, provider).await?;

    let _ = sqlx::query!(
        r#"
        INSERT INTO sessions (user_id, session_id, refresh_token, expires_at, provider, original_email)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id, provider) DO UPDATE
        SET 
            session_id = EXCLUDED.session_id,
            refresh_token = EXCLUDED.refresh_token,
            expires_at = EXCLUDED.expires_at
        "#,
        user_id,
        access_token,
        refresh_token,
        chrono::Utc.from_utc_datetime(&expires_at),
        provider.as_str(),
        original_email,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to upsert user session: {}", e)))?;

    tracing::info!("Successfully updated session for user: {}", email);
    Ok(())
}

#[tracing::instrument(name = "Get or create user", skip(db), fields(email = %email, provider = %provider.as_str()))]
async fn get_or_create_user(
    db: &sqlx::PgPool,
    email: &str,
    provider: &OAuthProvider,
) -> Result<String, AppError> {
    // Try to find existing user
    let user = sqlx::query_scalar::<_, String>("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(db)
        .await
        .map_err(|e| {
            AppError::Database(anyhow::Error::from(e).context("Failed to fetch user by email"))
        })?;

    if let Some(user_id) = user {
        tracing::debug!("Found existing user: {}", user_id);
        return Ok(user_id);
    }

    // Create new user
    let user_id = uuid::Uuid::new_v4().to_string();

    sqlx::query!(
        r#"
        INSERT INTO users (id, email, is_sso_user, created_at, updated_at)
        VALUES ($1, $2, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        "#,
        user_id,
        email
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to create user")))?;

    tracing::info!("Created new user: {} for email: {}", user_id, email);
    Ok(user_id)
}
