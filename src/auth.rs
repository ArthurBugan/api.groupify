use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    Json,
};
use chrono::{Duration, Local};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, RedirectUrl, RefreshToken, RequestTokenError, TokenResponse, TokenUrl,
};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{postgres::PgQueryResult, PgPool, Row};
use tower_cookies::Cookies;

use crate::{errors::AppError, routes::get_email_from_token, InnerState};

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
}

#[derive(Deserialize, sqlx::FromRow, Clone)]
pub struct UserProfile {
    email: String,
}

#[tracing::instrument(name = "Build OAuth client", skip(client_id, client_secret))]
pub fn build_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    tracing::info!("Building OAuth client for Google authentication");
    tracing::debug!("Setting up OAuth client with redirect URL");
    
    let redirect_url = "https://coolify.groupify.dev/api/auth/google_callback";
    //let redirect_url = "http://localhost:3001/auth/google_callback";

    tracing::debug!("Using redirect URL: {}", redirect_url);

    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .expect("Invalid authorization endpoint URL"),
        Some(
            TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
                .expect("Invalid token endpoint URL"),
        ),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string()).unwrap());

    tracing::info!("OAuth client successfully built");
    client
}

#[tracing::instrument(name = "Google OAuth callback", skip(inner, query), fields(code_length = query.code.len()))]
pub async fn google_callback(
    State(inner): State<InnerState>,
    Query(query): Query<AuthRequest>,
) -> Result<impl IntoResponse, AppError> {
    tracing::info!("Processing Google OAuth callback");
    
    let InnerState {
        db, oauth_client, ..
    } = inner;
    let domain = std::env::var("GROUPIFY_HOST").expect("GROUPIFY_HOST must be set.");

    tracing::debug!("Domain: {}, Authorization code received (length: {})", domain, query.code.len());
    tracing::info!("domain {:?} code {:?}", domain, query.code);

    tracing::debug!("Exchanging authorization code for access token");
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange authorization code: {:?}", e);
            tracing::error!("map error {:?}", e);
            match e {
                RequestTokenError::ServerResponse(server_response) => {
                    // Extract the error response from the server
                    let error_description = server_response.error_description();
                    let error_code = server_response.error();

                    tracing::error!("Server response error: {:?}", error_code);
                    println!("Server response error: {:?}", error_code);
                    if let Some(description) = error_description {
                        tracing::error!("Error description: {:?}", description);
                        println!("Error description: {:?}", description);
                    }
                }
                RequestTokenError::Request(request_error) => {
                    // This could be a network or other I/O error
                    tracing::error!("Request error during token exchange: {:?}", request_error);
                    println!("Request error: {:?}", request_error);
                }
                RequestTokenError::Parse(parse_error, response) => {
                    // Error occurred while parsing the response
                    tracing::error!("Parse error: {:?}, Response: {:?}", parse_error, response);
                    println!("Parse error: {:?}", parse_error);
                    println!("Response body: {:?}", response);
                }
                _ => {
                    // Fallback for other kinds of errors (if any)
                    tracing::error!("Unexpected OAuth error: {:?}", e);
                    println!("An unexpected error occurred: {:?}", e);
                }
            }

            AppError::ExternalService(anyhow::anyhow!("Failed to exchange authorization code"))
        })?;

    tracing::info!("Successfully exchanged authorization code for token");
    tracing::info!("Passou do oauth {:?}", token);

    tracing::debug!("Fetching user profile from Google");
    let profile = fetch_user_profile(&token.access_token().secret()).await?;
    tracing::info!("Retrieved user profile for email: {}", profile.email);
    
    let max_age = calculate_token_expiry(token.expires_in());
    tracing::debug!("Calculated token expiry: {:?}", max_age);

    let refresh_token = token
        .refresh_token()
        .ok_or_else(|| {
            tracing::error!("No refresh token received from OAuth provider");
            AppError::Validation(String::from("Token not found"))
        })?;

    tracing::debug!("Updating user session in database");
    update_user_session(
        &db,
        &profile.email,
        token.access_token().secret(),
        max_age,
        refresh_token.secret(),
    )
    .await?;

    let redirect_str = format!("https://{}/dashboard/groups", domain);
    tracing::info!("Redirecting user to: {}", redirect_str);

    Ok(Redirect::to(redirect_str.as_str()))
}

#[tracing::instrument(name = "Fetch user profile from Google", skip(access_token), fields(token_length = access_token.len()))]
async fn fetch_user_profile(access_token: &str) -> Result<UserProfile, AppError> {
    tracing::info!("Fetching user profile from Google API");
    tracing::debug!("Making request to Google userinfo endpoint");
    
    let req = Client::new();
    let response = req.get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to send request to Google userinfo API: {:?}", e);
            AppError::Unexpected(e.into())
        })?;

    tracing::debug!("Received response from Google API, parsing JSON");
    let profile = response
        .json::<UserProfile>()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse user profile JSON: {:?}", e);
            AppError::Unexpected(e.into())
        })?;

    tracing::info!("Successfully fetched user profile for: {}", profile.email);
    Ok(profile)
}

#[tracing::instrument(name = "Calculate token expiry", fields(expires_in_seconds = expires_in.as_ref().map(|d| d.as_secs())))]
fn calculate_token_expiry(expires_in: Option<std::time::Duration>) -> chrono::NaiveDateTime {
    tracing::debug!("Calculating token expiry time");
    
    match expires_in {
        Some(secs) => {
            let duration = Duration::seconds(secs.as_secs().try_into().unwrap_or(0));
            let expiry = Local::now().naive_local() + duration;
            tracing::debug!("Token will expire at: {:?} (in {} seconds)", expiry, secs.as_secs());
            expiry
        }
        None => {
            let expiry = Local::now().naive_local();
            tracing::warn!("No expiry time provided, using current time: {:?}", expiry);
            expiry
        }
    }
}

#[tracing::instrument(name = "Update user session", skip(db, access_token, refresh_token), fields(email = %email, expires_at = %expires_at))]
async fn update_user_session(
    db: &sqlx::PgPool,
    email: &str,
    access_token: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
) -> Result<(), AppError> {
    tracing::info!("Updating user session in database");
    tracing::debug!("Deleting existing sessions for user: {}", email);
    
    sqlx::query("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)")
        .bind(email)
        .execute(db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete existing sessions: {:?}", e);
            AppError::Database(anyhow::Error::new(e).context("SQLx operation failed"))
        })?;

    tracing::debug!("Inserting new session record");
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
    .map_err(|e| {
        tracing::error!("Failed to insert/update session: {:?}", e);
        AppError::Database(anyhow::Error::new(e).context("SQLx operation failed"))
    })?;

    // Check how many rows were affected
    if result.rows_affected() == 0 {
        tracing::error!("No rows were affected during session update");
        return Err(AppError::Database(anyhow::anyhow!("No rows were affected")));
    }

    tracing::info!("Successfully updated session for user: {} (rows affected: {})", email, result.rows_affected());
    Ok(())
}

#[tracing::instrument(name = "Renew OAuth token", skip(db, oauth_client), fields(email = %email))]
pub async fn renew_token(
    db: PgPool,
    oauth_client: BasicClient,
    email: String,
) -> Result<(), AppError> {
    tracing::info!("Renewing OAuth token for user: {}", email);
    
    tracing::debug!("Fetching refresh token from database");
    let refresh_token = fetch_refresh_token(&db, &email).await?;

    tracing::debug!("Exchanging refresh token for new access token");
    let token = oauth_client
        .exchange_refresh_token(&refresh_token)
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            tracing::error!("Failed to exchange refresh token: {:?}", err);
            tracing::error!("Request error: {:?}", err);
            AppError::ExternalService(anyhow::anyhow!("Failed to exchange refresh token"))
        })?;

    tracing::info!("Successfully renewed token for user: {}", email);
    let max_age = calculate_token_expiry(token.expires_in());

    tracing::debug!("Updating session with new token");
    update_user_session(
        &db,
        &email,
        token.access_token().secret(),
        max_age,
        refresh_token.secret(),
    )
    .await?;

    tracing::info!("Token renewal completed successfully for user: {}", email);
    Ok(())
}

#[tracing::instrument(name = "Fetch refresh token", skip(db), fields(email = %email))]
async fn fetch_refresh_token(db: &sqlx::PgPool, email: &str) -> Result<RefreshToken, AppError> {
    tracing::debug!("Fetching refresh token from database for user: {}", email);
    
    let refresh_token: String = sqlx::query("SELECT refresh_token FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)")
      .bind(email)
      .fetch_one(db)
      .await
      .map_err(|e| {
          tracing::error!("Failed to fetch refresh token: {:?}", e);
          AppError::Database(anyhow::Error::new(e).context("SQLx operation failed"))
      })?
      .get("refresh_token");

    tracing::debug!("Successfully retrieved refresh token for user: {}", email);
    Ok(RefreshToken::new(refresh_token))
}

#[tracing::instrument(name = "Check Google session", skip(inner, cookies))]
pub async fn check_google_session(
    State(inner): State<InnerState>,
    cookies: Cookies,
) -> Result<Json<Value>, AppError> {
    tracing::info!("Checking Google session validity");
    
    let InnerState { db, .. } = inner;

    tracing::debug!("Extracting auth token from cookies");
    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.clone().len() == 0 {
        tracing::warn!("No auth token found in cookies");
        return Err(AppError::Validation(String::from("No auth token found")));
    }

    tracing::debug!("Auth token found, extracting email");
    let email = get_email_from_token(auth_token).await;

    let email = match email {
        Ok(email) => {
            tracing::debug!("Successfully extracted email from token: {}", email);
            email
        }
        Err(e) => {
            tracing::error!("Failed to extract email from token: {:?}", e);
            return Err(AppError::Validation(String::from("Invalid auth token")));
        }
    };

    tracing::debug!("Checking session existence in database");
    let session: PgQueryResult = sqlx::query("SELECT refresh_token FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)")
        .bind(&email)
        .execute(&db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to query session: {:?}", e);
            AppError::Database(anyhow::Error::new(e).context("SQLx operation failed"))
        })?;

    tracing::debug!("Session query result: {:?}", session);
    tracing::info!("session {:?}", session);

    if session.rows_affected() == 0 {
        tracing::warn!("No session found for user: {}", email);
        return Err(AppError::Validation(String::from("Session not found")));
    }

    tracing::info!("Valid session found for user: {}", email);
    return Ok(Json(json!({ "success": "true" })));
}
