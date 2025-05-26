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

pub fn build_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    let redirect_url = "https://api.groupify.dev/auth/google_callback";
    //let redirect_url = "http://localhost:3001/auth/google_callback";

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
) -> Result<impl IntoResponse, AppError> {
    let InnerState {
        db, oauth_client, ..
    } = inner;
    let domain = std::env::var("GROUPIFY_HOST").expect("GROUPIFY_HOST must be set.");

    tracing::info!("domain {:?} code {:?}", domain, query.code);

    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            tracing::error!("map error {:?}", e);
            match e {
                RequestTokenError::ServerResponse(server_response) => {
                    // Extract the error response from the server
                    let error_description = server_response.error_description();
                    let error_code = server_response.error();

                    println!("Server response error: {:?}", error_code);
                    if let Some(description) = error_description {
                        println!("Error description: {:?}", description);
                    }
                }
                RequestTokenError::Request(request_error) => {
                    // This could be a network or other I/O error
                    println!("Request error: {:?}", request_error);
                }
                RequestTokenError::Parse(parse_error, response) => {
                    // Error occurred while parsing the response
                    println!("Parse error: {:?}", parse_error);
                    println!("Response body: {:?}", response);
                }
                _ => {
                    // Fallback for other kinds of errors (if any)
                    println!("An unexpected error occurred: {:?}", e);
                }
            }

            AppError::ExternalService(anyhow::anyhow!("Failed to exchange authorization code"))
        })?;

    tracing::info!("Passou do oauth {:?}", token);

    let profile = fetch_user_profile(&token.access_token().secret()).await?;
    let max_age = calculate_token_expiry(token.expires_in());

    let refresh_token = token
        .refresh_token()
        .ok_or(AppError::Validation(String::from("Token not found")))?;

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

async fn fetch_user_profile(access_token: &str) -> Result<UserProfile, AppError> {
    let req = Client::new();
    req.get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| AppError::Unexpected(e.into()))?
        .json::<UserProfile>()
        .await
        .map_err(|e| AppError::Unexpected(e.into()))
}

fn calculate_token_expiry(expires_in: Option<std::time::Duration>) -> chrono::NaiveDateTime {
    match expires_in {
        Some(secs) => {
            let duration = Duration::seconds(secs.as_secs().try_into().unwrap_or(0));
            Local::now().naive_local() + duration
        }
        None => Local::now().naive_local(),
    }
}

async fn update_user_session(
    db: &sqlx::PgPool,
    email: &str,
    access_token: &str,
    expires_at: chrono::NaiveDateTime,
    refresh_token: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1)")
        .bind(email)
        .execute(db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::new(e).context("SQLx operation failed")))?;

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
    .map_err(|e| AppError::Database(anyhow::Error::new(e).context("SQLx operation failed")))?;

    // Check how many rows were affected
    if result.rows_affected() == 0 {
        return Err(AppError::Database(anyhow::anyhow!("No rows were affected")));
    }

    Ok(())
}

pub async fn renew_token(
    db: PgPool,
    oauth_client: BasicClient,
    email: String,
) -> Result<(), AppError> {
    let refresh_token = fetch_refresh_token(&db, &email).await?;

    let token = oauth_client
        .exchange_refresh_token(&refresh_token)
        .request_async(async_http_client)
        .await
        .map_err(|err| {
            tracing::error!("Request error: {:?}", err);
            AppError::ExternalService(anyhow::anyhow!("Failed to exchange refresh token"))
        })?;

    let max_age = calculate_token_expiry(token.expires_in());

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

async fn fetch_refresh_token(db: &sqlx::PgPool, email: &str) -> Result<RefreshToken, AppError> {
    let refresh_token: String = sqlx::query("SELECT refresh_token FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)")
      .bind(email)
      .fetch_one(db)
      .await
      .map_err(|e| AppError::Database(anyhow::Error::new(e).context("SQLx operation failed")))?
      .get("refresh_token");

    Ok(RefreshToken::new(refresh_token))
}

pub async fn check_google_session(
    State(inner): State<InnerState>,
    cookies: Cookies,
) -> Result<Json<Value>, AppError> {
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.clone().len() == 0 {
        return Err(AppError::Validation(String::from("No auth token found")));
    }

    let email = get_email_from_token(auth_token).await;

    let session: PgQueryResult = sqlx::query("SELECT refresh_token FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)")
        .bind(email.unwrap())
        .execute(&db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::new(e).context("SQLx operation failed")))?;

    tracing::debug!("session {:?}", session);

    if session.rows_affected() == 0 {
        return Err(AppError::Validation(String::from("Session not found")));
    }

    return Ok(Json(json!({ "success": "true" })));
}
