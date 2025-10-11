use crate::api::v1::oauth::Session;
use crate::authentication::compute_password_hash;
use crate::api::v1::login::Claims;
use crate::errors::AppError; // Added
use crate::InnerState;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName};
use axum::http::{HeaderValue, StatusCode};
use axum::Json;
use chrono::NaiveDateTime;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Executor, FromRow, PgPool, Postgres, Transaction};
use tower_cookies::Cookies;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Option<String>,
    pub aud: Option<String>,
    pub role: Option<String>,
    pub email: String,
    pub encrypted_password: Option<String>,
    pub email_confirmed_at: Option<NaiveDateTime>,
    pub invited_at: Option<NaiveDateTime>,
    pub confirmation_token: Option<String>,
    pub confirmation_sent_at: Option<NaiveDateTime>,
    pub recovery_token: Option<String>,
    pub recovery_sent_at: Option<NaiveDateTime>,
    pub email_change_token_new: Option<String>,
    pub email_change: Option<String>,
    pub email_change_sent_at: Option<NaiveDateTime>,
    pub last_sign_in_at: Option<NaiveDateTime>,
    pub raw_app_meta_data: Option<String>,
    pub raw_user_meta_data: Option<String>,
    pub is_super_admin: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub phone: Option<String>,
    pub phone_confirmed_at: Option<NaiveDateTime>,
    pub phone_change: Option<String>,
    pub phone_change_token: Option<String>,
    pub confirmed_at: Option<NaiveDateTime>,
    pub email_change_token_current: Option<String>,
    pub email_change_confirm_status: Option<String>,
    pub banned_until: Option<String>,
    pub reauthentication_token: Option<String>,
    pub reauthentication_sent_at: Option<NaiveDateTime>,
    pub is_sso_user: Option<bool>,
    pub deleted_at: Option<NaiveDateTime>,
    pub display_name: Option<String>,
}

#[tracing::instrument(name = "Saving new user in the database", skip(user, transaction), err)]
pub async fn create_user(
    transaction: &mut Transaction<'_, Postgres>,
    user: User,
) -> Result<String, AppError> {
    let uuid = Uuid::new_v4().to_string();

    tracing::info!(
        "Attempting to create user with id {} and email {}",
        uuid,
        user.email
    );

    // First, check if user already exists
    let existing_user_check = sqlx::query_as::<_, User>(r#"SELECT * FROM users WHERE email = $1"#)
    .bind(&user.email)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|e| {
        tracing::error!("Failed to check for existing user: {}", e);
        AppError::Database(anyhow::Error::from(e).context("Failed to check for existing user"))
    })?;

    if existing_user_check.is_some() {
        tracing::warn!("Attempted to create user with existing email: {}", user.email);
        return Err(AppError::Conflict(format!("User with email '{}' already exists", user.email)));
    }

    let password_hash = compute_password_hash(user.encrypted_password.unwrap()).await?;

    let query = sqlx::query!(
        r#"INSERT INTO users (id, email, encrypted_password) VALUES ($1, $2, $3)"#,
        uuid,
        user.email,
        password_hash
    );

    transaction.execute(query).await.map_err(|e| {
        tracing::error!("Failed to insert user into database: {}", e);
        
        // Handle specific database constraint violations
        match &e {
            sqlx::Error::Database(db_err) => {
                if let Some(constraint) = db_err.constraint() {
                    match constraint {
                        "users_email_key" | "users_email_unique" => {
                            return AppError::Conflict(format!("User with email '{}' already exists", user.email));
                        }
                        _ => {
                            tracing::error!("Database constraint violation: {}", constraint);
                        }
                    }
                }
                
                // Check for duplicate key error codes (PostgreSQL specific)
                if let Some(code) = db_err.code() {
                    if code == "23505" { // unique_violation
                        return AppError::Conflict(format!("User with email '{}' already exists", user.email));
                    }
                }
            }
            _ => {}
        }
        
        AppError::Database(anyhow::Error::from(e).context("Failed to create user"))
    })?;

    tracing::info!("Successfully created user with id: {}", uuid);
    Ok(uuid)
}

#[tracing::instrument(name = "Get stored credentials", skip(email, pool))]
pub async fn get_stored_credentials(
    email: &str,
    pool: &PgPool,
) -> Result<User, AppError> { // Changed return type
    let row = sqlx::query_as::<_, User>(r#"SELECT * FROM users WHERE email = $1"#)
        .bind(email)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to get stored credentials")))?;

    Ok(row)
}

#[tracing::instrument(name = "Get user id from token", skip(confirmation_token, pool))]
pub async fn get_confirmation_token_from_user(
    pool: &PgPool,
    confirmation_token: String,
) -> Result<String, AppError> { // Changed return type
    let id = sqlx::query_as::<_, User>(r#" SELECT * FROM users WHERE confirmation_token = $1"#)
        .bind(confirmation_token)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to get confirmation token from user")))?
        .id
        .ok_or_else(|| AppError::NotFound("User ID not found for confirmation token".to_string()))?;

    Ok(id)
}

#[tracing::instrument(name = "Get user id from token", skip(confirmation_token, pool))]
pub async fn get_password_confirmation_token_from_user(
    pool: &PgPool,
    confirmation_token: String,
) -> Result<String, AppError> { // Changed return type
    let id = sqlx::query_as::<_, User>(r#" SELECT * FROM users WHERE recovery_token = $1"#)
        .bind(confirmation_token)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to get password confirmation token")))?
        .id
        .ok_or_else(|| AppError::NotFound("User ID not found for password recovery token".to_string()))?;

    Ok(id)
}

#[tracing::instrument(name = "Get user id from email", skip(email, pool))]
pub async fn get_user_id_from_email(
    pool: &PgPool,
    email: &str,
) -> Result<String, AppError> { // Changed return type
    let id = sqlx::query_as::<_, User>(r#" SELECT * FROM users WHERE email = $1"#)
        .bind(email)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to get user id from email")))?
        .id
        .ok_or_else(|| AppError::NotFound("User ID not found for email".to_string()))?;

    Ok(id)
}

#[tracing::instrument(name = "Get email from original email", skip(pool))]
pub async fn get_email_from_original_email(
    pool: &PgPool,
    original_email: &str,
) -> Result<String, AppError> {
    let session = sqlx::query_as::<_, Session>(r#"SELECT * FROM sessions WHERE original_email = $1"#)
        .bind(original_email)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to get session from original email")))?
        .user_id;
    
    tracing::info!("Email found for original email {}: user_id {}", original_email, session);

    let email = sqlx::query_scalar::<_, String>(r#"SELECT email FROM users u WHERE u.id = $1"#)
        .bind(session)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to get email from original email")))?;
    
    tracing::info!("Email found for original email {}: email {}", original_email, email);
    Ok(email)
}

#[tracing::instrument(name = "Get email from token", skip(token))]
pub async fn get_email_from_token(token: String) -> Result<String, AppError> { // Changed return type and error handling
    let secret = std::env::var("SECRET_TOKEN")
        .map_err(|e| AppError::Unexpected(anyhow::anyhow!(e).context("SECRET_TOKEN Env must be set")))?;
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256), // Specify algorithm, ensure it matches token generation
    )
    .map_err(|e| AppError::Authentication(anyhow::anyhow!(e).context("Failed to decode token")))?;

    Ok(token_data.claims.sub)
}

pub async fn get_user_id_from_token(token: String) -> Result<String, AppError> { // Changed return type and error handling
    let secret = std::env::var("SECRET_TOKEN")
        .map_err(|e| AppError::Unexpected(anyhow::anyhow!(e).context("SECRET_TOKEN Env must be set")))?;
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::new(Algorithm::HS256), // Specify algorithm, ensure it matches token generation
    )
    .map_err(|e| AppError::Unexpected(anyhow::anyhow!(e).context("Failed to decode token")))?;

    Ok(token_data.claims.user_id)
}

pub async fn get_language(headers: HeaderMap) -> Result<Json<Value>, (StatusCode, String)> {
    let header_value = match headers.get(HeaderName::from_static("accept-language")) {
        Some(value) => value.to_str().unwrap_or("").to_string(),
        None => String::new(),
    };

    let header_parts: Vec<&str> = header_value.split(|c| c == ',' || c == ';').collect();
    Ok(Json(json!({ "language": header_parts[1] })))
}

pub async fn delete_account(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Value>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .ok_or_else(|| AppError::Unexpected(anyhow::anyhow!("Missing auth-token cookie")));

    // Now get_user_id_from_token returns Result<String, AppError>
    let user_id = get_user_id_from_token(auth_token?).await?;

    sqlx::query!("DELETE FROM channels WHERE user_id = $1", &user_id)
        .execute(&db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to delete channels")))?;

    sqlx::query!("DELETE FROM groups WHERE user_id = $1", &user_id)
        .execute(&db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to delete groups")))?;

    sqlx::query!("DELETE FROM youtube_channels WHERE user_id = $1", &user_id)
        .execute(&db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to delete youtube_channels")))?;

    sqlx::query!("DELETE FROM sessions WHERE user_id = $1", &user_id)
        .execute(&db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to delete sessions")))?;

    sqlx::query!("DELETE FROM users WHERE id = $1", &user_id)
        .execute(&db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to delete user")))?;

    Ok(Json(json!({ "success": "true" })))
}
