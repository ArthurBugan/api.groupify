use crate::authentication::compute_password_hash;
use crate::routes::Claims;
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

pub trait HeaderValueExt {
    fn to_string(&self) -> String;
}

impl HeaderValueExt for HeaderValue {
    fn to_string(&self) -> String {
        self.to_str().unwrap_or_default().to_string()
    }
}

#[tracing::instrument(name = "Saving new user in the database", skip(user, transaction))]
pub async fn create_user(
    transaction: &mut Transaction<'_, Postgres>,
    user: User,
) -> Result<String, AppError> { // Changed return type
    let uuid = Uuid::new_v4().to_string();

    tracing::info!(
        "user id {} \
         user email {}\
         user password {:?}",
        uuid,
        user.email,
        user.encrypted_password
    );

    let password_hash = compute_password_hash(user.encrypted_password.unwrap()).await?;

    let query = sqlx::query_as::<_, User>(
        r#"INSERT INTO users (id, email, encrypted_password) values($1, $2, $3) returning *"#,
    )
    .bind(&uuid)
    .bind(user.email)
    .bind(password_hash);

    transaction.execute(query).await.map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to create user")))?;
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
        // Consider returning AppError::AuthError if token is missing
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
