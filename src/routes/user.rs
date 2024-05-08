use crate::utils::internal_error;
use axum::http::StatusCode;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use sqlx::{Executor, FromRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
pub struct User {
    pub id: Option<String>,
    pub aud: Option<String>,
    pub role: Option<String>,
    pub email: String,
    pub encrypted_password: String,
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

#[tracing::instrument(name = "Saving new user in the database", skip(user, transaction))]
pub async fn create_user(
    transaction: &mut Transaction<'_, Postgres>,
    user: User,
) -> Result<String, (StatusCode, String)> {
    let uuid = Uuid::new_v4().to_string();

    tracing::debug!(
        "user id {} \
         user email {}\
         user password {:?}",
        uuid,
        user.email,
        user.encrypted_password
    );

    let encrypted_password = sha3::Sha3_256::digest(user.encrypted_password.as_bytes());

    let encrypted_password = format!("{:x}", encrypted_password);

    let query = sqlx::query_as::<_, User>(
        r#"INSERT INTO users (id, email, encrypted_password) values($1, $2, $3) returning *"#,
    )
    .bind(&uuid)
    .bind(user.email)
    .bind(encrypted_password);

    transaction.execute(query).await.map_err(internal_error)?;
    Ok(uuid)
}

#[tracing::instrument(name = "Get stored credentials", skip(email, pool))]
pub async fn get_stored_credentials(
    email: &str,
    pool: &PgPool,
) -> Result<User, (StatusCode, String)> {
    let row = sqlx::query_as::<_, User>(r#"SELECT * FROM users WHERE email = $1"#)
        .bind(email)
        .fetch_one(pool)
        .await
        .map_err(internal_error)?;

    Ok(row)
}

#[tracing::instrument(name = "Get user id from token", skip(confirmation_token, pool))]
pub async fn get_confirmation_token_from_user(
    pool: &PgPool,
    confirmation_token: String,
) -> Result<String, (StatusCode, String)> {
    let id = sqlx::query_as::<_, User>(r#" SELECT * FROM users WHERE confirmation_token = $1"#)
        .bind(confirmation_token)
        .fetch_one(pool)
        .await
        .map(|user| user.id)
        .map_err(internal_error)?;

    Ok(id.unwrap_or_else(|| String::new()))
}

#[tracing::instrument(name = "Get user id from token", skip(confirmation_token, pool))]
pub async fn get_password_confirmation_token_from_user(
    pool: &PgPool,
    confirmation_token: String,
) -> Result<String, (StatusCode, String)> {
    let id = sqlx::query_as::<_, User>(r#" SELECT * FROM users WHERE recovery_token = $1"#)
        .bind(confirmation_token)
        .fetch_one(pool)
        .await
        .map(|user| user.id)
        .map_err(internal_error)?;

    Ok(id.unwrap_or_else(|| String::new()))
}
