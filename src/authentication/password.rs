use crate::routes::{
    generate_subscription_token, get_password_confirmation_token_from_user, get_stored_credentials,
    User,
};
use crate::errors::AppError;
use anyhow::{Context};
use std::collections::HashMap;

use crate::email::EmailClient;
use crate::InnerState;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{Executor, PgPool, Postgres, Transaction};


#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct PasswordChange {
    pub password: String,
    pub password_confirmation: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials.")]
    InvalidCredentials(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[tracing::instrument(name = "Validate credentials", skip(credentials, pool))]
pub async fn validate_credentials(
    credentials: &Credentials,
    pool: &PgPool,
) -> Result<String, AuthError> {
    let mut user_id = None;
    let mut expected_password_hash = String::from(
        "$argon2id$v=19$m=15000,t=2,p=1$\
        gZiV/M1gPc22ElAH/Jh1Hw$\
        CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno"
            .to_string(),
    );

    match get_stored_credentials(&credentials.email, pool).await {
        Ok(user) => {
            // If the Result is Ok, user will contain the User
            user_id = user.id;
            expected_password_hash = user.encrypted_password.unwrap();
        }
        Err(error) => {
            // If the Result is Err, error will contain the Error
            tracing::debug!("Error: {:?}", error);
        }
    }

    verify_password_hash(&expected_password_hash, &credentials.password)?;

    user_id
        .ok_or_else(|| anyhow::anyhow!("Unknown username."))
        .map_err(AuthError::InvalidCredentials)
}

pub async fn forget_password(
    State(inner): State<InnerState>,
    Json(user): Json<User>,
) -> Result<Json<Value>, AppError> {
    let InnerState {
        email_client, db, ..
    } = inner;

    let mut transaction = db.begin().await.context("Failed to begin database transaction.")?;

    let user_id_obj = get_stored_credentials(&user.email, &db).await?;

    let subscription_token = generate_subscription_token();

    store_token(&mut transaction, &user_id_obj.id, &subscription_token).await?;

    transaction.commit().await.context("Failed to commit database transaction.")?;

    send_forget_password_email(&email_client, user, &subscription_token).await?;

    return Ok(Json(json!({ "success": true })))
}

#[tracing::instrument(
    name = "Send a confirmation email to a new subscriber",
    skip(email_client, forget_password_token)
)]
pub async fn send_forget_password_email(
    email_client: &EmailClient,
    user: User,
    forget_password_token: &str,
) -> Result<reqwest::Response, AppError> {
    let confirmation_link = format!(
        "{}/forget-password/confirm/{}",
        &String::from("https://groupify.dev"),
        forget_password_token
    );

    let template_id = 3;

    let mut template_model = HashMap::new();
    template_model.insert("product_name".to_owned(), "Groupify".to_owned());
    template_model.insert("action_url".to_owned(), confirmation_link);
    template_model.insert("support_email".to_owned(), "admin@groupify.dev".to_owned());
    template_model.insert(
        "login_url".to_owned(),
        "https://groupify.dev/login".to_owned(),
    );

    let resp = email_client
        .send_email(&user.email, template_model, template_id)
        .await
        .context("Failed to send forget password email.")?;

    Ok(resp)
}

#[tracing::instrument(
    name = "Validate credentials",
    skip(expected_password_hash, password_candidate)
)]
fn verify_password_hash(
    expected_password_hash: &str,
    password_candidate: &str,
) -> Result<(), AuthError> {
    let expected_password_hash = PasswordHash::new(expected_password_hash)
        .context("Failed to parse hash in PHC string format.")?;

    Argon2::default()
        .verify_password(password_candidate.as_bytes(), &expected_password_hash)
        .context("Invalid password.")
        .map_err(AuthError::InvalidCredentials)
}

#[tracing::instrument(
    name = "Change password",
    skip(inner, password_change, forget_password_token)
)]
pub async fn change_password(
    State(inner): State<InnerState>,
    Path(forget_password_token): Path<String>,
    Json(password_change): Json<PasswordChange>,
) -> Result<Json<Value>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    // Assuming get_password_confirmation_token_from_user returns Result<_, AppError> or compatible
    let subscriber_id =
        get_password_confirmation_token_from_user(&db, forget_password_token).await?;

    if password_change.password != password_change.password_confirmation {
        return Err(AppError::Validation(anyhow::anyhow!("Passwords are different").to_string()));
    }

    let password_hash = compute_password_hash(password_change.password).await?;

    sqlx::query_as::<_, User>(
        r#"UPDATE users
        SET encrypted_password = $1,
        updated_at = CURRENT_TIMESTAMP,
        recovery_token = null,
        recovery_sent_at = null
        WHERE id = $2
        "#,
    )
    .bind(&password_hash)
    .bind(&subscriber_id)
    .fetch_optional(&db)
    .await
    .context("Failed to update password in database.")?;

    let success = String::from("Password changed");

    Ok(Json(json!({"data": success.to_string()})))
}

pub async fn compute_password_hash(password: String) -> Result<String, AppError> { // Changed return type
    let salt = SaltString::generate(&mut rand::thread_rng());
    let params = Params::new(15000, 2, 1, None)
        .map_err(|e| AppError::Unexpected(anyhow::Error::new(e).context("Failed to create Argon2 params")))?;
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
    .hash_password(password.as_bytes(), &salt)
    .map_err(|e| AppError::Unexpected(anyhow::Error::new(e).context("Failed to hash password")))?
    .to_string();
    Ok(password_hash)
}

#[tracing::instrument(
    name = "Store subscription token in the database",
    skip(subscription_token, transaction)
)]
pub async fn store_token(
    transaction: &mut Transaction<'_, Postgres>,
    subscriber_id: &Option<String>,
    subscription_token: &str,
) -> Result<(), AppError> { // Changed return type
    let query = sqlx::query_as::<_, User>(r#" UPDATE users SET recovery_token = $1, recovery_sent_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $2"#)
        .bind(&subscription_token)
        .bind(subscriber_id);

    transaction.execute(query).await.context("Failed to store token in database.")?;
    Ok(())
}
