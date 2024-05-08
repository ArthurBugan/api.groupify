use crate::routes::{
    generate_subscription_token, get_password_confirmation_token_from_user, get_stored_credentials,
    User,
};
use crate::utils::internal_error;
use anyhow::Context;
use std::collections::HashMap;

use crate::email::EmailClient;
use crate::InnerState;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use sqlx::{Executor, PgPool, Postgres, Transaction};
use url::quirks::password;

#[derive(Deserialize)]
pub struct Credentials {
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct PasswordChange {
    pub forget_password_token: String,
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
            expected_password_hash = user.encrypted_password;
        }
        Err(error) => {
            // If the Result is Err, error will contain the Error
            println!("Error: {:?}", error);
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
) -> Result<Json<String>, (StatusCode, String)> {
    let InnerState { email_client, db } = inner;

    let mut transaction = db.begin().await.map_err(internal_error)?;

    let user_id = get_stored_credentials(&user.email, &db).await?;

    let subscription_token = generate_subscription_token();

    store_token(&mut transaction, &user_id.id, &subscription_token).await?;

    transaction.commit().await.map_err(internal_error)?;

    let resp = send_forget_password_email(&email_client, user, &subscription_token).await?;

    Ok(Json("OK".to_owned()))
}

#[tracing::instrument(
    name = "Send a confirmation email to a new subscriber",
    skip(email_client, forget_password_token)
)]
pub async fn send_forget_password_email(
    email_client: &EmailClient,
    user: User,
    forget_password_token: &str,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let confirmation_link = format!(
        "{}/forget-password/confirm/{}",
        &String::from("https://groupify.dev"),
        forget_password_token
    );

    let template_id = "35815619";

    let mut template_model = HashMap::new();
    template_model.insert("product_name".to_owned(), "Groupify".to_owned());
    template_model.insert("action_url".to_owned(), confirmation_link);
    template_model.insert("support_email".to_owned(), "admin@groupify.dev".to_owned());
    template_model.insert(
        "login_url".to_owned(),
        "https://groupify.dev/login".to_owned(),
    );

    let resp = email_client
        .send_email(&user.email, "forget-password", template_model, template_id)
        .await
        .map_err(internal_error)?;

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

#[tracing::instrument(name = "Change password", skip(inner, password_change))]
pub async fn change_password(
    State(inner): State<InnerState>,
    Json(password_change): Json<PasswordChange>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let subscriber_id =
        get_password_confirmation_token_from_user(&db, password_change.forget_password_token)
            .await?;

    if password_change.password != password_change.password_confirmation {
        return Err((
            StatusCode::BAD_REQUEST,
            "Passwords are different".to_string(),
        ));
    }

    let password_hash = compute_password_hash(password_change.password)?;

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
    .map_err(internal_error)?;

    return Ok((StatusCode::OK, "Password successfully changed.".to_string()));
}

fn compute_password_hash(password: String) -> Result<String, (StatusCode, String)> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap(),
    )
    .hash_password(password.as_bytes(), &salt)
    .map_err(internal_error)?
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
) -> Result<(), (StatusCode, String)> {
    let query = sqlx::query_as::<_, User>(r#" UPDATE users SET recovery_token = $1, recovery_sent_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $2"#)
        .bind(&subscription_token)
        .bind(subscriber_id);

    transaction.execute(query).await.map_err(internal_error)?;
    Ok(())
}
