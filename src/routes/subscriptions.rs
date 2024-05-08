use crate::utils::internal_error;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha3::Digest;
use sqlx::{Executor, Postgres, Transaction};
use std::collections::HashMap;

use crate::routes::{create_user, User};
use crate::InnerState;

use crate::email::EmailClient;

pub async fn subscribe(
    State(inner): State<InnerState>,
    Json(user): Json<User>,
) -> Result<Json<String>, (StatusCode, String)> {
    let InnerState { email_client, db } = inner;

    let mut transaction = db.begin().await.map_err(internal_error)?;

    let user_id = create_user(&mut transaction, user.clone()).await?;
    let subscription_token = generate_subscription_token();

    store_token(&mut transaction, &user_id, &subscription_token).await?;

    transaction.commit().await.map_err(internal_error)?;

    let resp = send_confirmation_email(&email_client, user, &subscription_token).await?;

    Ok(Json("OK".to_owned()))
}

pub fn generate_subscription_token() -> String {
    let mut rng = thread_rng();
    std::iter::repeat_with(|| rng.sample(Alphanumeric))
        .map(char::from)
        .take(56)
        .collect()
}

#[tracing::instrument(
    name = "Send a confirmation email to a new subscriber",
    skip(email_client, subscription_token)
)]
pub async fn send_confirmation_email(
    email_client: &EmailClient,
    user: User,
    subscription_token: &str,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let confirmation_link = format!(
        "{}/subscriptions/confirm?subscription_token={}",
        &String::from("https://groupify.dev"),
        subscription_token
    );

    let template_id = "35795627";

    let mut template_model = HashMap::new();
    template_model.insert("product_name".to_owned(), "Groupify".to_owned());
    template_model.insert("action_url".to_owned(), confirmation_link);
    template_model.insert("support_email".to_owned(), "admin@groupify.dev".to_owned());
    template_model.insert(
        "login_url".to_owned(),
        "https://groupify.dev/login".to_owned(),
    );

    let resp = email_client
        .send_email(&user.email, "welcome-email", template_model, template_id)
        .await
        .map_err(internal_error)?;

    Ok(resp)
}

#[tracing::instrument(
    name = "Store subscription token in the database",
    skip(subscription_token, transaction)
)]
pub async fn store_token(
    transaction: &mut Transaction<'_, Postgres>,
    subscriber_id: &str,
    subscription_token: &str,
) -> Result<(), (StatusCode, String)> {
    let query = sqlx::query_as::<_, User>(r#" UPDATE users SET confirmation_token = $1, updated_at = CURRENT_TIMESTAMP, confirmation_sent_at = CURRENT_TIMESTAMP WHERE id = $2"#)
        .bind(&subscription_token)
        .bind(subscriber_id);

    transaction.execute(query).await.map_err(internal_error)?;
    Ok(())
}
