use crate::routes::{get_confirmation_token_from_user, User};
use crate::errors::AppError; // Added
use crate::InnerState;
use axum::extract::{Path, State};
use axum::Json;
use sqlx::PgPool;

#[derive(serde::Deserialize)]
pub struct Parameters {
    subscription_token: String,
}

#[tracing::instrument(name = "Confirm a pending subscriber", skip(subscription_token, inner), fields(subscription_token_length = subscription_token.len()))]
pub async fn confirm(
    State(inner): State<InnerState>,
    Path(subscription_token): Path<String>,
) -> Result<Json<String>, AppError> {
    tracing::info!("Starting subscription confirmation process");
    let InnerState { db, .. } = inner;

    tracing::debug!("Retrieving subscriber ID from confirmation token");
    let subscriber_id = get_confirmation_token_from_user(&db, subscription_token).await?;
    tracing::info!("Found subscriber ID: {}", subscriber_id);

    tracing::debug!("Confirming subscriber in database");
    let user_id_string = confirm_subscriber(&db, subscriber_id).await?;
    tracing::info!("Subscription confirmed successfully for user ID: {}", user_id_string);

    Ok(Json(user_id_string))
}

#[tracing::instrument(name = "Mark subscriber as confirmed", skip(subscriber_id, pool), fields(subscriber_id = %subscriber_id))]
pub async fn confirm_subscriber(
    pool: &PgPool,
    subscriber_id: String,
) -> Result<String, AppError> {
    tracing::info!("Marking subscriber as confirmed: {}", subscriber_id);
    
    tracing::debug!("Executing database update to confirm subscriber");
    let user = sqlx::query_as::<_, User>(r#"UPDATE users SET email_confirmed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 returning *"#)
        .bind(&subscriber_id)
        .fetch_one(pool)
        .await
        .map_err(|e| {
            tracing::error!("Database error while confirming subscriber {}: {:?}", subscriber_id, e);
            AppError::Database(anyhow::Error::from(e).context("Failed to confirm subscriber"))
        })?;

    let user_id = user.id
        .ok_or_else(|| {
            tracing::error!("User ID not found after confirmation for subscriber: {}", subscriber_id);
            AppError::NotFound("User ID not found after confirmation".to_string())
        })?;

    tracing::info!("Successfully confirmed subscriber: {}", subscriber_id);
    Ok(user_id)
}
