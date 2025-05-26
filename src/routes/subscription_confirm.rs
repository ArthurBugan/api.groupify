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

#[tracing::instrument(name = "Confirm a pending subscriber", skip(subscription_token, inner))]
pub async fn confirm(
    State(inner): State<InnerState>,
    Path(subscription_token): Path<String>,
) -> Result<Json<String>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    // Assuming get_confirmation_token_from_user is updated to return Result<String, AppError>
    let subscriber_id = get_confirmation_token_from_user(&db, subscription_token).await?;

    let user_id_string = confirm_subscriber(&db, subscriber_id).await?;

    Ok(Json(user_id_string)) // Return Json(String) instead of Json(user) if user is a String
}

#[tracing::instrument(name = "Mark subscriber as confirmed", skip(subscriber_id, pool))]
pub async fn confirm_subscriber(
    pool: &PgPool,
    subscriber_id: String,
) -> Result<String, AppError> { // Changed return type
    let id = sqlx::query_as::<_, User>(r#"UPDATE users SET email_confirmed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 returning *"#)
        .bind(subscriber_id)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to confirm subscriber")))? // Changed error mapping
        .id // Get the id field from the User struct
        .ok_or_else(|| AppError::NotFound("User ID not found after confirmation".to_string()))?; // Handle Option<String>

    Ok(id)
}
