use crate::routes::{get_confirmation_token_from_user, User};
use crate::utils::internal_error;
use crate::InnerState;
use axum::extract::{Path, State};
use axum::{http::StatusCode, Json};
use serde_json::Value;
use sqlx::PgPool;

#[derive(serde::Deserialize)]
pub struct Parameters {
    subscription_token: String,
}

#[tracing::instrument(name = "Confirm a pending subscriber", skip(subscription_token, inner))]
pub async fn confirm(
    State(inner): State<InnerState>,
    Path(subscription_token): Path<String>,
) -> Result<Json<String>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let subscriber_id = get_confirmation_token_from_user(&db, subscription_token).await?;

    let user = confirm_subscriber(&db, subscriber_id).await?;

    Ok(Json(user))
}

#[tracing::instrument(name = "Mark subscriber as confirmed", skip(subscriber_id, pool))]
pub async fn confirm_subscriber(
    pool: &PgPool,
    subscriber_id: String,
) -> Result<String, (StatusCode, String)> {
    let id = sqlx::query_as::<_, User>(r#"UPDATE users SET email_confirmed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = $1 returning *"#)
        .bind(subscriber_id)
        .fetch_one(pool)
        .await
        .map(|user| user.id)
        .map_err(internal_error)?;

    Ok(id.unwrap_or_else(|| String::new()))
}
