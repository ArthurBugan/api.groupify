use anyhow::Result;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use sea_orm::{FromQueryResult, DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait};
use tower_cookies::Cookies;

use crate::{
    api::{common::ApiResponse, v1::user::get_user_id_from_token, v3::entities::users},
    errors::AppError,
    InnerState,
};

#[derive(Debug, Serialize, Deserialize, FromQueryResult)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[tracing::instrument(name = "Get current user data", skip(cookies, inner))]
pub async fn me(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<ApiResponse<User>>, AppError> {
    let db: &DatabaseConnection = &inner.sea_db;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    let user = users::Entity::find_by_id(user_id.clone())
        .one(db)
        .await
        .map_err(AppError::SeaORM)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(ApiResponse::success(User {
        id: user.id,
        email: user.email,
        username: user.display_name.unwrap_or_default(),
        created_at: user.created_at.unwrap_or_default(),
        updated_at: user.updated_at.unwrap_or_default(),
    })))
}