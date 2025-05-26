use crate::errors::AppError;

use anyhow::{Result};
use axum::extract::{Path, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty, Value};
use sqlx::FromRow;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::InnerState;

use crate::routes::{get_email_from_token, get_user_id_from_token, Channel};

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub name: String,
    pub icon: String,
    pub user_id: String,
}

pub async fn all_groups(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<Group>>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("auth_token {}", auth_token.len());

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let email = get_email_from_token(auth_token).await?;

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(r#"SELECT *, g.id as id, g.created_at as created_at, g.updated_at as updated_at FROM groups g, users u where u.id = g.user_id and u.email = $1 ORDER BY name"#)
            .bind(email)
            .fetch_all(&db),
    )
    .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    Ok(Json(groups))
}

pub async fn create_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let uuid = Uuid::new_v4().to_string();

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    tracing::debug!(
        "group id {} \
         group created_at {} \
         group name {}\
         group icon {}",
        uuid,
        group.name,
        user_id,
        group.icon
    );

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(
            r#"INSERT INTO groups (id, name, icon, user_id) values($1, $2, $3, $4) returning *"#,
        )
        .bind(uuid)
        .bind(group.name)
        .bind(group.icon)
        .bind(user_id)
        .fetch_one(&db),
    )
    .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    println!("Created {:?}", to_string_pretty(&groups));
    Ok(Json(groups))
}

pub async fn update_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    tracing::debug!(
        "group id {} \
         group name {}\
         user id {}\
         group icon {}",
        group_id,
        group.name,
        user_id,
        group.icon
    );

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(
            r#"UPDATE groups SET name = $2, icon = $3, updated_at = CURRENT_TIMESTAMP where id = $1 and user_id = $4 returning *"#,
        )
        .bind(group_id)
        .bind(group.name)
        .bind(group.icon)
        .bind(user_id)
        .fetch_one(&db),
    )
    .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    println!("Created {:?}", to_string_pretty(&groups));
    Ok(Json(groups))
}

pub async fn delete_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<Value>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    tracing::debug!(
        "group id {} \
         user id {}",
        group_id,
        user_id,
    );

    tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Channel>(
            r#"DELETE FROM channels where group_id = $1 and user_id = $2"#,
        )
        .bind(group_id.clone())
        .bind(user_id.clone())
        .fetch_optional(&db),
    )
    .await??;

    tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(r#"DELETE FROM groups where id = $1 and user_id = $2"#)
            .bind(group_id)
            .bind(user_id)
            .fetch_optional(&db),
    )
    .await??;

    Ok(Json(json!({ "success": "true" })))
}
