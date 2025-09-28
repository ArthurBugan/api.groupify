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

use crate::api::v1::{get_email_from_token, get_user_id_from_token, Channel};

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

#[tracing::instrument(name = "Get all groups for user", skip(cookies, inner))]
pub async fn all_groups(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<Group>>, AppError> {
    tracing::info!("Starting to fetch all groups for user");
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("Auth token length: {}", auth_token.len());

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting email from auth token");
    let email = get_email_from_token(auth_token).await?;
    tracing::info!("Successfully extracted email for user: {}", email);

    tracing::debug!("Executing database query to fetch groups");
    let groups = match tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(r#"SELECT *, g.id as id, g.created_at as created_at, g.updated_at as updated_at FROM groups g, users u where u.id = g.user_id and u.email = $1 ORDER BY name"#)
            .bind(&email)
            .fetch_all(&db),
    )
    .await {
        Ok(Ok(groups)) => {
            tracing::info!("Successfully fetched {} groups for user: {}", groups.len(), email);
            groups
        },
        Ok(Err(e)) => {
            tracing::error!("Database error while fetching groups for user {}: {:?}", email, e);
            return Err(AppError::from(e));
        },
        Err(elapsed) => {
            tracing::error!("Timeout elapsed while fetching groups for user {}: {:?}", email, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_groups_timeout
            )));
        }
    };

    tracing::debug!("Returning {} groups to client", groups.len());
    Ok(Json(groups))
}

#[tracing::instrument(name = "Create new group", skip(cookies, inner, group), fields(group_name = %group.name, group_icon = %group.icon))]
pub async fn create_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, AppError> {
    tracing::info!("Starting to create new group: {}", group.name);
    let InnerState { db, .. } = inner;

    let create_groups_timeout = tokio::time::Duration::from_millis(10000);

    let uuid = Uuid::new_v4().to_string();
    tracing::debug!("Generated UUID for new group: {}", uuid);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token for group creation");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting user ID from auth token");
    let user_id = get_user_id_from_token(auth_token).await?;
    tracing::info!("Creating group '{}' for user: {}", group.name, user_id);

    tracing::debug!("Executing database insert for new group");
    let created_group = match tokio::time::timeout(
        create_groups_timeout,
        sqlx::query_as::<_, Group>(
            r#"INSERT INTO groups (id, name, icon, user_id) values($1, $2, $3, $4) returning *"#,
        )
        .bind(&uuid)
        .bind(&group.name)
        .bind(&group.icon)
        .bind(&user_id)
        .fetch_one(&db),
    )
    .await {
        Ok(Ok(group)) => {
            tracing::info!("Successfully created group '{}' with ID: {}", group.name, group.id.as_ref().unwrap_or(&"unknown".to_string()));
            group
        },
        Ok(Err(e)) => {
            tracing::error!("Database error while creating group '{}': {:?}", group.name, e);
            return Err(AppError::from(e));
        },
        Err(elapsed) => {
            tracing::error!("Timeout elapsed while creating group '{}': {:?}", group.name, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                create_groups_timeout
            )));
        }
    };

    tracing::debug!("Group creation completed successfully");
    Ok(Json(created_group))
}

#[tracing::instrument(name = "Update existing group", skip(cookies, inner, group), fields(group_id = %group_id, group_name = %group.name, group_icon = %group.icon))]
pub async fn update_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, AppError> {
    tracing::info!("Starting to update group ID: {} with name: {}", group_id, group.name);
    let InnerState { db, .. } = inner;

    let update_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token for group update");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting user ID from auth token");
    let user_id = get_user_id_from_token(auth_token).await?;
    tracing::info!("Updating group '{}' for user: {}", group.name, user_id);

    tracing::debug!("Executing database update for group ID: {}", group_id);
    let updated_group = match tokio::time::timeout(
        update_groups_timeout,
        sqlx::query_as::<_, Group>(
            r#"UPDATE groups SET name = $2, icon = $3, updated_at = CURRENT_TIMESTAMP where id = $1 and user_id = $4 returning *"#,
        )
        .bind(&group_id)
        .bind(&group.name)
        .bind(&group.icon)
        .bind(&user_id)
        .fetch_one(&db),
    )
    .await {
        Ok(Ok(group)) => {
            tracing::info!("Successfully updated group '{}' with ID: {}", group.name, group_id);
            group
        },
        Ok(Err(e)) => {
            tracing::error!("Database error while updating group ID {}: {:?}", group_id, e);
            return Err(AppError::from(e));
        },
        Err(elapsed) => {
            tracing::error!("Timeout elapsed while updating group ID {}: {:?}", group_id, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_groups_timeout
            )));
        }
    };

    tracing::debug!("Group update completed successfully");
    Ok(Json(updated_group))
}

#[tracing::instrument(name = "Delete group and associated channels", skip(cookies, inner), fields(group_id = %group_id))]
pub async fn delete_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    tracing::info!("Starting to delete group ID: {}", group_id);
    let InnerState { db, .. } = inner;

    let delete_group_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token for group deletion");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting user ID from auth token");
    let user_id = get_user_id_from_token(auth_token).await?;
    tracing::info!("Deleting group ID: {} for user: {}", group_id, user_id);

    tracing::debug!("Deleting associated channels for group ID: {}", group_id);
    match tokio::time::timeout(
        delete_group_timeout,
        sqlx::query_as::<_, Channel>(
            r#"DELETE FROM channels where group_id = $1 and user_id = $2"#,
        )
        .bind(&group_id)
        .bind(&user_id)
        .fetch_optional(&db),
    )
    .await {
        Ok(Ok(_)) => {
            tracing::info!("Successfully deleted channels for group ID: {}", group_id);
        },
        Ok(Err(e)) => {
            tracing::error!("Database error while deleting channels for group ID {}: {:?}", group_id, e);
            return Err(AppError::from(e));
        },
        Err(elapsed) => {
            tracing::error!("Timeout elapsed while deleting channels for group ID {}: {:?}", group_id, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                delete_group_timeout
            )));
        }
    };

    tracing::debug!("Deleting group record for group ID: {}", group_id);
    match tokio::time::timeout(
        delete_group_timeout,
        sqlx::query_as::<_, Group>(r#"DELETE FROM groups where id = $1 and user_id = $2"#)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_optional(&db),
    )
    .await {
        Ok(Ok(_)) => {
            tracing::info!("Successfully deleted group ID: {}", group_id);
        },
        Ok(Err(e)) => {
            tracing::error!("Database error while deleting group ID {}: {:?}", group_id, e);
            return Err(AppError::from(e));
        },
        Err(elapsed) => {
            tracing::error!("Timeout elapsed while deleting group ID {}: {:?}", group_id, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                delete_group_timeout
            )));
        }
    };

    tracing::debug!("Group deletion completed successfully");
    Ok(Json(json!({ "success": "true" })))
}
