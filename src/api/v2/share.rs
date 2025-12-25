use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tower_cookies::Cookies;
use uuid::{Uuid};

use crate::api::{common::cache::RedisCache, v2::channels::all_channels_by_group_id};
use crate::api::v2::groups::Group;
use crate::api::{
    common::ApiResponse, v1::user::get_user_id_from_token, v2::channels::ChannelWithGroup,
};
use crate::{errors::AppError, InnerState};
use futures::future::BoxFuture;
use crate::api::common::limits::enforce_group_sharing_allowed;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateShareLinkRequest {
    pub group_id: String,
    pub link_type: String,
    pub permission: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateShareLinkResponse {
    pub share_link: String,
}

#[derive(Debug, FromRow, Deserialize, Serialize)]
pub struct ShareLink {
    pub id: String,
    pub group_id: String,
    pub link_code: String,
    pub link_type: String,
    pub permission: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub expires_at: Option<NaiveDateTime>,
}

#[derive(Debug, Deserialize, FromRow, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumedShareLinkResponse {
    pub group_id: String,
    pub group_name: String,
    pub group_description: Option<String>,
    pub link_type: String,
    pub permission: Option<String>,
    pub channel_count: i64,
    pub channels: Vec<ChannelWithGroup>,
}

#[tracing::instrument(name = "Generate share link", skip(inner))]
pub async fn generate_share_link(
    State(inner): State<InnerState>,
    cookies: Cookies,
    Json(payload): Json<GenerateShareLinkRequest>,
) -> Result<Json<ApiResponse<GenerateShareLinkResponse>>, AppError> {
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("generate_share_link: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing authentication token")));
    }

    let user_id = match crate::api::v1::user::get_user_id_from_token(auth_token).await {
        Ok(id) => id,
        Err(e) => return Err(AppError::Authentication(anyhow::anyhow!(format!("Authentication error: {}", e)))),
    };

    // Check if the user is the owner of the group or has admin role
    let is_owner_or_admin = match sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM groups WHERE id = $1 AND user_id = $2
            UNION ALL
            SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND role = 'admin'
        )
        "#,
    )
    .bind(&payload.group_id)
    .bind(&user_id)
    .fetch_one(&db)
    .await {
        Ok(exists) => exists,
        Err(e) => {
            tracing::error!("Failed to check group ownership or admin role: {:?}", e);
            return Err(AppError::from(e));
        }
    };

    if !is_owner_or_admin {
        tracing::warn!(
            "User {} attempted to generate share link for group {} without proper permissions",
            user_id,
            payload.group_id
        );
        return Err(AppError::Permission(anyhow::anyhow!(
            "You do not have permission to generate a share link for this group."
        )));
    }

    if let Err(e) = enforce_group_sharing_allowed(&db, &user_id).await {
        return Err(e);
    }

    let share_link_id = Uuid::new_v4().to_string(); // Generate UUID for id
    let link_code = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::days(7); // Link valid for 7 days

    let new_share_link = match sqlx::query_as::<_, ShareLink>(
        r#"
        INSERT INTO share_links (id, group_id, link_code, link_type, permission, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, group_id, link_code, link_type, permission, created_at, expires_at
        "#,
    )
    .bind(&share_link_id) // Bind the generated ID
    .bind(&payload.group_id)
    .bind(&link_code)
    .bind(&payload.link_type)
    .bind(payload.permission)
    .bind(expires_at)
    .fetch_one(&db)
    .await
    {
        Ok(share_link) => share_link,
        Err(e) => {
            tracing::error!(
                "generate_share_link: Database error while inserting share link {}: {:?}",
                link_code,
                e
            );
            return Err(AppError::from(e));
        }
    };

    let share_link_url = format!(
        "{}/share/{}/{}",
        std::env::var("GROUPIFY_HOST").unwrap_or_else(|_| "http://localhost:3000".to_string()),
        new_share_link.link_type,
        new_share_link.link_code
    );

    Ok(Json(ApiResponse::success(GenerateShareLinkResponse {
        share_link: share_link_url,
    })))
}

#[tracing::instrument(name = "Get share link details", skip(inner))]
pub async fn get_share_link(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(link_code): Path<String>,
) -> Json<ApiResponse<ConsumedShareLinkResponse>> {
    let InnerState { db, .. } = inner.clone();

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("get_share_link: Missing authentication token");
        return Json(ApiResponse::error(
            "Missing authentication token".to_string(),
        ));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(id) => id,
        Err(e) => return Json(ApiResponse::error(format!("Authentication error: {}", e))),
    };

    // 1. Find the share link in the database
    let share_link = match sqlx::query_as::<_, ShareLink>(
        r#"
        SELECT id, group_id, link_code, link_type, permission, created_at, expires_at
        FROM share_links
        WHERE link_code = $1
        "#,
    )
    .bind(&link_code)
    .fetch_optional(&db)
    .await
    {
        Ok(share_link) => share_link,
        Err(e) => {
            tracing::error!(
                "get_share_link: Database error while fetching share link {}: {:?}",
                link_code,
                e
            );
            return Json(ApiResponse::error(format!("Database error: {}", e)));
        }
    };

    let share_link = match share_link {
        Some(link) => link,
        None => return Json(ApiResponse::error("Share link not found".to_string())),
    };

    // 2. Check if the link has expired
    if let Some(expires_at) = share_link.expires_at {
        if Utc::now().naive_utc() > expires_at {
            return Json(ApiResponse::error("Share link has expired".to_string()));
        }
    }

    // 3. Retrieve group details
    let original_group = match sqlx::query_as::<_, Group>(r#"SELECT * FROM groups WHERE id = $1"#)
        .bind(&share_link.group_id)
        .fetch_one(&db)
        .await
        {
            Ok(group) => group,
            Err(e) => {
                tracing::error!(
                    "get_share_link: Database error while fetching group {}: {:?}",
                    share_link.group_id,
                    e
                );
                return Json(ApiResponse::error(format!("Database error: {}", e)));
            }
        };

    // 4. Retrieve all channels for the original group
    let original_channels = match all_channels_by_group_id(
        State(inner.clone()),
        Path(original_group.id.clone().unwrap_or_default()),
        user_id.clone(),
    )
    .await
    {
        Ok(channels) => channels,
        Err(e) => {
            return Json(ApiResponse::error(format!(
                "Failed to retrieve channels: {}",
                e
            )))
        }
    };
    let channel_count = original_channels.len() as i64;

    Json(ApiResponse::success(ConsumedShareLinkResponse {
        group_id: original_group.id.unwrap_or_default(),
        group_name: original_group.name,
        group_description: original_group.description,
        link_type: share_link.link_type,
        permission: share_link.permission,
        channel_count,
        channels: original_channels,
    }))
}

async fn copy_channels_for_group(
    db: &sqlx::PgPool,
    target_group_id: String,
    channels_to_copy: Vec<ChannelWithGroup>,
    user_id: String,
) -> Result<(), AppError> {
    for channel in channels_to_copy {
        sqlx::query!(
            r#"
            INSERT INTO channels (id, group_id, name, thumbnail, new_content, channel_id, user_id, url, content_type)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            Uuid::new_v4().to_string(),
            target_group_id,
            channel.name,
            channel.thumbnail,
            false,
            channel.channel_id,
            user_id,
            channel.url,
            channel.content_type,
        )
        .execute(db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to copy channel: {:?}", e);
            AppError::Database(anyhow::Error::from(e).context("Failed to copy channel"))
        })?;
    }
    Ok(())
}

fn copy_group_recursive(
    db: &sqlx::PgPool,
    redis_cache: &RedisCache,
    original_group: &Group,
    new_parent_id: Option<String>,
    user_id: String,
) -> BoxFuture<'static, Result<Group, AppError>> {
    let db = db.clone();
    let original_group = original_group.clone();
    let redis_cache = redis_cache.clone();
    Box::pin(async move {
    let new_group_id = Uuid::new_v4().to_string();
    let new_group_name = format!("Copy of {}", original_group.name);

    let new_group = sqlx::query_as::<_, Group>(
        r#"
        INSERT INTO groups (id, name, icon, user_id, description, category, parent_id, nesting_level, display_order)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, created_at, updated_at, name, icon, user_id, description, category, parent_id, nesting_level, display_order
        "#,
    )
    .bind(&new_group_id)
    .bind(&new_group_name)
    .bind(&original_group.icon)
    .bind(&user_id)
    .bind(&original_group.description)
    .bind(&original_group.category)
    .bind(&new_parent_id)
    .bind(&original_group.nesting_level)
    .bind(&original_group.display_order)
    .fetch_one(&db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create new group recursively: {:?}", e);
        AppError::Database(anyhow::Error::from(e).context("Failed to copy group"))
    })?;

    // Fetch channels for the original group directly
    let original_channels_for_copy = sqlx::query_as::<_, ChannelWithGroup>(
        "SELECT c.*, g.name as group_name, g.icon as group_icon FROM channels c INNER JOIN users u ON u.id = c.user_id LEFT JOIN groups g ON g.id = c.group_id WHERE u.id = $1 AND c.group_id = $2 ORDER BY c.created_at DESC"
    )
    .bind(&user_id)
    .bind(&original_group.id)
    .fetch_all(&db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch channels for original group in recursive copy: {:?}", e);
        AppError::Database(anyhow::Error::from(e).context("Failed to copy channels"))
    })?;

    // Copy channels for this new group
            if let Err(e) = copy_channels_for_group(&db, new_group.id.clone().unwrap_or_default(), original_channels_for_copy, user_id.clone()).await {
        tracing::error!("Failed to copy channels for new group recursively: {}", e);
        return Err(AppError::Database(anyhow::Error::from(e).context("Failed to copy channels")));
    }

    // Invalidate Redis cache for groups
    let groups_pattern = format!("user:{}:groups:*", user_id);
    if let Err(e) = redis_cache.del_pattern(&groups_pattern).await {
        tracing::warn!("copy_group_recursive: redis DEL groups error: {:?}", e);
    }

    // Recursively copy child groups
    let child_groups = sqlx::query_as::<_, Group>(
        r#"SELECT * FROM groups WHERE parent_id = $1 AND user_id = $2"#
    )
    .bind(&original_group.id)
    .bind(&user_id)
    .fetch_all(&db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to fetch child groups recursively: {:?}", e);
        AppError::Database(anyhow::Error::from(e).context("Failed to copy child groups"))
    })?;

    for child_group in child_groups {
        copy_group_recursive(&db, &redis_cache, &child_group, new_group.id.clone(), user_id.clone()).await?;
    }

    Ok(new_group)
})
}

#[tracing::instrument(name = "Consume share link", skip(inner))]
pub async fn consume_share_link(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path((link_type, link_code)): Path<(String, String)>,
) -> Json<ApiResponse<ConsumedShareLinkResponse>> {
    let InnerState { db, .. } = inner.clone();

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("consume_share_link: Missing authentication token");
        return Json(ApiResponse::error(
            "Missing authentication token".to_string(),
        ));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(id) => id,
        Err(e) => return Json(ApiResponse::error(format!("Authentication error: {}", e))),
    };

    // 1. Find the share link in the database
    let share_link = match sqlx::query_as::<_, ShareLink>(
        r#"
        SELECT id, group_id, link_code, link_type, permission, created_at, expires_at
        FROM share_links
        WHERE link_code = $1 AND link_type = $2
        "#,
    )
    .bind(&link_code)
    .bind(&link_type)
    .fetch_optional(&db)
    .await
    {
        Ok(link) => link,
        Err(e) => {
            tracing::error!("Failed to query share link from database: {:?}", e);
            return Json(ApiResponse::error(format!("Database error: {}", e)));
        }
    };

    let share_link = match share_link {
        Some(link) => link,
        None => return Json(ApiResponse::error("Share link not found".to_string())),
    };

    // 2. Check if the link has expired
    if let Some(expires_at) = share_link.expires_at {
        if Utc::now().naive_utc() > expires_at {
            return Json(ApiResponse::error("Share link has expired".to_string()));
        }
    }

    // 3. Retrieve group details
    let original_group = match sqlx::query_as::<_, Group>(r#"SELECT * FROM groups WHERE id = $1"#)
        .bind(&share_link.group_id)
        .fetch_one(&db)
        .await
    {
        Ok(group) => group,
        Err(e) => {
            tracing::error!("Failed to retrieve group details for share link: {:?}", e);
            return Json(ApiResponse::error(format!("Database error: {}", e)));
        }
    };

    let original_channels = match all_channels_by_group_id(
        State(inner.clone()),
        Path(original_group.id.clone().unwrap_or_default()),
        user_id.clone(),
    )
    .await
    {
        Ok(channels) => channels,
        Err(e) => {
            return Json(ApiResponse::error(format!(
                "Failed to retrieve channels: {}",
                e
            )))
        }
    };

    // Now, based on link_type, we can implement the logic
    match share_link.link_type.as_str() {
        "copy" => {
            // 5. Recursively copy the original group and its children
            let new_group = match copy_group_recursive(
                &db,
                &inner.redis_cache,
                &original_group,
                None, // Top-level group has no new_parent_id
                user_id.clone(),
            ).await {
                Ok(group) => group,
                Err(e) => {
                    tracing::error!("Failed to copy group recursively: {:?}", e);
                    return Json(ApiResponse::error(format!("Database error: {}", e)));
                }
            };

            Json(ApiResponse::success(ConsumedShareLinkResponse {
                group_id: new_group.id.unwrap_or_default(),
                group_name: new_group.name,
                group_description: new_group.description,
                link_type: share_link.link_type,
                permission: share_link.permission,
                channel_count: original_channels.len() as i64, // This count is for the original group's channels
                channels: original_channels,
            }))
        }
        "view" => {
            let id = Uuid::now_v7().to_string();
            if let Err(e) = sqlx::query!(
                r#"
                INSERT INTO group_members (id, group_id, user_id, role)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (group_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = CURRENT_TIMESTAMP
                "#,
                id,
                original_group.id.clone().unwrap_or_default(),
                user_id,
                "viewer"
            )
            .execute(&db)
            .await {
                tracing::error!("Failed to grant viewer role: {:?}", e);
                return Json(ApiResponse::error(format!("Database error: {}", e)));
            };

            Json(ApiResponse::success(ConsumedShareLinkResponse {
                group_id: original_group.id.clone().unwrap_or_default(),
                group_name: original_group.name,
                group_description: original_group.description,
                link_type: share_link.link_type,
                permission: Some("viewer".to_string()), // Indicate the granted permission
                channel_count: original_channels.len() as i64,
                channels: original_channels.clone(),
            }))
        }
        "edit" => {
            let id = Uuid::now_v7().to_string();
            if let Err(e) = sqlx::query!(
                r#"
                INSERT INTO group_members (id, group_id, user_id, role)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (group_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = CURRENT_TIMESTAMP
                "#,
                id,
                original_group.id.clone().unwrap_or_default(),
                user_id,
                "editor"
            )
        .execute(&db)
        .await {
            tracing::error!("Failed to grant editor role: {:?}", e);
            return Json(ApiResponse::error(format!("Database error: {}", e)));
        };

            Json(ApiResponse::success(ConsumedShareLinkResponse {
                group_id: original_group.id.clone().unwrap_or_default(),
                group_name: original_group.name,
                group_description: original_group.description,
                link_type: share_link.link_type,
                permission: Some("editor".to_string()), // Indicate the granted permission
                channel_count: original_channels.len() as i64,
                channels: original_channels.clone(),
            }))
        }
        "admin" => {
            if let Err(e) = sqlx::query!(
            r#"
            INSERT INTO group_members (group_id, user_id, role)
            VALUES ($1, $2, $3)
            ON CONFLICT (group_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = CURRENT_TIMESTAMP
            "#,
            original_group.id.clone().unwrap_or_default(),
            user_id,
            "admin"
        )
        .execute(&db)
        .await {
            tracing::error!("Failed to grant admin role: {:?}", e);
            return Json(ApiResponse::error(format!("Database error: {}", e)));
        };

            Json(ApiResponse::success(ConsumedShareLinkResponse {
                group_id: original_group.id.clone().unwrap_or_default(),
                group_name: original_group.name,
                group_description: original_group.description,
                link_type: share_link.link_type,
                permission: Some("admin".to_string()),
                channel_count: original_channels.len() as i64,
                channels: original_channels.clone(),
            }))
        }
        _ => Json(ApiResponse::error("Unknown link type".to_string())),
    }
}
