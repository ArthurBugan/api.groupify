use crate::api::common::utils::timeout_query;
use crate::api::common::ApiResponse;
use crate::api::v1::channel::Channel;
use crate::api::v1::user::get_user_id_from_token;
use crate::api::v1::youtube::sync_channels_from_youtube;
use crate::errors::AppError;
use crate::InnerState;
use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{Execute, FromRow, Postgres, QueryBuilder};
use tower_cookies::Cookies;

/// Pagination parameters for channel queries
#[derive(Debug, Deserialize)]
pub struct ChannelPaginationParams {
    pub page: Option<i32>,
    pub limit: Option<i32>,
    pub search: Option<String>,
}

/// Paginated response structure for channels
#[derive(Debug, Serialize)]
pub struct PaginatedChannelsResponse {
    pub data: Vec<ChannelWithGroup>,
    pub pagination: PaginationInfo,
}

/// Pagination metadata
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationInfo {
    pub total: i64,
    pub page: i32,
    pub limit: i32,
    pub total_pages: i32,
}
/// Channel with group name for API responses
#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChannelWithGroup {
    pub id: String,
    pub user_id: String,
    pub group_id: Option<String>,
    pub name: String,
    pub channel_id: String,
    pub thumbnail: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub group_name: Option<String>,
    pub group_icon: Option<String>,
    pub content_type: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchChannelRequest {
    pub id: String,
    pub group_id: Option<String>,
    pub name: Option<String>,
    pub thumbnail: Option<String>,
    pub url: Option<String>,
    pub content_type: Option<String>,
    pub new_content: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchChannelsBatchRequest {
    pub channels: Vec<PatchChannelRequest>,
}

#[tracing::instrument(name = "Get all channels for user", skip(cookies, inner))]
pub async fn all_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(params): Query<ChannelPaginationParams>,
) -> Result<Json<PaginatedChannelsResponse>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!("Starting all_channels request");

    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner.clone();

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("all_channels: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => {
            tracing::debug!("all_channels: Successfully extracted user_id from token");
            user_id
        }
        Err(e) => {
            tracing::error!(
                "all_channels: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    tracing::info!("all_channels: Fetching channels for user_id: {}", user_id);

    // Set default pagination values
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(25).max(1).min(100); // Cap at 100 items per page
    let offset = (page - 1) * limit;

    tracing::info!(
        "all_channels: Pagination - page: {}, limit: {}, offset: {}",
        page,
        limit,
        offset
    );

    // Build the base query
    let mut base_query = String::from(
        "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url as url, c.content_type as content_type FROM channels c 
         INNER JOIN users u ON u.id = c.user_id 
         LEFT JOIN groups g ON g.id = c.group_id 
         WHERE (c.content_type = 'youtube' OR c.content_type IS NULL) AND u.id = $1
         UNION ALL 
         SELECT yc.id, yc.user_id, NULL as group_id, yc.name, yc.channel_id, yc.thumbnail, yc.created_at, yc.updated_at, NULL as group_name, NULL as group_icon, yc.url as url, 'youtube' as content_type FROM youtube_channels yc 
         INNER JOIN users u ON u.id = yc.user_id 
         WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM channels c2 WHERE c2.name = yc.name AND c2.user_id = yc.user_id)"
    );

    // Add search filter if provided
    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            base_query = format!(
                "SELECT * FROM ({}) AS combined_channels WHERE name ILIKE $2 OR group_name ILIKE $3",
                base_query
            );
        }
    }

    // Add ordering and pagination
    base_query.push_str(" ORDER BY created_at DESC LIMIT $4 OFFSET $5");

    // Execute the main query
    let channels = match tokio::time::timeout(
        fetch_channels_timeout,
        async {
            if let Some(search) = &params.search {
                if !search.trim().is_empty() {
                    let search_pattern = format!("%{}%", search.trim());
                    sqlx::query_as::<_, ChannelWithGroup>(
                        &base_query
                    )
                    .bind(&user_id)
                    .bind(&search_pattern)
                    .bind(&search_pattern)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&db)
                    .await
                } else {
                    // No search parameter, use combined query
                    sqlx::query_as::<_, ChannelWithGroup>(
                        "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url, c.content_type as content_type FROM channels c 
                         INNER JOIN users u ON u.id = c.user_id 
                         LEFT JOIN groups g ON g.id = c.group_id 
                         WHERE (c.content_type = 'youtube' OR c.content_type IS NULL) AND u.id = $1
                         UNION ALL 
                         SELECT yc.id, yc.user_id, NULL as group_id, yc.name, yc.channel_id, yc.thumbnail, yc.created_at, yc.updated_at, NULL as group_name, NULL as group_icon, yc.url as url, 'youtube' as content_type FROM youtube_channels yc 
                         INNER JOIN users u ON u.id = yc.user_id 
                         WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM channels c2 WHERE c2.name = yc.name AND c2.user_id = yc.user_id)
                         ORDER BY created_at DESC LIMIT $2 OFFSET $3"
                    )
                    .bind(&user_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(&db)
                    .await
                }
            } else {
                // No search parameter
                sqlx::query_as::<_, ChannelWithGroup>(
                    "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url as url, c.content_type as content_type FROM channels c 
                    INNER JOIN users u ON u.id = c.user_id 
                    LEFT JOIN groups g ON g.id = c.group_id 
                    WHERE (c.content_type = 'youtube' OR c.content_type IS NULL) AND u.id = $1
                    UNION ALL 
                    SELECT yc.id, yc.user_id, NULL as group_id, yc.name, yc.channel_id, yc.thumbnail, yc.created_at, yc.updated_at, NULL as group_name, NULL as group_icon, yc.url as url, 'youtube' as content_type FROM youtube_channels yc 
                    INNER JOIN users u ON u.id = yc.user_id 
                    WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM channels c2 WHERE c2.name = yc.name AND c2.user_id = yc.user_id)
                    ORDER BY created_at DESC LIMIT $2 OFFSET $3"
                )
                .bind(&user_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(&db)
                .await
            }
        }
    )
    .await
    {
        Ok(Ok(channels)) => {
            tracing::info!(
                "all_channels: Successfully fetched {} channels",
                channels.len()
            );
            channels
        }
        Ok(Err(e)) => {
            tracing::error!(
                "all_channels: Database error while fetching channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "all_channels: Timeout while fetching channels: {:?}",
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_channels_timeout
            )));
        }
    };

    // Count total channels for pagination
    let total_count = match tokio::time::timeout(
        fetch_channels_timeout,
        async {
            if let Some(search) = &params.search {
                if !search.trim().is_empty() {
                    let search_pattern = format!("%{}%", search.trim());
                    sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM (
                            SELECT c.id, c.name, g.name as group_name, c.content_type as content_type FROM channels c 
                            INNER JOIN users u ON u.id = c.user_id 
                            LEFT JOIN groups g ON g.id = c.group_id 
                            WHERE (c.content_type = 'youtube' OR c.content_type IS NULL) AND u.id = $1
                            UNION ALL 
                            SELECT yc.id, yc.name, NULL as group_name, 'youtube' as content_type FROM youtube_channels yc 
                            INNER JOIN users u ON u.id = yc.user_id 
                            WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM channels c2 WHERE c2.name = yc.name AND c2.user_id = yc.user_id)
                        ) AS combined_channels 
                        WHERE name ILIKE $2 OR group_name ILIKE $3"
                    )
                    .bind(&user_id)
                    .bind(&search_pattern)
                    .bind(&search_pattern)
                    .fetch_one(&db)
                    .await
                } else {
                    sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM channels c 
                         INNER JOIN users u ON u.id = c.user_id 
                         WHERE u.id = $1"
                    )
                    .bind(&user_id)
                    .fetch_one(&db)
                    .await
                }
            } else {
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM (
                        SELECT c.id FROM channels c 
                        INNER JOIN users u ON u.id = c.user_id 
                        LEFT JOIN groups g ON g.id = c.group_id 
                        WHERE (c.content_type = 'youtube' OR c.content_type IS NULL) AND u.id = $1
                        UNION ALL 
                        SELECT yc.id FROM youtube_channels yc 
                        INNER JOIN users u ON u.id = yc.user_id 
                        WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM channels c2 WHERE c2.name = yc.name AND c2.user_id = yc.user_id)
                    ) AS combined_channels"
                )
                .bind(&user_id)
                .fetch_one(&db)
                .await
            }
        }
    )
    .await
    {
        Ok(Ok(count)) => count,
        Ok(Err(e)) => {
            tracing::error!(
                "all_channels: Database error while counting channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "all_channels: Timeout while counting channels: {:?}",
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database count timeout after {:?}",
                fetch_channels_timeout
            )));
        }
    };

    if let Err(e) = sync_channels_from_youtube(cookies.clone(), State(inner.clone())).await {
        tracing::error!("Error syncing channels from YouTube: {:?}", e);
    }

    let total_pages = ((total_count as f64) / (limit as f64)).ceil() as i32;

    let response = PaginatedChannelsResponse {
        data: channels,
        pagination: PaginationInfo {
            total: total_count,
            page,
            limit,
            total_pages,
        },
    };

    let duration = start_time.elapsed();
    tracing::info!(
        "all_channels: Completed successfully in {:?} - found {} total channels, {} pages",
        duration,
        total_count,
        total_pages
    );
    Ok(Json(response))
}

#[tracing::instrument(name = "Patch channel by ID", skip(cookies, inner))]
pub async fn patch_channel(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(channel_id): Path<String>,
    Json(payload): Json<PatchChannelRequest>,
) -> Result<Json<ApiResponse<ChannelWithGroup>>, AppError> {
    let InnerState { db, .. } = inner;
    tracing::info!(
        "patch_channel: Patching channel {} with payload: {:?}",
        channel_id,
        payload
    );

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("patch_channel: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => user_id,
        Err(e) => {
            tracing::error!(
                "patch_channel: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    // Check if the channel exists and belongs to the user
    let existing_channel = match sqlx::query_as::<_, ChannelWithGroup>(
        "SELECT c.*, g.name as group_name, g.icon as group_icon
        FROM channels c
        LEFT JOIN groups g ON g.id = c.group_id
        WHERE c.id = $1 AND c.user_id = $2",
    )
    .bind(&channel_id)
    .bind(&user_id)
    .fetch_optional(&db)
    .await
    {
        Ok(channel) => channel,
        Err(e) => {
            tracing::error!(
                "patch_channel: Database error while fetching existing channel {}: {:?}",
                channel_id,
                e
            );
            return Err(AppError::from(e));
        }
    };

    let updated_channel = if let Some(mut channel) = existing_channel {
        // Update existing channel
        tracing::info!(
            "patch_channel: Updating existing channel {} for user {}",
            channel_id,
            user_id
        );

        let mut builder: QueryBuilder<Postgres> = QueryBuilder::new("UPDATE channels SET ");

        let mut separated = builder.separated(", ");

        if let Some(group_id) = payload.group_id {
            separated.push("group_id = ");
            separated.push_bind_unseparated(group_id);
        }
        if let Some(name) = payload.name {
            separated.push("name = ");
            separated.push_bind_unseparated(name);
        }
        if let Some(thumbnail) = payload.thumbnail {
            separated.push("thumbnail = ");
            separated.push_bind_unseparated(thumbnail);
        }
        if let Some(new_content) = payload.new_content {
            separated.push("new_content = ");
            separated.push_bind_unseparated(new_content);
        }
        if let Some(content_type) = payload.content_type {
            separated.push("content_type = ");
            separated.push_bind_unseparated(content_type);
        }

        // Add WHERE clause
        builder.push(" WHERE id = ");
        builder.push_bind(&channel_id);
        builder.push(" AND user_id = ");
        builder.push_bind(&user_id);
        builder.push(" RETURNING *");

        let query = builder.build_query_as::<Channel>();

        let update_timeout = tokio::time::Duration::from_millis(5000);

        tracing::debug!("patch_channel: Executing update query: {:?}", query.sql());

        let updated_channel: Channel = timeout_query(update_timeout, query.fetch_one(&db))
            .await
            .inspect_err(|e| tracing::error!("patch_channel: Database error: {:?}", e))?;

        // After successful update, fetch the channel with group info
        let fetched_channel = match sqlx::query_as::<_, ChannelWithGroup>(
            "SELECT c.*, g.name as group_name, g.icon as group_icon
            FROM channels c
            LEFT JOIN groups g ON g.id = c.group_id
            WHERE c.id = $1 AND c.user_id = $2",
        )
        .bind(&updated_channel.id)
        .bind(&user_id)
        .fetch_one(&db)
        .await
        {
            Ok(channel) => channel,
            Err(e) => {
                tracing::error!(
                    "patch_channel: Database error while fetching updated channel {}: {:?}",
                    updated_channel.id.as_deref().unwrap_or_default(),
                    e
                );
                return Err(AppError::from(e));
            }
        };

        fetched_channel
    } else {
        // Create new channel
        tracing::info!("patch_channel: Creating new channel with ID {}", channel_id);

        let cleaned_url = match payload.url {
            Some(ref url) => Some(url.replace("@", "")),
            None => None,
        };

        let create_timeout = tokio::time::Duration::from_millis(10000); // 10 seconds timeout for creation
        let new_channel = match tokio::time::timeout(
            create_timeout,
            sqlx::query_as::<_, Channel>(
                "INSERT INTO channels (id, user_id, group_id, name, thumbnail, channel_id, new_content, url, content_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *"
            )
            .bind(&channel_id)
            .bind(&user_id)
            .bind(payload.group_id)
            .bind(payload.name)
            .bind(payload.thumbnail)
            .bind(format!("{}/{}", user_id, channel_id))
            .bind(false)
            .bind(cleaned_url)
            .bind(payload.content_type)
            .fetch_one(&db),
        )
        .await
        {
            Ok(Ok(channel)) => {
                tracing::debug!(
                    "patch_channel: Successfully created new channel with ID: {}",
                    channel.id.as_deref().unwrap_or_default()
                );
                channel
            }
            Ok(Err(e)) => {
                tracing::error!(
                    "patch_channel: Database error while creating channel: {:?}",
                    e
                );
                return Err(AppError::from(e));
            }
            Err(elapsed) => {
                tracing::error!(
                    "patch_channel: Timeout while creating channel: {:?}",
                    elapsed
                );
                return Err(AppError::Database(anyhow::anyhow!(
                    "Database query timeout after {:?}",
                    create_timeout
                )));
            }
        };

        // After successful insertion, fetch the channel with group info
        let fetched_channel = sqlx::query_as::<_, ChannelWithGroup>(
            "SELECT c.*, g.name as group_name, g.icon as group_icon
            FROM channels c
            LEFT JOIN groups g
            ON g.id = c.group_id
            WHERE c.id = $1 AND c.user_id = $2",
        )
        .bind(&new_channel.id)
        .bind(&user_id)
        .fetch_one(&db)
        .await?;

        fetched_channel
    };

    Ok(Json(ApiResponse::success(updated_channel)))
}

#[tracing::instrument(name = "Get all channels by group ID for user", skip(inner))]
pub async fn all_channels_by_group_id(
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    user_id: String,
) -> Result<Vec<ChannelWithGroup>, AppError> {
    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    tracing::info!(
        "all_channels_by_group_id: Fetching channels for user_id: {} and group_id: {}",
        user_id,
        group_id
    );

    let channels = match tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, ChannelWithGroup>(
            "SELECT c.*, g.name as group_name, g.icon as group_icon FROM channels c INNER JOIN users u ON u.id = c.user_id LEFT JOIN groups g ON g.id = c.group_id WHERE u.id = $1 AND c.group_id = $2 ORDER BY c.created_at DESC"
        )
        .bind(&user_id)
        .bind(&group_id)
        .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(channels)) => {
            tracing::info!(
                "all_channels_by_group_id: Successfully fetched {} channels for group {}",
                channels.len(),
                group_id
            );
            channels
        }
        Ok(Err(e)) => {
            tracing::error!(
                "all_channels_by_group_id: Database error while fetching channels for group {}: {:?}",
                group_id,
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "all_channels_by_group_id: Timeout while fetching channels for group {}: {:?}",
                group_id,
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?} for group {}",
                fetch_channels_timeout,
                group_id
            )));
        }
    };

    Ok(channels)
}

#[tracing::instrument(name = "Get count of channels by channel ID for user", skip(db))]
pub async fn all_count_by_channel_id(
    db: &sqlx::PgPool,
    group_id: &str,
    user_id: &str,
) -> Result<i64, AppError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channels WHERE group_id = $1 AND user_id = $2",
    )
    .bind(group_id)
    .bind(user_id)
    .fetch_one(db)
    .await?;

    Ok(count)
}

#[tracing::instrument(name = "Delete all channels by group ID for user", skip(db))]
async fn delete_channels_by_group_id(
    db: &sqlx::PgPool,
    group_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    sqlx::query!(
        "DELETE FROM channels WHERE group_id = $1 AND user_id = $2",
        group_id,
        user_id
    )
    .execute(db)
    .await?;

    Ok(())
}

#[tracing::instrument(name = "Patch multiple channels in batch", skip(cookies, inner))]
pub async fn patch_channels_batch(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(payload): Json<PatchChannelsBatchRequest>,
) -> Result<Json<ApiResponse<Vec<ChannelWithGroup>>>, AppError> {
    let InnerState {
        db,
        email_client,
        oauth_clients,
    } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("patch_channels_batch: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => user_id,
        Err(e) => {
            tracing::error!(
                "patch_channels_batch: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    delete_channels_by_group_id(&db.clone(), &group_id, &user_id).await?;

    let mut updated_channels = Vec::new();

    for channel_request in payload.channels {
        let channel_id_for_patch = channel_request.id.clone();
        let mut patched_channel = patch_channel(
            cookies.clone(),
            State(InnerState {
                db: db.clone(),
                email_client: email_client.clone(),
                oauth_clients: oauth_clients.clone(),
            }),
            Path(channel_id_for_patch),
            Json(channel_request),
        )
        .await?;
        updated_channels.push(patched_channel.data.as_mut().unwrap().clone());
    }

    Ok(Json(ApiResponse::success(updated_channels)))
}

#[tracing::instrument(name = "Get channel by ID", skip(cookies, inner))]
pub async fn get_channel_by_id(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(channel_id): Path<String>,
) -> Result<Json<ApiResponse<ChannelWithGroup>>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Starting get_channel_by_id request for channel_id: {}",
        channel_id
    );

    let fetch_channel_timeout = tokio::time::Duration::from_millis(5000); // 5 seconds timeout
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("get_channel_by_id: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => {
            tracing::debug!("get_channel_by_id: Successfully extracted user_id from token");
            user_id
        }
        Err(e) => {
            tracing::error!(
                "get_channel_by_id: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    tracing::info!(
        "get_channel_by_id: Fetching channel {} for user_id: {}",
        channel_id,
        user_id
    );

    let channel = match tokio::time::timeout(
        fetch_channel_timeout,
        sqlx::query_as::<_, ChannelWithGroup>(
            "SELECT c.*, g.name as group_name, g.icon as group_icon
             FROM channels c
             INNER JOIN users u ON u.id = c.user_id
             LEFT JOIN groups g ON g.id = c.group_id
             WHERE c.id = $1 AND u.id = $2",
        )
        .bind(&channel_id)
        .bind(&user_id)
        .fetch_optional(&db),
    )
    .await
    {
        Ok(Ok(Some(channel))) => {
            tracing::info!(
                "get_channel_by_id: Successfully fetched channel {}",
                channel_id
            );
            channel
        }
        Ok(Ok(None)) => {
            tracing::warn!(
                "get_channel_by_id: Channel {} not found for user {}",
                channel_id,
                user_id
            );
            return Err(AppError::NotFound(format!(
                "Channel {} not found",
                channel_id
            )));
        }
        Ok(Err(e)) => {
            tracing::error!(
                "get_channel_by_id: Database error while fetching channel {}: {:?}",
                channel_id,
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "get_channel_by_id: Timeout while fetching channel {}: {:?}",
                channel_id,
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_channel_timeout
            )));
        }
    };

    tracing::info!(
        "Finished get_channel_by_id request for channel_id: {} in {:?}",
        channel_id,
        start_time.elapsed()
    );

    Ok(Json(ApiResponse::success(channel)))
}

#[tracing::instrument(name = "Delete channel by ID", skip(cookies, inner), fields(channel_id = %channel_id))]
pub async fn delete_channel(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(channel_id): Path<String>,
) -> Result<Json<ApiResponse<String>>, Json<ApiResponse<String>>> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Starting delete_channel request for channel_id: {}",
        channel_id
    );

    let delete_channel_timeout = tokio::time::Duration::from_millis(5000); // 5 seconds timeout
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("delete_channel: Missing authentication token");
        return Err(Json(ApiResponse::error("Missing token".to_string())));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => {
            tracing::debug!("delete_channel: Successfully extracted user_id from token");
            user_id
        }
        Err(e) => {
            tracing::error!(
                "delete_channel: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(Json(ApiResponse::error(format!(
                "Failed to extract user_id from token: {:?}",
                e
            ))));
        }
    };

    tracing::info!(
        "delete_channel: Deleting channel {} for user_id: {}",
        channel_id,
        user_id
    );

    let result: Result<ApiResponse<String>, ApiResponse<String>> = match tokio::time::timeout(
        delete_channel_timeout,
        sqlx::query!(
            "DELETE FROM channels WHERE id = $1 AND user_id = $2",
            &channel_id,
            &user_id
        )
        .execute(&db),
    )
    .await
    {
        Ok(Ok(query_result)) => {
            if query_result.rows_affected() == 0 {
                tracing::warn!(
                    "delete_channel: Channel {} not found for user {}",
                    channel_id,
                    user_id
                );
                return Err(Json(ApiResponse::error(format!(
                    "Channel {} not found",
                    channel_id
                ))));
            }
            tracing::info!(
                "delete_channel: Successfully deleted channel {}",
                channel_id
            );
            Ok(ApiResponse::success(format!(
                "Channel {} deleted successfully",
                channel_id
            )))
        }
        Ok(Err(e)) => {
            tracing::error!(
                "delete_channel: Database error while deleting channel {}: {:?}",
                channel_id,
                e
            );
            return Err(Json(ApiResponse::error(format!("Database error: {:?}", e))));
        }
        Err(elapsed) => {
            tracing::error!(
                "delete_channel: Timeout while deleting channel {}: {:?}",
                channel_id,
                elapsed
            );

            return Err(Json(ApiResponse::error(format!(
                "Timeout while deleting channel {}: {:?}",
                channel_id, elapsed
            ))));
        }
    };

    Ok(Json(result.unwrap()))
}
