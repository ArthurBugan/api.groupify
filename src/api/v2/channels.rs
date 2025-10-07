use crate::api::common::ApiResponse;
use crate::api::v1::channel::Channel;
use crate::api::v1::user::get_user_id_from_token;
use crate::errors::AppError;
use crate::InnerState;
use anyhow::Result;
use axum::extract::{Query, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
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
    let InnerState { db, .. } = inner;

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
        "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url as url FROM channels c 
         INNER JOIN users u ON u.id = c.user_id 
         LEFT JOIN groups g ON g.id = c.group_id 
         WHERE u.id = $1 
         UNION ALL 
         SELECT yc.id, yc.user_id, NULL as group_id, yc.name, yc.channel_id, yc.thumbnail, yc.created_at, yc.updated_at, NULL as group_name, NULL as group_icon, yc.url FROM youtube_channels yc 
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
                        "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url FROM channels c 
                         INNER JOIN users u ON u.id = c.user_id 
                         LEFT JOIN groups g ON g.id = c.group_id 
                         WHERE u.id = $1 
                         UNION ALL 
                         SELECT yc.id, yc.user_id, NULL as group_id, yc.name, yc.channel_id, yc.thumbnail, yc.created_at, yc.updated_at, NULL as group_name, NULL as group_icon, yc.url FROM youtube_channels yc 
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
                    "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url as url FROM channels c 
                    INNER JOIN users u ON u.id = c.user_id 
                    LEFT JOIN groups g ON g.id = c.group_id 
                    WHERE u.id = $1 
                    UNION ALL 
                    SELECT yc.id, yc.user_id, NULL as group_id, yc.name, yc.channel_id, yc.thumbnail, yc.created_at, yc.updated_at, NULL as group_name, NULL as group_icon, yc.url FROM youtube_channels yc 
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
                            SELECT c.id, c.name, g.name as group_name FROM channels c 
                            INNER JOIN users u ON u.id = c.user_id 
                            LEFT JOIN groups g ON g.id = c.group_id 
                            WHERE u.id = $1 
                            UNION ALL 
                            SELECT yc.id, yc.name, NULL as group_name FROM youtube_channels yc 
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
                        WHERE u.id = $1 
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
    axum::extract::Path(channel_id): axum::extract::Path<String>,
    Json(payload): Json<PatchChannelRequest>,
) -> Result<Json<ChannelWithGroup>, AppError> {
    let InnerState { db, .. } = inner;

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
    let existing_channel = sqlx::query_as::<_, ChannelWithGroup>(
        "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon FROM channels c LEFT JOIN groups g ON g.id = c.group_id WHERE c.id = $1 AND c.user_id = $2"
    )
    .bind(&channel_id)
    .bind(&user_id)
    .fetch_optional(&db)
    .await?;

    let updated_channel = if let Some(mut channel) = existing_channel {
        // Update existing channel
        tracing::info!("patch_channel: Updating existing channel {} for user {}", channel_id, user_id);
        let mut query_builder: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();
        let mut param_count = 1;

        if let Some(group_id) = payload.group_id {
            query_builder.push(format!("group_id = ${}", param_count));
            params.push(group_id);
            param_count += 1;
        }
        if let Some(name) = payload.name {
            query_builder.push(format!("name = ${}", param_count));
            params.push(name);
            param_count += 1;
        }
        if let Some(thumbnail) = payload.thumbnail {
            query_builder.push(format!("thumbnail = ${}", param_count));
            params.push(thumbnail);
            param_count += 1;
        }

        if query_builder.is_empty() {
            return Err(AppError::Validation(String::from("No fields to update")));
        }

        let query_string = format!(
            "UPDATE channels SET {} WHERE id = ${} AND user_id = ${} RETURNING id, user_id, group_id, name, channel_id, thumbnail, created_at, updated_at",
            query_builder.join(", "),
            param_count,
            param_count + 1
        );

        let mut query = sqlx::query_as::<_, Channel>(&query_string);
        for param in params {
            query = query.bind(param);
        }
        query = query.bind(&channel_id).bind(&user_id);

        let update_timeout = tokio::time::Duration::from_millis(5000); // 5 seconds timeout for update
        let updated_channel_base =
            match tokio::time::timeout(update_timeout, query.fetch_one(&db)).await {
                Ok(Ok(channel)) => {
                    tracing::debug!(
                        "patch_channel: Successfully updated channel with ID: {}",
                        channel.id.as_deref().unwrap_or_default()
                    );
                    channel
                }
                Ok(Err(e)) => {
                    tracing::error!(
                        "patch_channel: Database error while updating channel: {:?}",
                        e
                    );
                    return Err(AppError::from(e));
                }
                Err(elapsed) => {
                    tracing::error!(
                        "patch_channel: Timeout while updating channel: {:?}",
                        elapsed
                    );
                    return Err(AppError::Database(anyhow::anyhow!(
                        "Database query timeout after {:?}",
                        update_timeout
                    )));
                }
            };

        // After successful update, fetch the channel with group info
        let fetched_channel = sqlx::query_as::<_, ChannelWithGroup>(
            "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon FROM channels c LEFT JOIN groups g ON g.id = c.group_id WHERE c.id = $1 AND c.user_id = $2"
        )
        .bind(&updated_channel_base.id)
        .bind(&user_id)
        .fetch_one(&db)
        .await?;

        fetched_channel
    } else {
        // Create new channel
        tracing::info!("patch_channel: Creating new channel with ID {}", channel_id);
        let create_timeout = tokio::time::Duration::from_millis(5000); // 5 seconds timeout for creation
        let new_channel = match tokio::time::timeout(
            create_timeout,
            sqlx::query_as::<_, Channel>(
                "INSERT INTO channels (id, user_id, group_id, name, thumbnail, channel_id, new_content, url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *"
            )
            .bind(&channel_id)
            .bind(&user_id)
            .bind(payload.group_id)
            .bind(payload.name)
            .bind(payload.thumbnail)
            .bind(format!("{}/{}", user_id, channel_id))
            .bind(false)
            .bind(payload.url)
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
            "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon FROM channels c LEFT JOIN groups g ON g.id = c.group_id WHERE c.id = $1 AND c.user_id = $2"
        )
        .bind(&new_channel.id)
        .bind(&user_id)
        .fetch_one(&db)
        .await?;

        fetched_channel
    };

    Ok(Json(updated_channel))
}

#[tracing::instrument(name = "Get all channels by group ID for user", skip(inner))]
pub async fn all_channels_by_group_id(
    State(inner): State<InnerState>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
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
            "SELECT c.id, c.user_id, c.group_id, c.name, c.channel_id, c.thumbnail, c.created_at, c.updated_at, g.name as group_name, g.icon as group_icon, c.url FROM channels c INNER JOIN users u ON u.id = c.user_id LEFT JOIN groups g ON g.id = c.group_id WHERE u.id = $1 AND c.group_id = $2 ORDER BY c.created_at DESC"
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
    axum::extract::Path(group_id): axum::extract::Path<String>,
    Json(payload): Json<PatchChannelsBatchRequest>,
) -> Result<Json<ApiResponse<Vec<ChannelWithGroup>>>, AppError> {
    let InnerState { db, email_client, oauth_clients } = inner;

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
        let patched_channel = patch_channel(
            cookies.clone(),
            State(InnerState {
                db: db.clone(),
                email_client: email_client.clone(),
                oauth_clients: oauth_clients.clone(),
            }),
            axum::extract::Path(channel_id_for_patch),
            Json(channel_request),
        )
        .await?;
        updated_channels.push(patched_channel);
    }

    Ok(Json(ApiResponse::success(updated_channels.into_iter().map(|Json(c)| c).collect())))
}
