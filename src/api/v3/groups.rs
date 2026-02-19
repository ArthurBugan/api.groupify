use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{NaiveDateTime, Utc};
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ColumnTrait, Condition, EntityTrait, FromQueryResult, JoinType, Order,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::{
    api::{
        common::{ApiResponse, PaginatedResponse, PaginationInfo, PaginationParams},
        v1::auth::renew_token,
        v1::user::{get_email_from_token, get_user_id_from_token},
        v2::channels::ChannelWithGroup,
        v2::groups::Group,
        v3::entities::{channels, group_members, groups, videos},
        v3::services::youtube_video_sync::VideoSyncService,
    },
    errors::AppError,
    InnerState,
};

#[derive(Debug, Clone, FromQueryResult)]
struct GroupWithCountRow {
    pub id: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub name: String,
    pub icon: String,
    pub user_id: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub parent_id: Option<String>,
    pub nesting_level: Option<i32>,
    pub display_order: Option<f64>,
    pub channel_count: Option<i64>,
}

#[tracing::instrument(name = "Get all groups v3 (Optimized)", skip(cookies, inner))]
pub async fn all_groups_v3(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<Group>>, AppError> {
    let InnerState {
        sea_db,
        redis_cache,
        ..
    } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(10).max(1).min(100);
    let offset = (page - 1) * limit;

    let cache_key = format!(
        "user:{}:groups:{}:{}:{}",
        user_id,
        page,
        limit,
        params.search.clone().unwrap_or_default()
    );

    if let Ok(Some(cached)) = redis_cache
        .get_json::<PaginatedResponse<Group>>(&cache_key)
        .await
    {
        return Ok(Json(cached));
    }

    let base_access = Condition::any()
        .add(groups::Column::UserId.eq(user_id.clone()))
        .add(group_members::Column::UserId.eq(user_id.clone()));

    // Count query remains the same
    let mut count_q = groups::Entity::find()
        .join(JoinType::LeftJoin, groups::Relation::GroupMembers.def())
        .filter(base_access.clone());

    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            let s = format!("%{}%", search.trim());
            count_q = count_q.filter(
                Condition::any()
                    .add(groups::Column::Name.ilike(s.clone()))
                    .add(groups::Column::Description.ilike(s)),
            );
        }
    }

    let total_result_u64 = count_q
        .select_only()
        .column(groups::Column::Id)
        .distinct()
        .count(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    let total_result = total_result_u64.try_into().unwrap();
    let total_pages = ((total_result as f64) / (limit as f64)).ceil() as u32;
    let has_next = page < total_pages;
    let has_prev = page > 1;
    
    let order_expr = Expr::cust(
        "CASE WHEN groups.display_order = 0 OR groups.display_order IS NULL THEN 100 ELSE 0 END",
    );

    // OPTIMIZATION: Single query with subquery for channel counts
    // This eliminates the need for a second query to get channel counts
    let mut data_q = groups::Entity::find()
        .join(JoinType::LeftJoin, groups::Relation::GroupMembers.def())
        .filter(base_access)
        .select_only()
        .column(groups::Column::Id)
        .column(groups::Column::CreatedAt)
        .column(groups::Column::UpdatedAt)
        .column(groups::Column::Name)
        .column(groups::Column::Icon)
        .column(groups::Column::UserId)
        .column(groups::Column::Description)
        .column(groups::Column::Category)
        .column(groups::Column::ParentId)
        .column(groups::Column::NestingLevel)
        .column(groups::Column::DisplayOrder)
        // Use a correlated subquery to get channel count in the same query
        .expr_as(
            Expr::cust(
                format!(
                    "COALESCE((SELECT COUNT(*) FROM channels c WHERE c.group_id = groups.id AND c.user_id = '{}'), 0)",
                    user_id
                )
            ),
            "channel_count"
        )
        .expr_as(order_expr.clone(), "order_rank")
        .order_by(Expr::cust("order_rank"), Order::Asc)
        .distinct()
        .limit(limit as u64)
        .offset(offset as u64);

    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            let s = format!("%{}%", search.trim());
            data_q = data_q.filter(
                Condition::any()
                    .add(groups::Column::Name.ilike(s.clone()))
                    .add(groups::Column::Description.ilike(s)),
            );
        }
    }

    let rows: Vec<GroupWithCountRow> = data_q
        .into_model::<GroupWithCountRow>()
        .all(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    // Map directly to Group without needing a second query or HashMap
    let out: Vec<Group> = rows
        .into_iter()
        .map(|row| Group {
            id: Some(row.id),
            created_at: row.created_at,
            updated_at: row.updated_at,
            name: row.name,
            icon: row.icon,
            user_id: row.user_id,
            description: row.description,
            category: row.category,
            parent_id: row.parent_id,
            nesting_level: row.nesting_level,
            display_order: row.display_order,
            channel_count: Some(row.channel_count.unwrap_or(0)),
            channels: Vec::new(),
        })
        .collect();

    let response = PaginatedResponse {
        data: out,
        pagination: PaginationInfo {
            page,
            limit,
            total: total_result,
            total_pages,
            has_next,
            has_prev,
        },
    };

    let _ = redis_cache.set_json(&cache_key, &response, 300).await;

    Ok(Json(response))
}

/// Request to create a new channel in a group
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChannelRequest {
    pub channel_id: Option<String>, // Optional: if provided, will look up existing channel
    pub name: String,
    pub thumbnail: Option<String>,
    pub url: Option<String>,
    pub content_type: Option<String>,
}

/// Create a new channel in a group
#[tracing::instrument(name = "Create channel in group v3", skip(cookies, inner, payload))]
pub async fn create_channel_in_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(payload): Json<CreateChannelRequest>,
) -> Result<Json<ApiResponse<ChannelWithGroup>>, AppError> {
    let InnerState { sea_db, db, .. } = inner;

    // Authenticate user
    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    // Check if channel_id is provided - look up existing channel via GET /api/v2/channels/{id} logic
    let target_group_id = if let Some(channel_id) = payload.channel_id {
        tracing::info!("Looking up existing channel {} to get group data", channel_id);
        
        // Replicate GET /api/v2/channels/{id} logic using SeaORM
        let existing_channel = channels::Entity::find()
            .filter(channels::Column::Id.eq(&channel_id))
            .filter(channels::Column::UserId.eq(&user_id))
            .one(&sea_db)
            .await
            .map_err(AppError::SeaORM)?;
        
        if let Some(channel) = existing_channel {
            if let existing_group_id = channel.group_id {
                tracing::info!(
                    "Channel {} is already in group {}. Using that group.",
                    channel_id,
                    existing_group_id
                );
                existing_group_id
            } else {
                tracing::info!(
                    "Channel {} exists but has no group. Using provided group_id {}.",
                    channel_id,
                    group_id
                );
                group_id
            }
        } else {
            tracing::warn!("Channel {} not found. Using provided group_id.", channel_id);
            group_id
        }
    } else {
        group_id
    };

    // Verify user has access to the target group
    let group = groups::Entity::find()
        .filter(groups::Column::Id.eq(&target_group_id))
        .one(&sea_db)
        .await
        .map_err(AppError::SeaORM)?
        .ok_or_else(|| AppError::NotFound(format!("Group {} not found", target_group_id)))?;

    // Check if user is the owner or a member of the group
    let has_access = group.user_id == user_id || {
        group_members::Entity::find()
            .filter(group_members::Column::GroupId.eq(&target_group_id))
            .filter(group_members::Column::UserId.eq(&user_id))
            .one(&sea_db)
            .await
            .map_err(AppError::SeaORM)?
            .is_some()
    };

    if !has_access {
        return Err(AppError::Permission(anyhow::anyhow!(
            "You don't have permission to add channels to this group"
        )));
    }

    // Generate unique channel ID from user_id and url
    let channel_id = format!("{}/{}", user_id, payload.url.clone().unwrap_or_default());
    let now = Utc::now().fixed_offset();

    // Create the channel
    let new_channel = channels::ActiveModel {
        id: Set(channel_id.split('/').next().unwrap().to_string()),
        group_id: Set(target_group_id.clone()),
        user_id: Set(user_id.clone()),
        name: Set(payload.name),
        thumbnail: Set(payload.thumbnail.unwrap_or_default()),
        created_at: Set(Some(now.naive_utc())),
        updated_at: Set(Some(now.naive_utc())),
        new_content: Set(Some(false)),
        channel_id: Set(Some(channel_id.clone())),
        url: Set(payload.url),
        content_type: Set(Some("youtube".to_string())),
    };

    let channel = new_channel.insert(&sea_db).await.map_err(AppError::SeaORM)?;

    // Fetch the created channel with group info
    let channel_with_group = channels::Entity::find()
        .filter(channels::Column::Id.eq(&channel.id))
        .join(JoinType::LeftJoin, channels::Relation::Groups.def())
        .select_only()
        .column_as(channels::Column::Id, "id")
        .column_as(channels::Column::UserId, "user_id")
        .column_as(channels::Column::GroupId, "group_id")
        .column_as(channels::Column::Name, "name")
        .column_as(channels::Column::ChannelId, "channel_id")
        .column_as(channels::Column::Thumbnail, "thumbnail")
        .column_as(channels::Column::CreatedAt, "created_at")
        .column_as(channels::Column::UpdatedAt, "updated_at")
        .column_as(channels::Column::ContentType, "content_type")
        .column_as(channels::Column::Url, "url")
        .column_as(groups::Column::Name, "group_name")
        .column_as(groups::Column::Icon, "group_icon")
        .into_model::<ChannelWithGroup>()
        .one(&sea_db)
        .await
        .map_err(AppError::SeaORM)?
        .ok_or_else(|| AppError::NotFound("Channel not found after creation".to_string()))?;

    tracing::info!(
        "Channel {} created in group {} for user {}",
        channel.id,
        target_group_id,
        user_id
    );

    Ok(Json(ApiResponse::success(channel_with_group)))
}

/// Response structure for video data
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoResponse {
    pub id: String,
    pub channel_id: String,
    pub group_id: String,
    pub title: String,
    pub description: Option<String>,
    pub thumbnail: Option<String>,
    pub url: Option<String>,
    pub published_at: Option<NaiveDateTime>,
    pub content_type: String,
    pub external_id: Option<String>,
    pub duration_seconds: Option<i32>,
    pub views_count: Option<i32>,
}

impl From<videos::Model> for VideoResponse {
    fn from(video: videos::Model) -> Self {
        Self {
            id: video.id,
            channel_id: video.channel_id,
            group_id: video.group_id,
            title: video.title,
            description: video.description,
            thumbnail: video.thumbnail,
            url: video.url,
            published_at: video.published_at,
            content_type: video.content_type,
            external_id: video.external_id,
            duration_seconds: video.duration_seconds,
            views_count: video.views_count,
        }
    }
}

/// Get latest videos from channels in a group
#[tracing::instrument(name = "Get group videos", skip(cookies, inner))]
pub async fn get_group_videos(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<Vec<VideoResponse>>>, AppError> {
    let InnerState { sea_db, .. } = inner;

    // Authenticate user
    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = get_user_id_from_token(auth_token).await?;

    // Verify user has access to this group
    let group = groups::Entity::find()
        .filter(groups::Column::Id.eq(&group_id))
        .one(&sea_db)
        .await
        .map_err(AppError::SeaORM)?
        .ok_or_else(|| AppError::NotFound(format!("Group {} not found", group_id)))?;

    // Check if user is the owner or a member of the group
    let has_access = group.user_id == user_id || {
        group_members::Entity::find()
            .filter(group_members::Column::GroupId.eq(&group_id))
            .filter(group_members::Column::UserId.eq(&user_id))
            .one(&sea_db)
            .await
            .map_err(AppError::SeaORM)?
            .is_some()
    };

    if !has_access {
        return Err(AppError::Permission(anyhow::anyhow!(
            "You don't have permission to view videos in this group"
        )));
    }

    // Set pagination defaults
    let limit = params.limit.unwrap_or(20).max(1).min(50);
    let offset = (params.page.unwrap_or(1).saturating_sub(1)) * limit;

    // Fetch videos from all channels in the group
    let videos = videos::Entity::find()
        .filter(videos::Column::GroupId.eq(&group_id))
        .filter(videos::Column::UserId.eq(&user_id))
        .order_by_desc(videos::Column::PublishedAt)
        .limit(limit as u64)
        .offset(offset as u64)
        .all(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    let video_responses: Vec<VideoResponse> = videos.into_iter().map(|v| v.into()).collect();

    tracing::info!(
        "Retrieved {} videos for group {} (user {})",
        video_responses.len(),
        group_id,
        user_id
    );

    Ok(Json(ApiResponse::success(video_responses)))
}

/// Sync videos from YouTube for all channels in a group
#[tracing::instrument(name = "Sync group videos from YouTube", skip(cookies, inner))]
pub async fn sync_group_videos(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let InnerState { sea_db, db, .. } = inner;

    // Authenticate user
    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = get_user_id_from_token(auth_token.clone()).await?;
    let email = get_email_from_token(auth_token).await?;

    // Verify user has access to this group
    let group = groups::Entity::find()
        .filter(groups::Column::Id.eq(&group_id))
        .one(&sea_db)
        .await
        .map_err(AppError::SeaORM)?
        .ok_or_else(|| AppError::NotFound(format!("Group {} not found", group_id)))?;

    // Check if user is the owner or a member of the group
    let has_access = group.user_id == user_id || {
        group_members::Entity::find()
            .filter(group_members::Column::GroupId.eq(&group_id))
            .filter(group_members::Column::UserId.eq(&user_id))
            .one(&sea_db)
            .await
            .map_err(AppError::SeaORM)?
            .is_some()
    };

    if !has_access {
        return Err(AppError::Permission(anyhow::anyhow!(
            "You don't have permission to sync videos in this group"
        )));
    }

    // Get user's Google session token
    let session = sqlx::query(
        "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1) and provider = 'google'",
    )
    .bind(&email)
    .fetch_one(&db)
    .await
    .map_err(|e| {
        tracing::error!("No Google session found for user {}: {:?}", email, e);
        AppError::Authentication(anyhow::anyhow!("Google session not found. Please connect your Google account."))
    })?;

    let expires_at: chrono::DateTime<chrono::Utc> = session.get("expires_at");
    let mut session_id: String = session.get("session_id");

    // Check if token is expired and renew if necessary
    if expires_at < chrono::Utc::now() {
        tracing::info!("Google session expired for user {}, renewing token...", email);
        
        // Get the OAuth client from state
        let oauth_client = inner.oauth_clients.google.clone();
        
        match renew_token(db.clone(), oauth_client, email.clone()).await {
            Ok(_) => {
                tracing::info!("Token renewed successfully for user {}", email);
                
                // Re-fetch the session to get the new token
                let refreshed_session = sqlx::query(
                    "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1) and provider = 'google'",
                )
                .bind(&email)
                .fetch_one(&db)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to fetch refreshed session for user {}: {:?}", email, e);
                    AppError::Authentication(anyhow::anyhow!("Failed to retrieve refreshed Google session"))
                })?;
                
                session_id = refreshed_session.get("session_id");
            }
            Err(e) => {
                tracing::error!("Failed to renew token for user {}: {:?}", email, e);
                return Err(AppError::Authentication(anyhow::anyhow!(
                    "Google session expired and token renewal failed. Please reconnect your Google account."
                )));
            }
        }
    }

    // Get all channels in the group with YouTube content type
    let channels_in_group: Vec<channels::Model> = channels::Entity::find()
        .filter(channels::Column::GroupId.eq(&group_id))
        .filter(channels::Column::UserId.eq(&user_id))
        .filter(channels::Column::ContentType.eq("youtube"))
        .all(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    tracing::info!("Found {} YouTube channels in group {}", channels_in_group.len(), group_id);

    if channels_in_group.is_empty() {
        return Ok(Json(ApiResponse::success(
            "No YouTube channels found in this group".to_string()
        )));
    }

    // Extract YouTube channel IDs from the format "user_id/youtube_channel_id"
    let channel_ids: Vec<String> = channels_in_group
        .into_iter()
        .filter_map(|ch| {
            ch.channel_id.and_then(|id| {
                // Split on '/' and get the second part (YouTube channel ID)
                id.split('/').nth(1).map(|s| s.to_string())
            })
        })
        .collect();

    if channel_ids.is_empty() {
        return Ok(Json(ApiResponse::success(
            "No valid YouTube channel IDs found in this group".to_string()
        )));
    }

    tracing::info!("Extracted {} YouTube channel IDs: {:?}", channel_ids.len(), channel_ids);

    // Trigger video sync
    let sync_service = VideoSyncService::new(sea_db);
    
    match sync_service.sync_group_videos(&user_id, &group_id, &session_id, channel_ids).await {
        Ok(count) => {
            tracing::info!("Successfully synced {} videos for group {}", count, group_id);
            Ok(Json(ApiResponse::success(format!(
                "Successfully synced {} videos",
                count
            ))))
        }
        Err(e) => {
            tracing::error!("Failed to sync videos for group {}: {:?}", group_id, e);
            Err(e)
        }
    }
}
