use anyhow::Result;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::NaiveDateTime;
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ColumnTrait, Condition, EntityTrait, FromQueryResult, JoinType, Order,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set,
};
use serde::Deserialize;
use std::collections::HashMap;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::{
    api::{
        common::{ApiResponse, PaginatedResponse, PaginationInfo, PaginationParams},
        v1::user::get_user_id_from_token,
        v2::channels::ChannelWithGroup,
        v2::groups::Group,
        v3::entities::{channels, group_members, groups},
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
    let now = chrono::Utc::now().naive_utc();

    // Create the channel
    let new_channel = channels::ActiveModel {
        id: Set(channel_id.split('/').next().unwrap().to_string()),
        group_id: Set(target_group_id.clone()),
        user_id: Set(user_id.clone()),
        name: Set(payload.name),
        thumbnail: Set(payload.thumbnail.unwrap_or_default()),
        created_at: Set(Some(now)),
        updated_at: Set(Some(now)),
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
