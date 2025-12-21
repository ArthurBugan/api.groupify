use anyhow::Result;
use axum::{
    extract::{Path, State},
    Json,
};
use std::collections::HashSet;
use tower_cookies::Cookies;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, EntityTrait, Iterable,
    QueryFilter, QuerySelect, RelationTrait, Set,
};

use crate::{
    api::{
        common::ApiResponse,
        v1::user::get_user_id_from_token,
        v2::channels::{ChannelWithGroup, PatchChannelRequest, PatchChannelsBatchRequest},
        v3::entities::{channels, group_members, groups},
    },
    errors::AppError,
    InnerState,
};

#[derive(Debug, Clone, Copy)]
pub enum GroupChannelPermission {
    Owner,
    Editor,
    Admin,
}

#[tracing::instrument(name = "Patch v3 multiple channels in batch", skip(cookies, inner))]
pub async fn patch_channels_batch(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(payload): Json<PatchChannelsBatchRequest>,
) -> Result<Json<ApiResponse<Vec<ChannelWithGroup>>>, AppError> {
    let InnerState {
        db,
        sea_db,
        redis_cache,
        email_client,
        oauth_clients,
    } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = get_user_id_from_token(auth_token).await?;
    let incoming_ids: Vec<String> = payload.channels.iter().map(|c| c.id.clone()).collect();

    let permission = check_group_channel_permission(&sea_db, &group_id, &user_id).await?;

    let effective_user_id = match permission {
        GroupChannelPermission::Owner => user_id.clone(),
        GroupChannelPermission::Editor => user_id.clone(),
        GroupChannelPermission::Admin => user_id.clone(),
    };

    delete_missing_channels_by_group_id(&sea_db, &group_id, &user_id, &incoming_ids).await?;

    let mut updated_channels = Vec::with_capacity(payload.channels.len());

    for channel_request in payload.channels {
        let channel_id = channel_request.id.clone();

        let response = patch_channel(
            cookies.clone(),
            State(InnerState {
                db: db.clone(),
                sea_db: sea_db.clone(),
                redis_cache: redis_cache.clone(),
                email_client: email_client.clone(),
                oauth_clients: oauth_clients.clone(),
            }),
            Path(channel_id),
            Path(effective_user_id.clone()),
            Path(group_id.clone()),
            Json(channel_request),
        )
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

        if let Some(channel) = response.data.clone() {
            updated_channels.push(channel);
        }
    }

    redis_cache
        .del_pattern(&format!("user:{}:group:*", user_id))
        .await
        .ok();

    redis_cache
        .del_pattern(&format!("user:{}:channels:*", user_id))
        .await
        .ok();

    redis_cache
        .del_pattern(&format!("user:{}:animes:*", user_id))
        .await
        .ok();

    Ok(Json(ApiResponse::success(updated_channels)))
}

#[tracing::instrument(name = "Patch v3 multiple channels in batch", skip(cookies, inner))]
pub async fn patch_channel(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(channel_id): Path<String>,
    Path(effective_user_id): Path<String>,
    Path(group_id): Path<String>,
    Json(payload): Json<PatchChannelRequest>,
) -> Result<Json<ApiResponse<ChannelWithGroup>>, AppError> {
    let db: &DatabaseConnection = &inner.sea_db;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = effective_user_id.clone();

    let channel_exists = channels::Entity::find()
        .filter(channels::Column::Id.eq(channel_id.clone()))
        .filter(channels::Column::GroupId.eq(group_id.clone()))
        .one(db)
        .await
        .map_err(AppError::SeaORM)?
        .is_some();

    tracing::info!(
        "Channel exists: {}, channel_id: {}, group_id: {}",
        channel_exists,
        channel_id,
        group_id
    );

    let channel_with_group = if channel_exists {
        let condition = Condition::any()
            .add(channels::Column::UserId.eq(user_id.clone()))
            .add(groups::Column::UserId.eq(user_id.clone()))
            .add(
                group_members::Column::UserId
                    .eq(user_id.clone())
                    .and(group_members::Column::Role.is_in(vec!["admin", "editor"])),
            );

        let existing = channels::Entity::find()
            .filter(channels::Column::Id.eq(channel_id.clone()))
            .filter(channels::Column::GroupId.eq(group_id.clone()))
            .join(
                sea_orm::JoinType::LeftJoin,
                channels::Relation::Groups.def(),
            )
            .join(
                sea_orm::JoinType::LeftJoin,
                groups::Relation::GroupMembers.def(),
            )
            .filter(condition)
            .one(db)
            .await
            .map_err(AppError::SeaORM)?;

        let channel = match existing {
            Some(c) => c,
            None => {
                return Err(AppError::Permission(anyhow::anyhow!(
                    "You do not have permission to modify this channel"
                )))
            }
        };

        let mut active: channels::ActiveModel = channel.into();

        active.group_id = Set(payload.group_id.clone());

        if let Some(name) = payload.name {
            active.name = Set(name);
        }
        if let Some(thumbnail) = payload.thumbnail {
            active.thumbnail = Set(thumbnail);
        }
        if let Some(new_content) = payload.new_content {
            active.new_content = Set(Some(new_content));
        }
        if let Some(content_type) = payload.content_type {
            active.content_type = Set(Some(content_type));
        }

        active.update(db).await.map_err(AppError::SeaORM)?;

        channels::Entity::find()
            .filter(channels::Column::Id.eq(channel_id.clone()))
            .join(
                sea_orm::JoinType::LeftJoin,
                channels::Relation::Groups.def(),
            )
            .select_only()
            .columns(channels::Column::iter())
            .column_as(groups::Column::Name, "group_name")
            .column_as(groups::Column::Icon, "group_icon")
            .into_model::<ChannelWithGroup>()
            .one(db)
            .await
            .map_err(AppError::SeaORM)?
    } else {
        let group_id = payload.group_id.clone();
        let cleaned_url = payload.url.map(|u| u.replace("@", ""));
        let id: String = format!("{}", channel_id);
        let new_channel = channels::ActiveModel {
            id: Set(id.clone()),
            user_id: Set(user_id.clone()),
            group_id: Set(group_id),
            name: Set(payload.name.unwrap_or_default()),
            thumbnail: Set(payload.thumbnail.unwrap_or_default()),
            channel_id: Set(Some(format!("{}/{}", user_id, channel_id))),
            new_content: Set(Some(payload.new_content.unwrap_or(false))),
            url: Set(cleaned_url),
            content_type: Set(payload.content_type),
            ..Default::default()
        };

        new_channel.insert(db).await.map_err(AppError::SeaORM)?;

        channels::Entity::find()
            .filter(channels::Column::Id.eq(id))
            .join(
                sea_orm::JoinType::LeftJoin,
                channels::Relation::Groups.def(),
            )
            .select_only()
            .columns(channels::Column::iter())
            .column_as(groups::Column::Name, "group_name")
            .column_as(groups::Column::Icon, "group_icon")
            .into_model::<ChannelWithGroup>()
            .one(db)
            .await
            .map_err(AppError::SeaORM)?
    };

    inner
        .redis_cache
        .del_pattern(&format!("user:{}:groups:*", user_id))
        .await
        .ok();
    inner
        .redis_cache
        .del_pattern(&format!("user:{}:channels:*", user_id))
        .await
        .ok();
    inner
        .redis_cache
        .del_pattern(&format!("user:{}:animes:*", user_id))
        .await
        .ok();

    Ok(Json(ApiResponse::success(channel_with_group.unwrap())))
}

#[tracing::instrument(
    name = "Delete all channels by group v3 ID for user",
    skip(db, group_id, user_id)
)]
pub async fn delete_channels_by_group_id(
    db: &DatabaseConnection,
    group_id: &str,
    user_id: &str,
) -> Result<(), AppError> {
    channels::Entity::delete_many()
        .filter(channels::Column::GroupId.eq(group_id))
        .filter(channels::Column::UserId.eq(user_id))
        .exec(db)
        .await
        .map_err(AppError::SeaORM)?;

    Ok(())
}

#[tracing::instrument(
    name = "Delete missing channels by group ID (diff-based)",
    skip(db, group_id, user_id, incoming_channel_ids)
)]
pub async fn delete_missing_channels_by_group_id(
    db: &DatabaseConnection,
    group_id: &str,
    user_id: &str,
    incoming_channel_ids: &[String],
) -> Result<(), AppError> {
    let existing_ids: Vec<String> = channels::Entity::find()
        .select_only()
        .column(channels::Column::Id)
        .filter(channels::Column::GroupId.eq(group_id))
        .filter(channels::Column::UserId.eq(user_id))
        .into_tuple()
        .all(db)
        .await
        .map_err(AppError::SeaORM)?;

    let incoming: HashSet<&String> = incoming_channel_ids.iter().collect();

    let to_delete: Vec<String> = existing_ids
        .into_iter()
        .filter(|id| !incoming.contains(id))
        .collect();

    if to_delete.is_empty() {
        tracing::debug!("No channels to delete for group {}", group_id);
        return Ok(());
    } else {
        tracing::info!(
            "Found {:?} stale channels to delete for group {}",
            to_delete,
            group_id
        );
    }

    let result = channels::Entity::delete_many()
        .filter(channels::Column::Id.is_in(to_delete))
        .filter(channels::Column::GroupId.eq(group_id))
        .exec(db)
        .await
        .map_err(AppError::SeaORM)?;

    tracing::info!(
        "Deleted {} stale channels for group {}",
        result.rows_affected,
        group_id
    );

    Ok(())
}

pub async fn check_group_channel_permission(
    db: &DatabaseConnection,
    group_id: &str,
    user_id: &str,
) -> Result<GroupChannelPermission, AppError> {
    let is_owner = groups::Entity::find()
        .filter(groups::Column::Id.eq(group_id))
        .filter(groups::Column::UserId.eq(user_id))
        .one(db)
        .await
        .map_err(AppError::SeaORM)?
        .is_some();

    if is_owner {
        return Ok(GroupChannelPermission::Owner);
    }

    let is_editor = group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(group_id))
        .filter(group_members::Column::UserId.eq(user_id))
        .filter(group_members::Column::Role.is_in(["editor"]))
        .one(db)
        .await
        .map_err(AppError::SeaORM)?
        .is_some();

    if is_editor {
        return Ok(GroupChannelPermission::Editor);
    }

    let is_admin = group_members::Entity::find()
        .filter(group_members::Column::GroupId.eq(group_id))
        .filter(group_members::Column::UserId.eq(user_id))
        .filter(group_members::Column::Role.is_in(["admin"]))
        .one(db)
        .await
        .map_err(AppError::SeaORM)?
        .is_some();

    if is_admin {
        return Ok(GroupChannelPermission::Admin);
    }

    Err(AppError::Permission(anyhow::anyhow!(
        "You do not have permission to manage channels in this group"
    )))
}
