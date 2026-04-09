use anyhow::Result;
use axum::{
    extract::{Query, State},
    Json,
};
use sea_orm::{ColumnTrait, EntityTrait, FromQueryResult, JoinType, QueryFilter, QuerySelect, RelationTrait, sea_query::Expr};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;

use crate::{
    api::{
        v1::user::get_user_id_from_token,
        common::{PaginatedResponse, PaginationInfo},
        v3::entities::{channels, groups},
    },
    errors::AppError,
    InnerState,
};

#[derive(Debug, Serialize, Deserialize, FromQueryResult, Clone)]
#[serde(rename_all = "camelCase")]
pub struct WebsiteChannel {
    pub id: String,
    pub user_id: Option<String>,
    pub group_id: Option<String>,
    pub name: String,
    pub channel_id: String,
    pub thumbnail: Option<String>,
    pub created_at: Option<sea_orm::prelude::DateTime>,
    pub updated_at: Option<sea_orm::prelude::DateTime>,
    pub group_name: Option<String>,
    pub group_icon: Option<String>,
    pub url: Option<String>,
    pub content_type: String,
}

#[derive(Debug, Deserialize)]
pub struct WebsitePaginationParams {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub search: Option<String>,
}

#[tracing::instrument(name = "Get all website channels", skip(cookies, inner))]
pub async fn all_websites_v3(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(params): Query<WebsitePaginationParams>,
) -> Result<Json<PaginatedResponse<WebsiteChannel>>, AppError> {
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
    let limit = params.limit.unwrap_or(25).max(1).min(100);
    let offset = (page - 1) * limit;

    let cache_key = format!(
        "user:{}:websites:{}:{}:{}",
        user_id,
        page,
        limit,
        params.search.clone().unwrap_or_default()
    );

    if let Ok(Some(cached)) = redis_cache
        .get_json::<PaginatedResponse<WebsiteChannel>>(&cache_key)
        .await
    {
        return Ok(Json(cached));
    }

    let channels_q = channels::Entity::find()
        .filter(channels::Column::UserId.eq(user_id.clone()))
        .filter(channels::Column::ContentType.eq("website"))
        .join(JoinType::LeftJoin, channels::Relation::Groups.def())
        .select_only()
        .column(channels::Column::Id)
        .column(channels::Column::UserId)
        .column(channels::Column::GroupId)
        .column(channels::Column::Name)
        .expr_as(Expr::cust("COALESCE(channels.channel_id, '')"), "channel_id")
        .column(channels::Column::Thumbnail)
        .column(channels::Column::CreatedAt)
        .column(channels::Column::UpdatedAt)
        .column_as(groups::Column::Name, "group_name")
        .column_as(groups::Column::Icon, "group_icon")
        .column(channels::Column::Url)
        .column(channels::Column::ContentType);

    let channels_q = if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            channels_q.filter(channels::Column::Name.ilike(format!("%{}%", search)))
        } else {
            channels_q
        }
    } else {
        channels_q
    };

    let websites: Vec<WebsiteChannel> = channels_q
        .into_model::<WebsiteChannel>()
        .all(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    let total_count = websites.len() as i64;
    let start = offset as usize;
    let end = (start + limit as usize).min(websites.len());
    let page_data = if start < websites.len() { websites[start..end].to_vec() } else { Vec::new() };

    let total_pages = ((total_count as f64) / (limit as f64)).ceil() as u32;
    let has_next = page < total_pages;
    let has_prev = page > 1;

    let response = PaginatedResponse {
        data: page_data,
        pagination: PaginationInfo {
            total: total_count,
            page: page as u32,
            limit: limit as u32,
            total_pages,
            has_next,
            has_prev,
        },
    };

    let _ = redis_cache.set_json(&cache_key, &response, 300).await;

    Ok(Json(response))
}
