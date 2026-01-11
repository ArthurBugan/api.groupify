use anyhow::Result;
use axum::{
    extract::{Query, State},
    Json,
};
use chrono::NaiveDateTime;
use sea_orm::{
    sea_query::Expr, ColumnTrait, Condition, EntityTrait, FromQueryResult, JoinType, Order,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, RelationTrait,
};
use std::collections::HashMap;
use tower_cookies::Cookies;

use crate::{
    api::{
        common::{PaginatedResponse, PaginationInfo, PaginationParams},
        v1::user::get_user_id_from_token,
        v2::groups::Group,
        v3::entities::{channels, group_members, groups},
    },
    errors::AppError,
    InnerState,
};

#[derive(Debug, Clone, FromQueryResult)]
struct GroupRow {
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
}

#[derive(Debug, Clone, FromQueryResult)]
struct GroupChannelCountRow {
    pub group_id: String,
    pub channel_count: i64,
}

#[tracing::instrument(name = "Get all groups v3 (SeaORM)", skip(cookies, inner))]
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

    let rows: Vec<GroupRow> = data_q
        .into_model::<GroupRow>()
        .all(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    let group_ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();

    let channel_counts: Vec<GroupChannelCountRow> = if group_ids.is_empty() {
        Vec::new()
    } else {
        channels::Entity::find()
            .select_only()
            .column(channels::Column::GroupId)
            .expr_as(Expr::cust("COUNT(*)"), "channel_count")
            .filter(channels::Column::UserId.eq(user_id.clone()))
            .filter(channels::Column::GroupId.is_in(group_ids))
            .group_by(channels::Column::GroupId)
            .into_model::<GroupChannelCountRow>()
            .all(&sea_db)
            .await
            .map_err(AppError::SeaORM)?
    };

    let channel_count_map: HashMap<String, i64> = channel_counts
        .into_iter()
        .map(|r| (r.group_id, r.channel_count))
        .collect();

    let mut out: Vec<Group> = Vec::with_capacity(rows.len());
    for row in rows {
        let channel_count = channel_count_map.get(&row.id).copied().unwrap_or(0);

        out.push(Group {
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
            channel_count: Some(channel_count),
            channels: Vec::new(),
        });
    }

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
