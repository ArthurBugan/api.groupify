use anyhow::Result;
use axum::{
    extract::{Query, State},
    Json,
};
use sea_orm::{DatabaseConnection, DbBackend, FromQueryResult, QueryResult, Statement};
use tower_cookies::Cookies;

use crate::{
    api::{
        v1::user::get_user_id_from_token,
        v2::animes::{
            AnimePaginationParams, PaginatedAnimesResponse, PaginationInfo, UnifiedAnime,
        },
    },
    errors::AppError,
    InnerState,
};

#[tracing::instrument(name = "Get all animes", skip(cookies, inner))]
pub async fn all_animes_v3(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(params): Query<AnimePaginationParams>,
) -> Result<Json<PaginatedAnimesResponse>, AppError> {
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
        "user:{}:animes:{}:{}:{}",
        user_id,
        page,
        limit,
        params.search.clone().unwrap_or_default()
    );

    if let Ok(Some(cached)) = redis_cache
        .get_json::<PaginatedAnimesResponse>(&cache_key)
        .await
    {
        return Ok(Json(cached));
    }

    // === Build dynamic SQL ===
    let mut sql = r#"
    SELECT
        COALESCE(ch.id, c.id)                       AS id,
        ch.user_id                                 AS user_id,
        ch.group_id                                AS group_id,
        'anime'                                    AS content_type,
        COALESCE(ch.name, c.title)                 AS name,
        COALESCE(ch.channel_id, c.channel_id)      AS channel_id,
        COALESCE(ch.thumbnail, c.poster_image_url) AS thumbnail,
        ch.created_at                              AS created_at,
        ch.updated_at                              AS updated_at,
        COALESCE(g.name, c.title)                  AS group_name,
        g.icon                                     AS group_icon,
        COALESCE(ch.url, c.id)                     AS url
    FROM crunchyroll_channels c
    LEFT JOIN channels ch
        ON ch.name = c.title
       AND ch.content_type = 'anime'
    LEFT JOIN users u
        ON u.id = ch.user_id
    LEFT JOIN groups g
        ON g.id = ch.group_id
"#
    .to_string();

    let mut values: Vec<sea_orm::Value> = vec![user_id.clone().into()];
    let mut bind_index = 2;

    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            sql.push_str(&format!(" WHERE COALESCE(c.title, ch.name) ILIKE ${}", bind_index));
            values.push(format!("%{}%", search).into());
            bind_index += 1;
        }
    }

    sql.push_str(&format!(
        " ORDER BY name DESC LIMIT ${} OFFSET ${}",
        bind_index,
        bind_index + 1
    ));

    values.push(limit.into());
    values.push(offset.into());

    let stmt = Statement::from_sql_and_values(DbBackend::Postgres, sql, values);

    let animes = UnifiedAnime::find_by_statement(stmt)
        .all(&sea_db)
        .await
        .map_err(AppError::SeaORM)?;

    // === Count query ===
    let mut count_sql = r#"
        SELECT COUNT(*) AS count FROM (
            SELECT ch.id, ch.name
            FROM channels ch
            INNER JOIN users u ON u.id = ch.user_id
            WHERE u.id = $1

            UNION ALL

            SELECT c.id, c.title AS name
            FROM crunchyroll_channels c
        ) AS combined
    "#
    .to_string();

    let mut count_values: Vec<sea_orm::Value> = vec![user_id.into()];
    let mut count_bind = 2;

    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            count_sql.push_str(&format!(" WHERE name ILIKE ${}", count_bind));
            count_values.push(format!("%{}%", search).into());
        }
    }

    #[derive(FromQueryResult)]
    struct CountResult {
        count: i64,
    }

    let count_stmt = Statement::from_sql_and_values(DbBackend::Postgres, count_sql, count_values);

    let total_count = CountResult::find_by_statement(count_stmt)
        .one(&sea_db)
        .await
        .map_err(AppError::SeaORM)?
        .map(|r| r.count)
        .unwrap_or(0);

    let total_pages = ((total_count as f64) / (limit as f64)).ceil() as i32;

    let response = PaginatedAnimesResponse {
        data: animes,
        pagination: PaginationInfo {
            total: total_count,
            page,
            limit,
            total_pages,
        },
    };

    let _ = redis_cache.set_json(&cache_key, &response, 300).await;

    Ok(Json(response))
}
