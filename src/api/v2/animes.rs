use crate::api::common::utils::timeout_query;
use crate::api::v1::user::get_user_id_from_token;
use crate::errors::AppError;
use crate::InnerState;
use anyhow::Result;
use axum::extract::{Query, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, QueryBuilder};
use tower_cookies::Cookies;

/// Pagination parameters for anime queries
#[derive(Debug, Deserialize)]
pub struct AnimePaginationParams {
    pub page: Option<i32>,
    pub limit: Option<i32>,
    pub search: Option<String>,
}

/// Paginated response structure for animes
#[derive(Debug, Serialize)]
pub struct PaginatedAnimesResponse {
    pub data: Vec<UnifiedAnime>,
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

/// Anime for API responses
#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Anime {
    pub id: String,
    pub external_id: Option<String>,
    pub slug_title: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub promo_title: Option<String>,
    pub promo_description: Option<String>,
    pub last_public: NaiveDateTime,
    #[sqlx(rename = "type")]
    pub r#type: Option<String>,
    pub channel_id: Option<String>,
    #[sqlx(rename = "new")]
    pub is_new: Option<bool>,
    pub average_rating: Option<f64>,
    pub total_ratings: Option<i32>,
    pub poster_image_url: Option<String>,
    pub wide_image_url: Option<String>,
    pub audio_locales: Option<Vec<String>>,
    pub subtitle_locales: Option<Vec<String>>,
    pub content_descriptors: Option<Vec<String>>,
    pub maturity_ratings: Option<Vec<String>>,
    pub extended_maturity_level: Option<String>,
    pub extended_maturity_rating: Option<String>,
    pub rating_system: Option<String>,
    pub episode_count: Option<i32>,
    pub season_count: Option<i32>,
    pub launch_year: Option<i32>,
    pub is_dubbed: Option<bool>,
    pub is_subbed: Option<bool>,
    pub is_mature: Option<bool>,
    pub is_simulcast: Option<bool>,
    pub tenant_categories: Option<Vec<String>>,
    pub group_name: Option<String>,
    pub group_icon: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchAnimeRequest {
    pub id: String,
    pub external_id: Option<String>,
    pub slug_title: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub promo_title: Option<String>,
    pub promo_description: Option<String>,
    pub last_public: Option<NaiveDateTime>,
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub channel_id: Option<String>,
    #[serde(rename = "new")]
    pub is_new: Option<bool>,
    pub average_rating: Option<f64>,
    pub total_ratings: Option<i32>,
    pub poster_image_url: Option<String>,
    pub wide_image_url: Option<String>,
    pub audio_locales: Option<Vec<String>>,
    pub subtitle_locales: Option<Vec<String>>,
    pub content_descriptors: Option<Vec<String>>,
    pub maturity_ratings: Option<Vec<String>>,
    pub extended_maturity_level: Option<String>,
    pub extended_maturity_rating: Option<String>,
    pub rating_system: Option<String>,
    pub episode_count: Option<i32>,
    pub season_count: Option<i32>,
    pub launch_year: Option<i32>,
    pub is_dubbed: Option<bool>,
    pub is_subbed: Option<bool>,
    pub is_mature: Option<bool>,
    pub is_simulcast: Option<bool>,
    pub tenant_categories: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchAnimesBatchRequest {
    pub animes: Vec<PatchAnimeRequest>,
}

#[derive(Deserialize, Serialize, Debug, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedAnime {
    pub id: String,
    pub user_id: Option<String>,
    pub group_id: Option<String>,
    pub content_type: Option<String>,
    pub name: String,
    pub channel_id: String,
    pub thumbnail: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub group_name: Option<String>,
    pub group_icon: Option<String>,
    pub url: Option<String>,
}

#[tracing::instrument(name = "Get all animes", skip(cookies, inner))]
pub async fn all_animes(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(params): Query<AnimePaginationParams>,
) -> Result<Json<PaginatedAnimesResponse>, AppError> {
    let start_time = std::time::Instant::now();
    let InnerState { db, .. } = inner;

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

    let fetch_timeout = tokio::time::Duration::from_secs(10);

    // === Build Query using sqlx::QueryBuilder ===
    let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"
        SELECT 
            id, user_id, group_id, name, channel_id, thumbnail, 
            created_at, updated_at, group_name, group_icon, url, content_type
        FROM (
            SELECT 
                ch.id, ch.user_id, ch.group_id, ch.name, ch.channel_id, ch.thumbnail, 
                ch.created_at, ch.updated_at, g.name AS group_name, g.icon AS group_icon, 
                ch.url, ch.content_type
            FROM channels ch
            INNER JOIN users u ON u.id = ch.user_id
            LEFT JOIN groups g ON g.id = ch.group_id
            WHERE ch.content_type = 'anime'
            AND u.id = "#,
    );

    builder.push_bind(user_id.clone());

    builder.push(
        r#"
            UNION ALL
            SELECT 
                c.id, NULL AS user_id, NULL AS group_id, c.title AS name, c.channel_id, 
                c.poster_image_url AS thumbnail, NULL AS created_at, NULL AS updated_at, 
                c.title AS group_name, NULL AS group_icon, c.id AS url, 'anime' as content_type
            FROM crunchyroll_channels c
            WHERE NOT EXISTS (SELECT 1 FROM channels c2 WHERE c2.name = c.title)
        ) AS combined_animes
        "#,
    );

    // === Add search filter if provided ===
    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            builder.push(" WHERE name ILIKE ");
            builder.push_bind(format!("%{}%", search));
        }
    }

    builder.push(" ORDER BY name DESC");
    builder.push(" LIMIT ");
    builder.push_bind(limit);
    builder.push(" OFFSET ");
    builder.push_bind(offset);

    let query = builder.build_query_as::<UnifiedAnime>();

   let animes: Vec<UnifiedAnime> = timeout_query(fetch_timeout, query.fetch_all(&db))
        .await
        .inspect_err(|e| tracing::error!("all_animes: Database error: {:?}", e))?;

    // === Count query ===
    let mut count_builder: QueryBuilder<Postgres> = QueryBuilder::new(
        r#"
        SELECT COUNT(*) FROM (
            SELECT ch.id, ch.name
            FROM channels ch
            INNER JOIN users u ON u.id = ch.user_id
            WHERE u.id = "#,
    );
    count_builder.push_bind(user_id);

    count_builder.push(
        r#"
            UNION ALL
            SELECT c.id, c.title as name FROM crunchyroll_channels c
        ) AS combined_animes
        "#,
    );

    if let Some(search) = &params.search {
        if !search.trim().is_empty() {
            count_builder.push(" WHERE name ILIKE ");
            count_builder.push_bind(format!("%{}%", search));
        }
    }

    let count_query = count_builder.build_query_scalar::<i64>();
    let total_count: i64 = timeout_query(fetch_timeout, count_query.fetch_one(&db))
        .await
        .inspect_err(|e| tracing::error!("all_animes: total_count Database error: {:?}", e))?;

    let total_pages = ((total_count as f64) / (limit as f64)).ceil() as i32;

    Ok(Json(PaginatedAnimesResponse {
        data: animes,
        pagination: PaginationInfo {
            total: total_count,
            page,
            limit,
            total_pages,
        },
    }))
}