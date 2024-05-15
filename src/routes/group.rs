use crate::utils::internal_error;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::Json;
use chrono::{DateTime, NaiveDateTime, Utc};
use jsonwebtoken::{decode, DecodingKey, Validation};
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty, Value};
use sha3::Digest;
use sqlx::{Executor, FromRow, PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
use tokio::sync::RwLock;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::InnerState;

use crate::email::{EmailClient, SendEmailRequest};
use crate::routes::{get_email_from_token, Claims, get_user_id_from_token};

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub name: String,
    pub icon: String,
    pub user_id: String,
}

pub async fn all_groups(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<Group>>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("auth_token {}", auth_token.len(),);

    if auth_token.clone().len() == 0 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Missing token" })).to_string(),
        ));
    }

    let email = get_email_from_token(auth_token).await;

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(r#"SELECT *, g.id as id FROM groups g, users u where u.id = g.user_id and u.email = $1"#)
            .bind(email)
            .fetch_all(&db),
    )
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(Json(groups))
}

pub async fn create_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let uuid = Uuid::new_v4().to_string();

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

   if auth_token.clone().len() == 0 {
         return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Missing token" })).to_string()));
    }

    let user_id = get_user_id_from_token(auth_token).await;

    tracing::debug!(
        "group id {} \
         group created_at {} \
         group name {}\
         group icon {}",
        uuid,
        group.name,
        user_id,
        group.icon
    );

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(
            r#"INSERT INTO groups (id, name, icon, user_id) values($1, $2, $3, $4) returning *"#,
        )
        .bind(uuid)
        .bind(group.name)
        .bind(group.icon)
        .bind(user_id)
        .fetch_one(&db),
    )
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    println!("Created {:?}", to_string_pretty(&groups));
    Ok(Json(groups))
}

pub async fn update_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

   if auth_token.clone().len() == 0 {
         return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Missing token" })).to_string()));
    }

    let user_id = get_user_id_from_token(auth_token).await;

    tracing::debug!(
        "group id {} \
         group name {}\
         user id {}\
         group icon {}",
        group_id,
        group.name,
        user_id,
        group.icon
    );

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(
            r#"UPDATE groups SET name = $2, icon = $3 where id = $1 and user_id = $4 returning *"#,
        )
        .bind(group_id)
        .bind(group.name)
        .bind(group.icon)
        .bind(user_id)
        .fetch_one(&db),
    )
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    println!("Created {:?}", to_string_pretty(&groups));
    Ok(Json(groups))
}