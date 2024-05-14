use crate::utils::internal_error;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Response, StatusCode};
use axum::Json;
use chrono::{DateTime, Local, NaiveDateTime, Utc};
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
use crate::routes::get_email_from_token;

#[derive(serde::Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub id: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub group_id: String,
    pub name: String,
    pub thumbnail: String,
    pub new_content: bool,
    pub user_id: String,
}

pub async fn all_channels(
    cookies: Cookies,
    State(inner): State<InnerState>
) -> Result<Json<Vec<Channel>>, (StatusCode, String)> {
    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

   if auth_token.clone().len() == 0 {
         return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Missing token" })).to_string()));
    }

    let email = get_email_from_token(auth_token).await;

    tracing::debug!(
        "email {}",
        email
    );

    let channels = tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(r#"SELECT c.* FROM channels c, users u where u.id = c.user_id AND u.email = $1"#)
            .bind(email)
            .fetch_all(&db),
    )
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    Ok(Json(channels))
}

pub async fn all_channels_by_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<Channel>>, (StatusCode, String)> {
    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("auth_token {}", auth_token.len(),);

   if auth_token.clone().len() == 0 {
         return Err((StatusCode::UNAUTHORIZED, Json(json!({ "error": "Missing token" })).to_string()));
    }

    let email = get_email_from_token(auth_token).await;

    tracing::debug!(
        "group id {}\
        email {}",
        group_id,
        email
    );

    let channels = tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(r#"SELECT c.* FROM channels c, users u where u.id = c.user_id AND c.group_id = $1 AND u.email = $2"#)
            .bind(group_id)
            .bind(email)
            .fetch_all(&db),
    )
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    Ok(Json(channels))
}

pub async fn create_channel(
    State(inner): State<InnerState>,
    Json(channel): Json<Channel>,
) -> Result<Json<Channel>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    println!("Received data {:?}", to_string_pretty(&channel));

    let uuid = Uuid::new_v4().to_string();

    tracing::debug!(
        "channel id {} \
         channel name {}\
         channel user id {}\
         channel group id {}",
        uuid,
        channel.name,
        channel.user_id,
        channel.group_id
    );

    let channels = tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(r#"INSERT INTO channels (id, group_id, name, thumbnail, new_content, user_id) values($1, $2, $3, $4, $5, $6) returning *"#)
            .bind(uuid)
            .bind(channel.group_id)
            .bind(channel.name)
            .bind(channel.thumbnail)
            .bind(channel.new_content)
            .bind(channel.user_id)
            .fetch_one(&db),
    )
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    println!("Created {:?}", to_string_pretty(&channels));
    Ok(Json(channels))
}
