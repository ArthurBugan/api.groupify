use crate::utils::internal_error;

use std::collections::HashMap;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, FromRow, Row, Sqlite, SqlitePool, Transaction};
use tokio::sync::RwLock;
use axum::http::{HeaderMap, Response, StatusCode};
use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, NaiveDateTime, Utc};
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use serde_json::to_string_pretty;
use sha3::Digest;
use uuid::Uuid;


use crate::{InnerState};

use crate::email::{EmailClient, SendEmailRequest};

#[derive(serde::Serialize, Deserialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub group_id: String,
    pub name: String,
    pub thumbnail: String,
    pub new_content: bool,
    pub user_id: String,
}


pub async fn all_channels(State(inner): State<InnerState>, headers: HeaderMap, Path(user_id): Path<String>) -> Result<Json<Vec<Channel>>, (StatusCode, String)> {
    let fetch_channels_timeout = tokio::time::Duration::from_millis(1000);
    let InnerState { db, .. } = inner;

    tracing::debug!(
        "user id {}\
        headers {:?}",
        user_id,
        headers.get("Authorization")
    );

    let channels = tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(r#"SELECT * FROM channels where user_id = $1"#)
            .bind(user_id)
            .fetch_all(&db),
    )
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    Ok(Json(channels))
}

pub async fn create_channel(State(inner): State<InnerState>, Json(channel): Json<Channel>) -> Result<Json<Channel>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_channels_timeout = tokio::time::Duration::from_millis(1000);
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
