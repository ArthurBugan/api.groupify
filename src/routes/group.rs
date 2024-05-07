use crate::utils::internal_error;

use std::collections::HashMap;
use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sqlx::{Executor, FromRow, Row, Sqlite, SqlitePool, Transaction};
use tokio::sync::RwLock;
use axum::http::{Response, StatusCode};
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

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub name: String,
    pub icon: String,
    pub user_id: String,
}


pub async fn all_groups(State(inner): State<InnerState>, Path(user_id): Path<String>) -> Result<Json<Vec<Group>>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(1000);

    tracing::debug!(
        "user_user_id {}",
        user_id
    );

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(r#"SELECT * FROM groups where user_id = $1"#)
            .bind(user_id)
            .fetch_all(&db),
    )
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    Ok(Json(groups))
}

pub async fn create_group(State(inner): State<InnerState>, Json(group): Json<Group>) -> Result<Json<Group>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(1000);
    println!("Received data {:?}", to_string_pretty(&group));

    let uuid = Uuid::new_v4().to_string();

    tracing::debug!(
        "group id {} \
         group created_at {} \
         group name {}\
         group icon {}",
        uuid,
        group.name,
        group.user_id,
        group.icon
    );

    let groups = tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(r#"INSERT INTO groups (id, name, icon, user_id) values($1, $2, $3, $4) returning *"#)
            .bind(uuid)
            .bind(group.name)
            .bind(group.icon)
            .bind(group.user_id)
            .fetch_one(&db),
    )
        .await
        .map_err(internal_error)?
        .map_err(internal_error)?;

    println!("Created {:?}", to_string_pretty(&groups));
    Ok(Json(groups))
}
