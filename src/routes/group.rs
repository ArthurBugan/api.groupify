use crate::utils::internal_error;

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Response, StatusCode};
use axum::Json;
use chrono::{DateTime, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use sha3::Digest;
use sqlx::{Executor, FromRow, PgPool, Postgres, Row, Transaction};
use std::collections::HashMap;
use jsonwebtoken::{decode, DecodingKey, Validation};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::InnerState;

use crate::email::{EmailClient, SendEmailRequest};
use crate::routes::{Claims, get_email_from_token};

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
    State(inner): State<InnerState>,
    headers: HeaderMap
) -> Result<Json<Vec<Group>>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let fetch_groups_timeout = tokio::time::Duration::from_millis(1000);

    tracing::debug!("headers {:?}", headers);

    let email = get_email_from_token(headers).await;

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
    State(inner): State<InnerState>,
    Json(group): Json<Group>,
) -> Result<Json<Group>, (StatusCode, String)> {
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
        sqlx::query_as::<_, Group>(
            r#"INSERT INTO groups (id, name, icon, user_id) values($1, $2, $3, $4) returning *"#,
        )
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
