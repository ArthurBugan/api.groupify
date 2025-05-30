use crate::errors::AppError;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty, Value};
use sqlx::{Executor, FromRow, PgPool};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::InnerState;

use crate::routes::{get_email_from_token, get_user_id_from_token};

#[derive(Serialize, Deserialize, FromRow, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Channel {
    pub id: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub group_id: String,
    pub channel_id: String,
    pub name: String,
    pub thumbnail: String,
    pub new_content: bool,
    pub user_id: String,
}

#[derive(Serialize, Deserialize, FromRow, Debug)]
#[serde(rename_all = "camelCase")]
pub struct YoutubeChannel {
    pub id: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub url: String,
    pub channel_id: String,
    pub name: String,
    pub thumbnail: String,
    pub new_content: bool,
}

pub async fn all_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<Channel>>, AppError> { // Changed return type
    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let email = get_email_from_token(auth_token).await?; // Assuming get_email_from_token returns Result<_, AppError>

    tracing::debug!("email {}", email);

    let channels = tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(
            r#"SELECT c.* FROM channels c, users u where u.id = c.user_id AND u.email = $1"#,
        )
        .bind(email)
        .fetch_all(&db),
    )
    .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    Ok(Json(channels))
}

pub async fn all_channels_by_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<Channel>>, AppError> { // Changed return type
    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("auth_token {}", auth_token.len());

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let email = get_email_from_token(auth_token).await?; // Assuming get_email_from_token returns Result<_, AppError>

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
        .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    Ok(Json(channels))
}

pub async fn fetch_youtube_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<YoutubeChannel>>, AppError> { // Changed return type
    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("auth_token {}", auth_token.len());

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let user_id = get_user_id_from_token(auth_token).await?; // Assuming get_user_id_from_token returns Result<_, AppError>

    let channels = tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, YoutubeChannel>(
            r#"SELECT * FROM youtube_channels yt, users u where u.id = yt.user_id AND u.id = $1"#,
        )
        .bind(user_id)
        .fetch_all(&db),
    )
    .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    Ok(Json(channels))
}

pub async fn create_channel(
    State(inner): State<InnerState>,
    Json(channel): Json<Channel>,
) -> Result<Json<Channel>, AppError> { // Changed return type
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
        .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    Ok(Json(channels))
}

pub async fn update_channels_in_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(channels): Json<Vec<Channel>>,
) -> Result<Json<String>, AppError> { // Changed return type
    let InnerState {
        email_client, db, ..
    } = inner;
    let update_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let user_id = get_user_id_from_token(auth_token).await?; // Assuming get_user_id_from_token returns Result<_, AppError>

    let mut tx = db.begin().await?; // Replaced .map_err(internal_error)?

    tokio::time::timeout(
        update_groups_timeout,
        sqlx::query_as::<_, Channel>(
            r#"DELETE FROM channels where group_id = $1 and user_id = $2"#,
        )
        .bind(channels[0].group_id.clone()) // Potential panic if channels is empty
        .bind(user_id.clone())
        .fetch_optional(&db), // This is inside a transaction, should use &mut tx
    )
    .await??; // Replaced .map_err(internal_error)?.map_err(internal_error)? with ??

    for channel in channels {
        let query = sqlx::query_as::<_, Channel>(r#"INSERT INTO channels (id, group_id, name, thumbnail, new_content, channel_id, user_id) values($1, $2, $3, $4, $5, $6, $7) returning *"#)
            .bind(&channel.id)
            .bind(&channel.group_id)
            .bind(&channel.name)
            .bind(&channel.thumbnail)
            .bind(&channel.new_content)
            .bind(&channel.channel_id)
            .bind(&user_id);

        tx.execute(query).await?; // Replaced .map_err(internal_error)?
    }

    tx.commit().await?; // Replaced .map_err(internal_error)?

    Ok(Json("OK".to_owned()))
}

pub async fn save_youtube_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(channels): Json<Vec<YoutubeChannel>>,
) -> Result<Json<Value>, AppError> { // Changed return type
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token"))); // Use AppError
    }

    let user_id = get_user_id_from_token(auth_token).await?; // Assuming get_user_id_from_token returns Result<_, AppError>

    let number_of_channels = count_all_channels(user_id.clone(), &db).await?;

    if number_of_channels as usize == channels.len() {
        return Ok(Json(json!({ "data": "Same size"})));
    }

    if number_of_channels > 0 {
        sqlx::query!("DELETE FROM youtube_channels WHERE user_id = $1", &user_id)
            .execute(&db)
            .await?;
            // .map_err(internal_error)?; // Removed
    }

    bulk_insert_channels(&db, user_id, &channels)
        .await?;
        // .map_err(internal_error)?; // Removed

    return Ok(Json(json!({ "success": "true" })));
}

pub async fn count_all_channels(user_id: String, db: &PgPool) -> Result<i64, AppError> { // Changed return type
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM youtube_channels where user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await?;
        // .map_err(internal_error)?; // Removed

    Ok(count)
}

async fn bulk_insert_channels(
    pool: &sqlx::PgPool,
    user_id: String,
    channels: &[YoutubeChannel],
) -> Result<(), AppError> { // Changed return type, sqlx::Error will be converted via From
    // Start a transaction
    let mut transaction = pool.begin().await?;

    // Construct the COPY FROM STDIN query
    let copy_query = "COPY youtube_channels (id, name, thumbnail, new_content, channel_id, user_id, url) FROM STDIN (FORMAT CSV)";

    // Execute the COPY command
    let mut copy_in = transaction.copy_in_raw(copy_query).await?;

    // Iterate over the channels and write them to the COPY stream
    for channel in channels {
        let concat_id = user_id.clone() + "/" + &*channel.channel_id.clone();

        // Replace commas with periods in each field
        let id = channel.id.as_ref().unwrap().replace(",", "."); // .unwrap() can panic
        let name = channel.name.replace(",", ".");
        let thumbnail = channel.thumbnail.replace(",", ".");
        let new_content = channel.new_content;
        let channel_id_clean = concat_id.replace(",", "."); // Renamed to avoid conflict
        let user_id_clean = user_id.replace(",", ".");
        let clean_url = channel.url.replace(",", ".");

        // Construct the data string
        let data = format!(
            "{},{},{},{},{},{},{}\n",
            id, name, thumbnail, new_content, channel_id_clean, user_id_clean, clean_url
        );

        copy_in
            .send(data.as_bytes())
            .await
            // .map_err(internal_error) // Removed
            // .expect("Failed to send data to COPY stream"); // Replaced with ?
            .map_err(|e| AppError::Database(anyhow::anyhow!("Failed to send data to COPY stream: {}", e)))?;
    }

    // Complete the COPY operation
    copy_in.finish().await?;

    // Commit the transaction
    transaction.commit().await?;

    Ok(())
}
