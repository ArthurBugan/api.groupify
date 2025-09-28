use crate::errors::AppError;
use anyhow::Result;
use axum::extract::{Path, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string_pretty, Value};
use sqlx::{FromRow, PgPool};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::InnerState;

use crate::api::v1::{get_email_from_token, get_user_id_from_token};

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

#[tracing::instrument(name = "Get all channels for user", skip(cookies, inner))]
pub async fn all_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<Channel>>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!("Starting all_channels request");

    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("all_channels: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let email = match get_email_from_token(auth_token).await {
        Ok(email) => {
            tracing::debug!("all_channels: Successfully extracted email from token");
            email
        }
        Err(e) => {
            tracing::error!("all_channels: Failed to extract email from token: {:?}", e);
            return Err(e);
        }
    };

    tracing::info!("all_channels: Fetching channels for email: {}", email);

    let channels = match tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(
            r#"SELECT c.* FROM channels c, users u where u.id = c.user_id AND u.email = $1"#,
        )
        .bind(&email)
        .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(channels)) => {
            tracing::info!(
                "all_channels: Successfully fetched {} channels",
                channels.len()
            );
            channels
        }
        Ok(Err(e)) => {
            tracing::error!(
                "all_channels: Database error while fetching channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "all_channels: Timeout while fetching channels: {:?}",
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_channels_timeout
            )));
        }
    };

    let duration = start_time.elapsed();
    tracing::info!("all_channels: Completed successfully in {:?}", duration);
    Ok(Json(channels))
}

#[tracing::instrument(name = "Get all channels by group", skip(cookies, inner), fields(group_id = %group_id))]
pub async fn all_channels_by_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<Channel>>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Starting all_channels_by_group request for group_id: {}",
        group_id
    );

    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!(
        "all_channels_by_group: Auth token length: {}",
        auth_token.len()
    );

    if auth_token.is_empty() {
        tracing::warn!("all_channels_by_group: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let email = match get_email_from_token(auth_token).await {
        Ok(email) => {
            tracing::debug!("all_channels_by_group: Successfully extracted email from token");
            email
        }
        Err(e) => {
            tracing::error!(
                "all_channels_by_group: Failed to extract email from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    tracing::info!(
        "all_channels_by_group: Fetching channels for group_id: {}, email: {}",
        group_id,
        email
    );

    let channels = match tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(r#"SELECT c.* FROM channels c, users u where u.id = c.user_id AND c.group_id = $1 AND u.email = $2"#)
            .bind(&group_id)
            .bind(&email)
            .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(channels)) => {
            tracing::info!(
                "all_channels_by_group: Successfully fetched {} channels",
                channels.len()
            );
            channels
        }
        Ok(Err(e)) => {
            tracing::error!(
                "all_channels_by_group: Database error while fetching channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("all_channels_by_group: Timeout while fetching channels: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_channels_timeout
            )));
        }
    };

    let duration = start_time.elapsed();
    tracing::info!(
        "all_channels_by_group: Completed successfully in {:?}",
        duration
    );
    Ok(Json(channels))
}

#[tracing::instrument(name = "Fetch YouTube channels", skip(cookies, inner))]
pub async fn fetch_youtube_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Vec<YoutubeChannel>>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!("Starting fetch_youtube_channels request");

    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);
    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!(
        "fetch_youtube_channels: Auth token length: {}",
        auth_token.len()
    );

    if auth_token.is_empty() {
        tracing::warn!("fetch_youtube_channels: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => {
            tracing::debug!("fetch_youtube_channels: Successfully extracted user_id from token");
            user_id
        }
        Err(e) => {
            tracing::error!(
                "fetch_youtube_channels: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    tracing::info!(
        "fetch_youtube_channels: Fetching YouTube channels for user_id: {}",
        user_id
    );

    let channels = match tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, YoutubeChannel>(
            r#"SELECT * FROM youtube_channels yt, users u where u.id = yt.user_id AND u.id = $1"#,
        )
        .bind(&user_id)
        .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(channels)) => {
            tracing::info!(
                "fetch_youtube_channels: Successfully fetched {} YouTube channels",
                channels.len()
            );
            channels
        }
        Ok(Err(e)) => {
            tracing::error!(
                "fetch_youtube_channels: Database error while fetching YouTube channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "fetch_youtube_channels: Timeout while fetching YouTube channels: {:?}",
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_channels_timeout
            )));
        }
    };

    let duration = start_time.elapsed();
    tracing::info!(
        "fetch_youtube_channels: Completed successfully in {:?}",
        duration
    );
    Ok(Json(channels))
}

#[tracing::instrument(name = "Create new channel", skip(inner, channel), fields(channel_name = %channel.name, group_id = %channel.group_id, user_id = %channel.user_id))]
pub async fn create_channel(
    State(inner): State<InnerState>,
    Json(channel): Json<Channel>,
) -> Result<Json<Channel>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!("Starting create_channel request");

    let InnerState { db, .. } = inner;

    let fetch_channels_timeout = tokio::time::Duration::from_millis(10000);

    tracing::debug!(
        "create_channel: Received channel data: {:?}",
        to_string_pretty(&channel)
    );

    let uuid = Uuid::new_v4().to_string();

    tracing::info!(
        "create_channel: Creating channel with id: {}, name: {}, user_id: {}, group_id: {}",
        uuid,
        channel.name,
        channel.user_id,
        channel.group_id
    );

    let created_channel = match tokio::time::timeout(
        fetch_channels_timeout,
        sqlx::query_as::<_, Channel>(r#"INSERT INTO channels (id, group_id, name, thumbnail, new_content, user_id) values($1, $2, $3, $4, $5, $6) returning *"#)
            .bind(&uuid)
            .bind(&channel.group_id)
            .bind(&channel.name)
            .bind(&channel.thumbnail)
            .bind(channel.new_content)
            .bind(&channel.user_id)
            .fetch_one(&db),
    )
    .await
    {
        Ok(Ok(channel)) => {
            tracing::info!("create_channel: Successfully created channel with id: {}", uuid);
            channel
        }
        Ok(Err(e)) => {
            tracing::error!("create_channel: Database error while creating channel: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("create_channel: Timeout while creating channel: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_channels_timeout
            )));
        }
    };

    let duration = start_time.elapsed();
    tracing::info!("create_channel: Completed successfully in {:?}", duration);
    Ok(Json(created_channel))
}

#[tracing::instrument(name = "Update channels in group", skip(cookies, inner, channels), fields(channel_count = channels.len()))]
pub async fn update_channels_in_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(channels): Json<Vec<Channel>>,
) -> Result<Json<String>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Starting update_channels_in_group request with {} channels",
        channels.len()
    );

    let InnerState {
        email_client, db, ..
    } = inner;
    let update_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("update_channels_in_group: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => {
            tracing::debug!("update_channels_in_group: Successfully extracted user_id from token");
            user_id
        }
        Err(e) => {
            tracing::error!(
                "update_channels_in_group: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    if channels.is_empty() {
        tracing::warn!("update_channels_in_group: No channels provided for update");
        return Err(AppError::NotFound(String::from("No channels provided")));
    }

    let group_id = &channels[0].group_id;
    tracing::info!(
        "update_channels_in_group: Updating channels for group_id: {}, user_id: {}",
        group_id,
        user_id
    );

    let mut tx = match db.begin().await {
        Ok(tx) => {
            tracing::debug!("update_channels_in_group: Started database transaction");
            tx
        }
        Err(e) => {
            tracing::error!(
                "update_channels_in_group: Failed to start transaction: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
    };

    // Delete existing channels
    match tokio::time::timeout(
        update_groups_timeout,
        sqlx::query(r#"DELETE FROM channels where group_id = $1 and user_id = $2"#)
            .bind(group_id)
            .bind(&user_id)
            .execute(&mut *tx),
    )
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                "update_channels_in_group: Deleted {} existing channels",
                result.rows_affected()
            );
        }
        Ok(Err(e)) => {
            tracing::error!(
                "update_channels_in_group: Database error while deleting channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "update_channels_in_group: Timeout while deleting channels: {:?}",
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_groups_timeout
            )));
        }
    }

    // Insert new channels
    for (index, channel) in channels.iter().enumerate() {
        tracing::debug!(
            "update_channels_in_group: Inserting channel {} of {}: {}",
            index + 1,
            channels.len(),
            channel.name
        );

        let query = sqlx::query(r#"INSERT INTO channels (id, group_id, name, thumbnail, new_content, channel_id, user_id) values($1, $2, $3, $4, $5, $6, $7)"#)
            .bind(&channel.id)
            .bind(&channel.group_id)
            .bind(&channel.name)
            .bind(&channel.thumbnail)
            .bind(channel.new_content)
            .bind(&channel.channel_id)
            .bind(&user_id);

        if let Err(e) = query.execute(&mut *tx).await {
            tracing::error!(
                "update_channels_in_group: Failed to insert channel {}: {:?}",
                channel.name,
                e
            );
            return Err(AppError::from(e));
        }
    }

    match tx.commit().await {
        Ok(_) => {
            tracing::info!("update_channels_in_group: Successfully committed transaction");
        }
        Err(e) => {
            tracing::error!(
                "update_channels_in_group: Failed to commit transaction: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
    }

    let duration = start_time.elapsed();
    tracing::info!(
        "update_channels_in_group: Completed successfully in {:?}",
        duration
    );
    Ok(Json("OK".to_owned()))
}

#[tracing::instrument(name = "Save YouTube channels", skip(cookies, inner, channels), fields(channel_count = channels.len()))]
pub async fn save_youtube_channels(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(channels): Json<Vec<YoutubeChannel>>,
) -> Result<Json<Value>, AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Starting save_youtube_channels request with {} channels",
        channels.len()
    );

    let InnerState { db, .. } = inner;

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("save_youtube_channels: Missing authentication token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    let user_id = match get_user_id_from_token(auth_token).await {
        Ok(user_id) => {
            tracing::debug!("save_youtube_channels: Successfully extracted user_id from token");
            user_id
        }
        Err(e) => {
            tracing::error!(
                "save_youtube_channels: Failed to extract user_id from token: {:?}",
                e
            );
            return Err(e);
        }
    };

    tracing::info!(
        "save_youtube_channels: Processing YouTube channels for user_id: {}",
        user_id
    );

    let number_of_channels = match count_all_channels(user_id.clone(), &db).await {
        Ok(count) => {
            tracing::debug!("save_youtube_channels: Current channel count: {}", count);
            count
        }
        Err(e) => {
            tracing::error!(
                "save_youtube_channels: Failed to count existing channels: {:?}",
                e
            );
            return Err(e);
        }
    };

    if number_of_channels as usize == channels.len() {
        tracing::info!("save_youtube_channels: Channel count unchanged, skipping update");
        let duration = start_time.elapsed();
        tracing::info!(
            "save_youtube_channels: Completed (no changes) in {:?}",
            duration
        );
        return Ok(Json(json!({ "data": "Same size"})));
    }

    if number_of_channels > 0 {
        tracing::info!(
            "save_youtube_channels: Deleting {} existing channels",
            number_of_channels
        );
        if let Err(e) = sqlx::query!("DELETE FROM youtube_channels WHERE user_id = $1", &user_id)
            .execute(&db)
            .await
        {
            tracing::error!(
                "save_youtube_channels: Failed to delete existing channels: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
        tracing::debug!("save_youtube_channels: Successfully deleted existing channels");
    }

    tracing::info!(
        "save_youtube_channels: Bulk inserting {} new channels",
        channels.len()
    );
    if let Err(e) = bulk_insert_channels(&db, user_id, &channels).await {
        tracing::error!(
            "save_youtube_channels: Failed to bulk insert channels: {:?}",
            e
        );
        return Err(e);
    }

    let duration = start_time.elapsed();
    tracing::info!(
        "save_youtube_channels: Completed successfully in {:?}",
        duration
    );
    Ok(Json(json!({ "success": "true" })))
}

#[tracing::instrument(name = "Count all channels", skip(db), fields(user_id = %user_id))]
pub async fn count_all_channels(user_id: String, db: &PgPool) -> Result<i64, AppError> {
    let start_time = std::time::Instant::now();
    tracing::debug!("Starting count_all_channels for user_id: {}", user_id);

    let count: i64 =
        match sqlx::query_scalar("SELECT COUNT(*) FROM youtube_channels where user_id = $1")
            .bind(&user_id)
            .fetch_one(db)
            .await
        {
            Ok(count) => {
                tracing::debug!("count_all_channels: Found {} channels", count);
                count
            }
            Err(e) => {
                tracing::error!(
                    "count_all_channels: Database error while counting channels: {:?}",
                    e
                );
                return Err(AppError::from(e));
            }
        };

    let duration = start_time.elapsed();
    tracing::debug!("count_all_channels: Completed in {:?}", duration);
    Ok(count)
}

#[tracing::instrument(name = "Bulk insert YouTube channels", skip(pool, channels), fields(user_id = %user_id, channel_count = channels.len()))]
async fn bulk_insert_channels(
    pool: &sqlx::PgPool,
    user_id: String,
    channels: &[YoutubeChannel],
) -> Result<(), AppError> {
    let start_time = std::time::Instant::now();
    tracing::info!(
        "Starting bulk_insert_channels for {} channels",
        channels.len()
    );

    // Start a transaction
    let mut transaction = match pool.begin().await {
        Ok(tx) => {
            tracing::debug!("bulk_insert_channels: Started database transaction");
            tx
        }
        Err(e) => {
            tracing::error!("bulk_insert_channels: Failed to start transaction: {:?}", e);
            return Err(AppError::from(e));
        }
    };

    // Construct the COPY FROM STDIN query
    let copy_query = "COPY youtube_channels (id, name, thumbnail, new_content, channel_id, user_id, url) FROM STDIN (FORMAT CSV)";

    // Execute the COPY command
    let mut copy_in = match transaction.copy_in_raw(copy_query).await {
        Ok(copy_in) => {
            tracing::debug!("bulk_insert_channels: Started COPY operation");
            copy_in
        }
        Err(e) => {
            tracing::error!(
                "bulk_insert_channels: Failed to start COPY operation: {:?}",
                e
            );
            return Err(AppError::from(e));
        }
    };

    // Iterate over the channels and write them to the COPY stream
    for (index, channel) in channels.iter().enumerate() {
        tracing::debug!(
            "bulk_insert_channels: Processing channel {} of {}: {}",
            index + 1,
            channels.len(),
            channel.name
        );

        let concat_id = user_id.clone() + "/" + &*channel.channel_id.clone();

        // Replace commas with periods in each field
        let id = channel
            .id
            .as_ref()
            .ok_or_else(|| {
                tracing::error!("bulk_insert_channels: Channel {} has no ID", channel.name);
                AppError::Validation(format!("Channel {} has no ID", channel.name))
            })?
            .replace(",", ".");
        let name = channel.name.replace(",", ".");
        let thumbnail = channel.thumbnail.replace(",", ".");
        let new_content = channel.new_content;
        let channel_id_clean = concat_id.replace(",", ".");
        let user_id_clean = user_id.replace(",", ".");
        let clean_url = channel.url.replace(",", ".");

        // Construct the data string
        let data = format!(
            "{},{},{},{},{},{},{}\n",
            id, name, thumbnail, new_content, channel_id_clean, user_id_clean, clean_url
        );

        if let Err(e) = copy_in.send(data.as_bytes()).await {
            tracing::error!(
                "bulk_insert_channels: Failed to send data for channel {}: {:?}",
                channel.name,
                e
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Failed to send data to COPY stream: {}",
                e
            )));
        }
    }

    // Complete the COPY operation
    if let Err(e) = copy_in.finish().await {
        tracing::error!(
            "bulk_insert_channels: Failed to finish COPY operation: {:?}",
            e
        );
        return Err(AppError::from(e));
    }
    tracing::debug!("bulk_insert_channels: Completed COPY operation");

    // Commit the transaction
    if let Err(e) = transaction.commit().await {
        tracing::error!(
            "bulk_insert_channels: Failed to commit transaction: {:?}",
            e
        );
        return Err(AppError::from(e));
    }

    let duration = start_time.elapsed();
    tracing::info!(
        "bulk_insert_channels: Successfully inserted {} channels in {:?}",
        channels.len(),
        duration
    );
    Ok(())
}
