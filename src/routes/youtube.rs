use axum::{extract::State, Json};
use chrono::{DateTime, Local, Utc};
use hyper::StatusCode;
use reqwest::Client;
use serde_json::{json, Value};
use tower_cookies::Cookies;

use crate::{
    auth::renew_token,
    routes::{get_email_from_token, User},
    InnerState,
};

use serde::{Deserialize, Serialize};
use sqlx::Row;

use super::{save_youtube_channels, YoutubeChannel};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteYoutubeChannel {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub page_info: PageInfo,
    pub items: Vec<Item>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Snippet,
    pub content_details: ContentDetails,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentDetails {
    pub total_item_count: i64,
    pub new_item_count: i64,
    pub activity_type: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snippet {
    pub published_at: String,
    pub title: String,
    pub description: String,
    pub resource_id: ResourceId,
    pub channel_id: String,
    pub thumbnails: Thumbnails,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceId {
    pub kind: String,
    pub channel_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Thumbnails {
    #[serde(rename = "default")]
    pub default: Default,
    pub medium: Default,
    pub high: Default,
}

#[derive(Serialize, Deserialize)]
pub struct Default {
    pub url: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub total_results: i64,
    pub results_per_page: i64,
}

pub async fn sync_channels_from_youtube(
    cookies: Cookies,
    State(inner): State<InnerState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let InnerState {
        db,
        oauth_client, // Borrow oauth_client here
        ..
    } = &inner; // Borrow inner to avoid moving

    // Extract the auth token from the cookies
    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    // Get the email from the token (assuming get_email_from_token is implemented)
    let email = get_email_from_token(auth_token).await;

    // Query to get the session id using the email
    let bearer = sqlx::query(
        "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)",
    )
    .bind(email.clone())
    .fetch_one(&db.clone())
    .await
    .map_err(|err| {
        tracing::error!("Database query error: {:?}", err);
        (StatusCode::NOT_FOUND, "Database error".to_string())
    })?;

    let expires_at: DateTime<Utc> = bearer.get("expires_at");

    // Renew token if it has expired
    if expires_at < Local::now() {
        let _ = renew_token(db.clone(), oauth_client.clone(), email.clone()).await;
    }

    // Query to get the session id again after potentially renewing the token
    let bearer = sqlx::query(
        "SELECT * FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 LIMIT 1)",
    )
    .bind(email)
    .fetch_one(db)
    .await
    .map_err(|err| {
        tracing::error!("Database query error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Database error".to_string(),
        )
    })?;

    let session_id: String = bearer.get("session_id");

    let req = Client::new();
    let mut all_items = Vec::new();
    let mut next_page_token = None;

    // Loop through paginated results
    loop {
        let mut url = format!(
          "https://www.googleapis.com/youtube/v3/subscriptions?mine=true&maxResults=50&part=snippet,contentDetails"
      );

        // If there's a next_page_token, add it to the URL
        if let Some(token) = &next_page_token {
            url.push_str(&format!("&pageToken={}", token));
        }

        // Send the request to YouTube API
        let channels_req = req
            .get(&url)
            .bearer_auth(&session_id) // Use the session ID as the bearer token
            .send()
            .await
            .map_err(|err| {
                tracing::error!("Request error: {:?}", err);
                (
                    StatusCode::BAD_GATEWAY,
                    "Failed to fetch YouTube data".to_string(),
                )
            })?;

        // Check the response status
        if !channels_req.status().is_success() {
            tracing::error!("YouTube API error: {:?}", channels_req.status());
            return Err((
                StatusCode::BAD_REQUEST,
                "YouTube API request failed".to_string(),
            ));
        }

        // Parse the YouTube API response into a CompleteYoutubeChannel struct
        let youtube_channel: CompleteYoutubeChannel = channels_req.json().await.map_err(|err| {
            tracing::error!("Failed to parse YouTube API response: {:?}", err);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to parse response".to_string(),
            )
        })?;

        // Add the items to the results
        all_items.extend(youtube_channel.items);

        // Check if there's a next page token
        if let Some(token) = youtube_channel.next_page_token {
            next_page_token = Some(token);
        } else {
            break; // No more pages, exit the loop
        }
    }

    // Map the all_items into a new Vec<SimplifiedChannel>
    let simplified_channels: Vec<YoutubeChannel> = all_items
        .into_iter()
        .map(|item| YoutubeChannel {
            id: Some(item.id.clone()),
            name: item.snippet.title.clone(),
            thumbnail: item.snippet.thumbnails.default.url.clone(),
            channel_id: item.snippet.resource_id.channel_id.clone(),
            created_at: Some(Local::now().naive_utc()),
            updated_at: Some(Local::now().naive_utc()),
            url: format!(
                "{}{}",
                "@".to_string(),
                item.snippet.resource_id.channel_id.trim().to_string()
            ),
            new_content: item.content_details.new_item_count > 0,
        })
        .collect();

    let _ = save_youtube_channels(cookies, State(inner.clone()), Json(simplified_channels)).await?;

    // Return all collected items as JSON
    return Ok(Json(json!({ "success": "true" })));
}
