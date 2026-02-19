//! YouTube Video Sync Service
//! 
//! This module handles syncing videos from YouTube API to the local database.
//! It uses the user's Google OAuth session to make authenticated API calls.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::Client;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::api::v3::entities::videos;
use crate::errors::AppError;

/// YouTube API response for search/list videos
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YoutubeVideoListResponse {
    pub kind: String,
    pub etag: String,
    pub next_page_token: Option<String>,
    pub prev_page_token: Option<String>,
    pub page_info: PageInfo,
    pub items: Vec<YoutubeVideoItem>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    pub total_results: i32,
    pub results_per_page: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct YoutubeVideoItem {
    pub kind: String,
    pub etag: String,
    pub id: String,
    pub snippet: Option<VideoSnippet>,
    pub content_details: Option<ContentDetails>,
    pub statistics: Option<Statistics>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VideoSnippet {
    pub published_at: String,
    pub channel_id: String,
    pub title: String,
    pub description: String,
    pub thumbnails: Thumbnails,
    pub channel_title: String,
    pub tags: Option<Vec<String>>,
    pub category_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thumbnails {
    pub default: Thumbnail,
    pub medium: Thumbnail,
    pub high: Thumbnail,
    pub standard: Option<Thumbnail>,
    pub maxres: Option<Thumbnail>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Thumbnail {
    pub url: String,
    pub width: Option<i32>,
    pub height: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentDetails {
    pub duration: String,
    pub dimension: String,
    pub definition: String,
    pub caption: String,
    pub licensed_content: bool,
    pub content_rating: ContentRating,
    pub projection: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentRating {
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Statistics {
    pub view_count: Option<String>,
    pub like_count: Option<String>,
    pub favorite_count: Option<String>,
    pub comment_count: Option<String>,
}

/// Service for syncing YouTube videos
pub struct VideoSyncService {
    db: DatabaseConnection,
    http_client: Client,
}

impl VideoSyncService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            http_client: Client::new(),
        }
    }

    /// Sync videos for all channels in a group
    #[tracing::instrument(name = "Sync YouTube videos", skip(self, google_token))]
    pub async fn sync_group_videos(
        &self,
        user_id: &str,
        group_id: &str,
        google_token: &str,
        channel_ids: Vec<String>,
    ) -> Result<usize, AppError> {
        let mut total_synced = 0;

        for channel_id in channel_ids {
            info!("Syncing videos for channel: {}", channel_id);
            
            match self.sync_channel_videos(user_id, group_id, &channel_id, google_token).await {
                Ok(count) => {
                    total_synced += count;
                    info!("Synced {} videos for channel {}", count, channel_id);
                }
                Err(e) => {
                    error!("Failed to sync videos for channel {}: {:?}", channel_id, e);
                    // Continue with other channels even if one fails
                }
            }
        }

        info!(
            "Total videos synced for group {}: {}",
            group_id, total_synced
        );
        
        Ok(total_synced)
    }

    /// Fetch and store videos for a single channel
    #[tracing::instrument(name = "Sync channel videos", skip(self, google_token))]
    async fn sync_channel_videos(
        &self,
        user_id: &str,
        group_id: &str,
        channel_id: &str,
        google_token: &str,
    ) -> Result<usize, AppError> {
        // Fetch recent videos from YouTube API
        let videos_response = self
            .fetch_youtube_videos(channel_id, google_token, Some(10))
            .await?;

        let mut synced_count = 0;

        for item in videos_response.items {
            if let Some(snippet) = item.snippet {
                // Parse duration from ISO 8601 format (e.g., "PT10M30S")
                let duration_seconds = item
                    .content_details
                    .as_ref()
                    .and_then(|cd| parse_duration(&cd.duration).ok());

                // Parse view count
                let views_count = item.statistics.as_ref().and_then(|s| {
                    s.view_count
                        .as_ref()
                        .and_then(|v| v.parse::<i32>().ok())
                });

                let published_at = snippet.published_at;
                let video_url = format!("https://www.youtube.com/watch?v={}", item.id);

                // Get best available thumbnail
                let thumbnail = snippet
                    .thumbnails
                    .maxres
                    .as_ref()
                    .or(snippet.thumbnails.standard.as_ref())
                    .or(Some(&snippet.thumbnails.high))
                    .map(|t| t.url.clone());

                // Create video ID (user_id + channel_id + video_id)
                let video_db_id = format!("{}_{}_{}", user_id, channel_id, item.id);

                // Check if video already exists
                let existing = videos::Entity::find()
                    .filter(videos::Column::ExternalId.eq(&item.id))
                    .filter(videos::Column::ChannelId.eq(channel_id))
                    .one(&self.db)
                    .await
                    .map_err(|e| {
                        error!("Database error checking existing video: {:?}", e);
                        AppError::SeaORM(e)
                    })?;

                if existing.is_some() {
                    // Video already exists, update view count and other metrics
                    if let Some(existing_video) = existing {
                        let mut active: videos::ActiveModel = existing_video.into();
                        active.views_count = Set(views_count);
                        active.updated_at = Set(Some(Utc::now().naive_utc()));
                        
                        active.update(&self.db).await.map_err(|e| {
                            error!("Failed to update video: {:?}", e);
                            AppError::SeaORM(e)
                        })?;
                    }
                } else {
                    // Insert new video
                    let video_active = videos::ActiveModel {
                        id: Set(video_db_id),
                        channel_id: Set(channel_id.to_string()),
                        group_id: Set(group_id.to_string()),
                        user_id: Set(user_id.to_string()),
                        title: Set(snippet.title),
                        description: Set(Some(snippet.description)),
                        thumbnail: Set(thumbnail),
                        url: Set(Some(video_url)),
                        published_at: Set(Some(DateTime::parse_from_rfc3339(&published_at)
                            .map_err(|e| {
                                error!("Failed to parse published_at: {:?}", e);
                                AppError::BadRequest("Invalid published_at format".to_string())
                            })?
                            .with_timezone(&Utc)
                            .naive_utc())),
                        content_type: Set("youtube".to_string()),
                        external_id: Set(Some(item.id.clone())),
                        duration_seconds: Set(duration_seconds),
                        views_count: Set(views_count),
                        created_at: Set(Some(Utc::now().naive_utc())),
                        updated_at: Set(Some(Utc::now().naive_utc())),
                    };

                    video_active.insert(&self.db).await.map_err(|e| {
                        error!("Failed to insert video: {:?}", e);
                        AppError::SeaORM(e)
                    })?;

                    synced_count += 1;
                }
            }
        }

        Ok(synced_count)
    }

    /// Fetch videos from YouTube API for a channel
    #[tracing::instrument(name = "Fetch YouTube videos", skip(self, token))]
    async fn fetch_youtube_videos(
        &self,
        channel_id: &str,
        token: &str,
        max_results: Option<i32>,
    ) -> Result<YoutubeVideoListResponse, AppError> {
        let max_results = max_results.unwrap_or(10).min(50);
        
        // First, get video IDs from search API
        let search_url = format!(
            "https://www.googleapis.com/youtube/v3/search?channelId={}&part=snippet&order=date&maxResults={}&type=video",
            channel_id,
            max_results
        );

        info!("Fetching video list from YouTube API for channel: {}", channel_id);

        let search_response = self
            .http_client
            .get(&search_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| {
                error!("HTTP error fetching video list: {:?}", e);
                AppError::ExternalService(anyhow::Error::new(e))
            })?;

        if !search_response.status().is_success() {
            let error_text = search_response.text().await.unwrap_or_default();
            error!("YouTube API error: {}", error_text);
            return Err(AppError::ExternalService(anyhow::anyhow!(
                "YouTube API error: {}",
                error_text
            )));
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SearchItem {
            id: SearchId,
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SearchId {
            video_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct SearchResponse {
            items: Vec<SearchItem>,
        }

        let search_data: SearchResponse = search_response.json().await.map_err(|e| {
            error!("Failed to parse search response: {:?}", e);
            AppError::ExternalService(anyhow::Error::new(e))
        })?;

        let video_ids: Vec<String> = search_data
            .items
            .into_iter()
            .map(|item| item.id.video_id)
            .collect();

        if video_ids.is_empty() {
            return Ok(YoutubeVideoListResponse {
                kind: "youtube#videoListResponse".to_string(),
                etag: "".to_string(),
                next_page_token: None,
                prev_page_token: None,
                page_info: PageInfo {
                    total_results: 0,
                    results_per_page: 0,
                },
                items: vec![],
            });
        }

        // Now fetch detailed video information
        let ids_param = video_ids.join(",");
        let videos_url = format!(
            "https://www.googleapis.com/youtube/v3/videos?id={}&part=snippet,contentDetails,statistics&maxResults={}",
            ids_param,
            max_results
        );

        info!("Fetching video details for {} videos", video_ids.len());

        let videos_response = self
            .http_client
            .get(&videos_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| {
                error!("HTTP error fetching video details: {:?}", e);
                AppError::ExternalService(anyhow::Error::new(e))
            })?;

        if !videos_response.status().is_success() {
            let error_text = videos_response.text().await.unwrap_or_default();
            error!("YouTube API error: {}", error_text);
            return Err(AppError::ExternalService(anyhow::anyhow!(
                "YouTube API error: {}",
                error_text
            )));
        }

        let videos_data: YoutubeVideoListResponse = videos_response.json().await.map_err(|e| {
            error!("Failed to parse videos response: {:?}", e);
            AppError::ExternalService(anyhow::Error::new(e))
        })?;

        Ok(videos_data)
    }
}

/// Parse ISO 8601 duration format (e.g., "PT10M30S") to seconds
fn parse_duration(duration_str: &str) -> Result<i32, Box<dyn std::error::Error>> {
    // Remove PT prefix
    let duration_str = duration_str.trim_start_matches("PT");
    
    let mut total_seconds = 0i32;
    let mut current_num = String::new();
    
    for c in duration_str.chars() {
        if c.is_ascii_digit() {
            current_num.push(c);
        } else {
            let num: i32 = current_num.parse()?;
            match c {
                'H' => total_seconds += num * 3600,
                'M' => total_seconds += num * 60,
                'S' => total_seconds += num,
                _ => {}
            }
            current_num.clear();
        }
    }
    
    Ok(total_seconds)
}
