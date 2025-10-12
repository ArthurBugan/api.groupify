//! V1 API route definitions
//! 
//! This module contains all the route definitions for API version 1,
//! maintaining backward compatibility with existing clients.

use axum::{
    middleware, routing::{delete, get, patch, post, put}, Router
};

use crate::{api::common::middleware::auth_middleware, InnerState};
use crate::api::v1::channel::{all_channels, all_channels_by_group, create_channel, update_channels_in_group, fetch_youtube_channels, save_youtube_channels};
use crate::api::v1::group::{all_groups, create_group, delete_group, update_group};
use crate::api::v1::link_shortner::{create_link, get_link_statistics, redirect, update_link};
use crate::api::v1::auth::{google_callback, check_google_session, google_login, me, disconnect_google};
use crate::api::v1::survey::{insert_survey};

use crate::api::v1::youtube::{sync_channels_from_youtube};
use crate::api::v1::discord_auth::{discord_callback, discord_login, check_discord_session, disconnect_discord};


/// Creates V1 API routes (existing routes for backward compatibility)
#[tracing::instrument(name = "create_v1_routes", skip(state))]
pub fn create_v1_routes(state: InnerState) -> Router<InnerState> {
    tracing::info!("Setting up V1 API routes");

    Router::new()
        // Link shortener routes
        .route("/create", post(create_link))
        .route("/{id}/statistics", get(get_link_statistics))
        .route("/{id}", patch(update_link).get(redirect))

        // Survey routes
        .route("/add-survey", post(insert_survey))

        // Channel management routes
        .route("/channels", get(all_channels))
        .route("/channel", post(create_channel))
        .route("/channels/{group_id}", get(all_channels_by_group))
        .route("/channels/{group_id}", put(update_channels_in_group))
        
        // Group management routes
        .route("/groups", get(all_groups))
        .route("/group", post(create_group))
        .route("/group/{group_id}", put(update_group))
        .route("/group/{group_id}", delete(delete_group))

        // YouTube integration routes
        .route("/youtube-channels", post(save_youtube_channels))
        .route("/youtube-channels", get(fetch_youtube_channels))
        .route(
            "/sync-channels-from-youtube",
            post(sync_channels_from_youtube),
        )
        
        // OAuth routes
        .route("/auth/google", get(google_login))
        .route("/auth/google_callback", get(google_callback))
        .route("/check-google-session", get(check_google_session))
        .route("/auth/check-google-session", get(check_google_session))
        .route("/auth/disconnect-google", delete(disconnect_google))
        
        // New Discord OAuth routes
        .route("/auth/discord", get(discord_login))
        .route("/auth/discord_callback", get(discord_callback))
        .route("/auth/check-discord-session", get(check_discord_session))
        .route("/auth/disconnect-discord", delete(disconnect_discord))

        .route("/me", get(me))
        .layer(middleware::from_fn(auth_middleware))
        .with_state(state)
}