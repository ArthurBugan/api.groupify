//! V1 API route definitions
//! 
//! This module contains all the route definitions for API version 1,
//! maintaining backward compatibility with existing clients.

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};

use crate::InnerState;
use crate::api::v1::channel::{all_channels, all_channels_by_group, create_channel, update_channels_in_group, fetch_youtube_channels, save_youtube_channels};
use crate::api::v1::group::{all_groups, create_group, delete_group, update_group};
use crate::api::v1::link_shortner::{create_link, get_link_statistics, redirect, update_link};
use crate::api::v1::auth::{google_callback, check_google_session, google_login, me};

use crate::api::v1::subscriptions::{subscribe};
use crate::api::v1::subscription_confirm::{confirm};
use crate::api::v1::user::{delete_account, get_language};
use crate::api::v1::login::{login_user, logout_user};
use crate::api::v1::youtube::{sync_channels_from_youtube};
use crate::api::v1::survey::{insert_survey};
use crate::authentication::{change_password, forget_password};
use crate::api::v1::discord_auth::{discord_callback, discord_login, check_discord_session};


/// Creates V1 API routes (existing routes for backward compatibility)
#[tracing::instrument(name = "create_v1_routes")]
pub fn create_v1_routes(state: InnerState) -> Router<InnerState> {
    tracing::info!("Setting up V1 API routes");

    Router::new()
        // Link shortener routes
        .route("/create", post(create_link))
        .route("/:id/statistics", get(get_link_statistics))
        .route("/:id", patch(update_link).get(redirect))
        
        // Channel management routes
        .route("/channels", get(all_channels))
        .route("/channel", post(create_channel))
        .route("/channels/:group_id", get(all_channels_by_group))
        .route("/channels/:group_id", put(update_channels_in_group))
        
        // Group management routes
        .route("/groups", get(all_groups))
        .route("/group", post(create_group))
        .route("/group/:group_id", put(update_group))
        .route("/group/:group_id", delete(delete_group))
        
        // User management routes
        .route("/registration", post(subscribe))
        .route("/subscription/confirm/:subscription_token", post(confirm))
        .route("/account", delete(delete_account))
        
        // Authentication routes
        .route("/authorize", post(login_user))
        .route("/logout", post(logout_user))
        .route("/forget-password", post(forget_password))
        .route(
            "/forget-password/confirm/:forget_password_token",
            post(change_password),
        )
        
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
        
        // New Discord OAuth routes
        .route("/auth/discord", get(discord_login))
        .route("/auth/discord_callback", get(discord_callback))
        .route("/auth/discord_session", get(check_discord_session))
        
        // Survey routes
        .route("/add-survey", post(insert_survey))
        
        // Utility routes
        .route("/language", get(get_language))
        .route("/me", get(me))
        .with_state(state)
}