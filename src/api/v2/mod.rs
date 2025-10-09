//! API Version 2 endpoints
//! 
//! This module contains enhanced V2 API endpoints with
//! improved functionality and breaking changes from V1.

pub mod auth;
pub mod channels;
pub mod groups;
pub mod subscriptions;
pub mod users;
pub mod dashboard;
pub mod animes;

use axum::Router;
use axum::routing::{delete, get, patch, post, put};
use tower_cookies::CookieManagerLayer;

use crate::InnerState;

/// Creates the V2 API router
#[tracing::instrument(name = "create_v2_router", skip(state))]
pub fn create_v2_router(state: InnerState) -> Router<InnerState> {
    tracing::info!("Creating V2 API router");
    
    Router::new()
        .route("/api/v2/groups", get(groups::all_groups))
        .route("/api/v2/groups", post(groups::create_group))
        .route("/api/v2/groups/{group_id}", get(groups::get_group_by_id))
        .route("/api/v2/groups/{group_id}", put(groups::update_group))
        .route("/api/v2/groups/{group_id}", delete(groups::delete_group))
        .route("/api/v2/groups/{group_id}/display-order", put(groups::update_display_order))

        .route("/api/v2/channels", get(channels::all_channels))
        .route("/api/v2/channels/{channel_id}", get(channels::get_channel_by_id))
        .route("/api/v2/channels/{channel_id}", patch(channels::patch_channel))
        .route("/api/v2/channels/{channel_id}", delete(channels::delete_channel))
        .route("/api/v2/channels/{channel_id}/batch", patch(channels::patch_channels_batch))

        .route("/api/v2/dashboard/total", get(dashboard::get_dashboard_total))

        .route("/api/v2/animes", get(animes::all_animes))

        .layer(CookieManagerLayer::new())
        .with_state(state)
}