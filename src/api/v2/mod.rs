//! API Version 2 endpoints
//! 
//! This module contains enhanced V2 API endpoints with
//! improved functionality and breaking changes from V1.

pub mod auth;
pub mod channels;
pub mod groups;
pub mod subscriptions;
pub mod users;

use axum::Router;
use axum::routing::{delete, get, patch, post, put};
use tower_cookies::CookieManagerLayer;

use crate::InnerState;

/// Creates the V2 API router
#[tracing::instrument(name = "create_v2_router", skip(state))]
pub fn create_v2_router(state: InnerState) -> Router<InnerState> {
    tracing::info!("Creating V2 API router");
    
    Router::new()
        .route("/", get(|| async { "API V2 - Coming Soon" }))
        .route("/groups", get(groups::all_groups))
        .route("/groups", post(groups::create_group))
        .route("/groups/:group_id", get(groups::get_group_by_id))
        .route("/groups/:group_id", put(groups::update_group))
        .route("/groups/:group_id", delete(groups::delete_group))
        .route("/groups/:group_id/display-order", put(groups::update_display_order))

        .route("/channels", get(channels::all_channels))
        .route("/channels/:channel_id", patch(channels::patch_channel))
        .route("/channels/:channel_id/batch", patch(channels::patch_channels_batch))

        .layer(CookieManagerLayer::new())
        .with_state(state)
}