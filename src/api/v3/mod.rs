pub mod entities;
pub mod animes;
pub mod channels;
pub mod users;

use axum::{middleware, Router};
use axum::routing::{delete, get, patch, post, put};
use tower_cookies::CookieManagerLayer;

use crate::InnerState;
use crate::api::common::middleware::auth_middleware;


/// Creates the V2 API router
#[tracing::instrument(name = "create_v3_router", skip(state))]
pub fn create_v3_router(state: InnerState) -> Router<InnerState> {
    tracing::info!("Creating V3 API router");
        
    Router::new()
        .route("/api/v3/health", get(|| async { "v3 health check ok!" }))
        .route("/api/v3/animes", get(animes::all_animes_v3))
        .route("/api/v3/channels/{channel_id}/batch", patch(channels::patch_channels_batch))
        .route("/api/v3/me", get(users::me))
        .layer(CookieManagerLayer::new())
        .layer(middleware::from_fn(auth_middleware))
        .with_state(state)
}