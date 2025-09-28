//! API Version 2 endpoints
//! 
//! This module contains enhanced V2 API endpoints with
//! improved functionality and breaking changes from V1.

pub mod auth;
pub mod channels;
pub mod groups;
pub mod subscriptions;
pub mod users;
pub mod youtube;

use axum::Router;

use axum::routing::get;

use crate::InnerState;

/// Creates the V2 API router
#[tracing::instrument(name = "create_v2_router")]
pub fn create_v2_router(state: InnerState) -> Router<InnerState> {
    tracing::info!("Creating V2 API router");
    
    Router::new()
        .route("/", get(|| async { "API V2 - Coming Soon" }))
        .with_state(state)
}