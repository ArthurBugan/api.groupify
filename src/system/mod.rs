//! System-level routes and utilities

pub mod debug;
pub mod health_check;
pub mod metrics;

use axum::{routing::get, Router};
use sqlx::PgPool;

/// Creates system routes
#[tracing::instrument(name = "create_system_router")]
pub fn create_system_router(pool: PgPool) -> Router {
    tracing::info!("Creating system router");
    
    Router::new()
        .route("/health", get(health_check::health_check))
        .route("/debug", get(debug::handle_get))
        .with_state(pool)
}