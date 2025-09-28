//! API module containing all versioned API endpoints
//! 
//! This module organizes API endpoints by version to support
//! backward compatibility and gradual migration.

pub mod common;
pub mod v1;
pub mod v2;

use axum::Router;
use sqlx::PgPool;

/// Creates the main API router with all versions
#[tracing::instrument(name = "create_api_router")]
pub fn create_api_router(pool: PgPool) -> Router {
    tracing::info!("Creating API router with versioned endpoints");
    
    Router::new()
        .nest("/v2", v2::create_v2_router(pool))
}