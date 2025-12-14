//! System-level routes and utilities

pub mod health_check;
pub mod metrics;

use axum::{
    routing::{delete, get, post},
    Router,
};


use crate::api::v1::auth::{google_callback, google_login};
use crate::api::v1::discord_auth::{discord_callback, discord_login};

use crate::api::v1::login::{login_user, logout_user};
use crate::api::v1::subscription_confirm::confirm;
use crate::api::v1::subscriptions::subscribe;
use crate::api::v1::user::{delete_account, get_language};
use crate::authentication::{change_password, forget_password};
use crate::InnerState;

/// Creates system routes
#[tracing::instrument(name = "create_system_router")]
pub fn create_system_router(state: InnerState) -> Router<InnerState> {
    tracing::info!("Creating system/unauthorized router");

    Router::new()
        .route("/health", get(health_check::health_check))
        // User management routes
        .route("/registration", post(subscribe))
        .route("/subscription/confirm/{subscription_token}", post(confirm))
        .route("/account", delete(delete_account))
        // Authentication routes
        .route("/authorize", post(login_user))
        .route("/logout", post(logout_user))
        .route("/forget-password", post(forget_password))
        .route(
            "/forget-password/confirm/{forget_password_token}",
            post(change_password),
        )
        .route("/language", get(get_language))

        .route("/auth/google", get(google_login))
        .route("/auth/google_callback", get(google_callback))

        .route("/auth/discord", get(discord_login))
        .route("/auth/discord_callback", get(discord_callback))

        .with_state(state)
}
