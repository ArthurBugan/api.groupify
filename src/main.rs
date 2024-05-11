mod auth;
mod authentication;
mod db;
mod email;
mod routes;
mod utils;

use crate::email::EmailClient;
use std::collections::HashMap;

use crate::db::init_db;

use crate::routes::{
    all_channels, all_groups, confirm, create_channel, create_group, create_link,
    get_link_statistics, health_check, login_user, redirect, root, subscribe, update_link, Counter,
};

use serde::{Deserialize, Serialize};

use crate::authentication::{change_password, forget_password};

use axum::extract::FromRef;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post, put};
use axum::{Extension, Router};
use axum_prometheus::PrometheusMetricLayer;
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
use time::Duration;
use tower_http::trace::TraceLayer;
use tower_http::cors::CorsLayer;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

struct AppState {
    inner: InnerState,
}

const COUNTER_KEY: &str = "counter";

#[derive(Clone)]
struct InnerState {
    pub db: PgPool,
    pub email_client: EmailClient,
}

async fn handler(session: Session) -> impl IntoResponse {
    let counter: Counter = session.get(COUNTER_KEY).await.unwrap().unwrap_or_default();
    session.insert(COUNTER_KEY, counter.0 + 1).await.unwrap();
    format!("Current count: {}", counter.0)
}

impl FromRef<AppState> for InnerState {
    fn from_ref(app_state: &AppState) -> InnerState {
        app_state.inner.clone()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "link_shortener=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let sender_email = std::env::var("EMAIL_SENDER")?;

    let email_client = EmailClient::new(
        std::env::var("EMAIL_BASE_URL")?,
        sender_email,
        std::env::var("EMAIL_TOKEN")?,
    );

    let db = init_db().await?;

    let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

    let session_store = MemoryStore::default();
    let session = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(120)));

    let app_state = InnerState { db, email_client };

    let app = Router::new()
        .route("/create", post(create_link))
        .route("/:id/statistics", get(get_link_statistics))
        .route("/:id", patch(update_link).get(redirect))
        .route("/metrics", get(|| async move { metric_handle.render() }))
        .route("/health", get(health_check))

        .route("/groups", get(all_groups))
        .route("/channels/:group_id", get(all_channels))

        .route("/group", post(create_group))
        .route("/channel", post(create_channel))

        .route("/registration", post(subscribe))
        .route("/subscription/confirm/:subscription_token", post(confirm))

        .route("/", get(root))
        .route("/authorize", post(login_user    ))
        .route("/forget-password", post(forget_password))
        .route("/forget-password/confirm", put(change_password))

        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(prometheus_layer)
        .layer(session)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("Could not initialize TcpListener");

    tracing::debug!(
        "listening on {}",
        listener
            .local_addr()
            .expect("Could not convert listener address to local address")
    );

    axum::serve(listener, app)
        .await
        .expect("Could not successfully connect");

    Ok(())
}
