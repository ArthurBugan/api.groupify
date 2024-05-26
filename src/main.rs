mod auth;
mod authentication;
mod db;
mod email;
mod routes;
mod utils;

use crate::email::EmailClient;
use std::collections::HashMap;

use crate::db::init_db;

use crate::routes::{all_channels, all_groups, confirm, create_channel, create_group, create_link, get_link_statistics, health_check, login_user, redirect, root, subscribe, update_link, Counter, all_channels_by_group, update_group, update_channels_in_group, save_youtube_channels, fetch_youtube_channels, delete_group, delete_account};

use serde::{Deserialize, Serialize};

use crate::authentication::{change_password, forget_password};

use axum::extract::FromRef;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Router};
use axum_prometheus::PrometheusMetricLayer;
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderValue;
use hyper::Method;
use time::Duration;
use tower_http::trace::TraceLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tracing::info;

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

    let origins = [
        "https://localhost".parse().unwrap(),
        "http://localhost:3000".parse().unwrap(),
        "https://localhost:3000".parse().unwrap(),
        "https://groupify.dev".parse().unwrap(),
        "https://www.youtube.com".parse().unwrap(),
        "https://youtube.com".parse().unwrap(),
    ];

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS, Method::PUT, Method::DELETE])
        .allow_headers([CONTENT_TYPE])
        .allow_origin(origins)
        .allow_credentials(true);

    let app = Router::new()
        .route("/create", post(create_link))
        .route("/:id/statistics", get(get_link_statistics))
        .route("/:id", patch(update_link).get(redirect))
        .route("/metrics", get(|| async move { metric_handle.render() }))
        .route("/health", get(health_check))

        .route("/channels", get(all_channels))
        .route("/channel", post(create_channel))
        .route("/channels/:group_id", get(all_channels_by_group))
        .route("/channels/:group_id", put(update_channels_in_group))

        .route("/groups", get(all_groups))
        .route("/group", post(create_group))
        .route("/group/:group_id", put(update_group))
        .route("/group/:group_id", delete(delete_group))

        .route("/registration", post(subscribe))
        .route("/subscription/confirm/:subscription_token", post(confirm))

        .route("/", get(root))
        .route("/authorize", post(login_user))
        .route("/forget-password", post(forget_password))
        .route("/forget-password/confirm/:forget_password_token", post(change_password))

        .route("/youtube-channels", post(save_youtube_channels))
        .route("/youtube-channels", get(fetch_youtube_channels))

        .route("/account", delete(delete_account))

        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(CookieManagerLayer::new())
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
