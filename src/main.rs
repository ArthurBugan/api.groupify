mod auth;
mod authentication;
mod db;
mod email;
mod errors;

mod api;
mod system;

use crate::email::EmailClient;

use crate::db::init_db;
use crate::api::v1::{
    all_channels, all_channels_by_group, all_groups, confirm, create_channel, create_group,
    create_link, delete_account, delete_group, fetch_youtube_channels, get_language,
    get_link_statistics, insert_survey, login_user, logout_user, redirect, save_youtube_channels,
    subscribe, sync_channels_from_youtube, update_channels_in_group, update_group, update_link,
};

use crate::auth::{build_oauth_client, check_google_session, google_callback};

use crate::authentication::{change_password, forget_password};
use crate::system::create_system_router;

use anyhow::Result;
use axum::extract::FromRef;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Router};
use axum_prometheus::PrometheusMetricLayer;
use bytes::BytesMut;
use hyper::Method;
use oauth2::basic::BasicClient;
use sqlx::PgPool;
use std::error::Error;
use time::Duration;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use std::sync::{Arc, RwLock};
use tower_http::trace::TraceLayer;
use tracing::Level;

use axum_otel::{AxumOtelOnFailure, AxumOtelOnResponse, AxumOtelSpanCreator};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tracing_otel_extra::{
    get_resource, init_env_filter, init_meter_provider, init_tracer_provider,
    init_tracing_subscriber,
};

use opentelemetry::KeyValue;

struct AppState {
    inner: InnerState,
}

#[derive(Clone, Debug)]
struct InnerState {
    pub db: PgPool,
    pub email_client: EmailClient,
    pub oauth_client: BasicClient,
}

#[derive(Default)]
pub struct HeaderAppState {
    pub headers: HeaderMap,
    pub body: BytesMut,
}

impl FromRef<AppState> for InnerState {
    fn from_ref(app_state: &AppState) -> InnerState {
        app_state.inner.clone()
    }
}

pub type SharedState = Arc<RwLock<HeaderAppState>>;

fn make_custom_span<B>(request: &axum::http::Request<B>) -> tracing::Span {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    tracing::info_span!(
        "http_request",
        method = %request.method(),
        uri = %request.uri().path(),
        query = ?request.uri().query(),
        version = ?request.version(),
        request_id = request_id,
        user_agent = ?request.headers().get("user-agent"),
        content_type = ?request.headers().get("content-type"),
        content_length = ?request.headers().get("content-length"),
    )
}

fn on_custom_request<B>(request: &axum::http::Request<B>, _span: &tracing::Span) {
    let headers: std::collections::HashMap<String, String> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            // Filter sensitive headers
            if name.as_str().to_lowercase().contains("authorization")
                || name.as_str().to_lowercase().contains("cookie")
                || name.as_str().to_lowercase().contains("token")
            {
                Some((name.to_string(), "[REDACTED]".to_string()))
            } else {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_string()))
            }
        })
        .collect();

    tracing::info!(
        method = %request.method(),
        uri = %request.uri(),
        headers = ?headers,
        "Incoming HTTP request"
    );
}

fn on_custom_response<B>(
    response: &axum::http::Response<B>,
    latency: std::time::Duration,
    _span: &tracing::Span,
) {
    let status = response.status();
    let latency_ms = latency.as_millis();

    let log_level = match status.as_u16() {
        200..=299 => tracing::Level::INFO,
        300..=399 => tracing::Level::INFO,
        400..=499 => tracing::Level::WARN,
        500..=599 => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    let headers: std::collections::HashMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();

    match log_level {
        tracing::Level::INFO => tracing::info!(
            status = %status,
            latency_ms = latency_ms,
            headers = ?headers,
            "HTTP request completed successfully"
        ),
        tracing::Level::WARN => tracing::warn!(
            status = %status,
            latency_ms = latency_ms,
            headers = ?headers,
            "HTTP request completed with client error"
        ),
        tracing::Level::ERROR => tracing::error!(
            status = %status,
            latency_ms = latency_ms,
            headers = ?headers,
            "HTTP request completed with server error"
        ),
        _ => {}
    }
}

fn on_custom_failure(
    error: tower_http::classify::ServerErrorsFailureClass,
    latency: std::time::Duration,
    _span: &tracing::Span,
) {
    tracing::error!(
        error = ?error,
        latency_ms = latency.as_millis(),
        error_type = match error {
            tower_http::classify::ServerErrorsFailureClass::StatusCode(code) => {
                format!("HTTP {}", code.as_u16())
            }
            tower_http::classify::ServerErrorsFailureClass::Error(_) => {
                "Internal Error".to_string()
            }
        },
        "HTTP request failed"
    );
}

/// Creates V1 API routes (existing routes for backward compatibility)
fn create_v1_routes() -> Router<InnerState> {
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
        .route("/auth/google_callback", get(google_callback))
        .route("/check-google-session", get(check_google_session))
        // Survey routes
        .route("/add-survey", post(insert_survey))
        // Utility routes
        .route("/language", get(get_language))
}

/// Creates V2 API routes (new routes for future development)
fn create_v2_routes() -> Router<InnerState> {
    tracing::info!("Setting up V2 API routes");

    Router::new()
        // TODO: Add V2 routes here as they are developed
        // Example structure for future V2 routes:
        // RESTful resource-based routes
        // .route("/channels", get(v2::channels::list).post(v2::channels::create))
        // .route("/channels/:id", get(v2::channels::get).put(v2::channels::update).delete(v2::channels::delete))
        // .route("/groups", get(v2::groups::list).post(v2::groups::create))
        // .route("/groups/:id", get(v2::groups::get).put(v2::groups::update).delete(v2::groups::delete))
        // .route("/groups/:id/channels", get(v2::groups::list_channels))
        // .route("/users", get(v2::users::list).post(v2::users::create))
        // .route("/users/:id", get(v2::users::get).put(v2::users::update).delete(v2::users::delete))
        // .route("/auth/login", post(v2::auth::login))
        // .route("/auth/logout", post(v2::auth::logout))
        // .route("/auth/refresh", post(v2::auth::refresh))
        // Placeholder route for V2 API info
        .route("/", get(|| async { "API V2 - Coming Soon" }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().ok();
    let service_name = "api-groupify";
    let resource = get_resource(service_name, &[KeyValue::new("environment", "production")]);

    let tracer_provider = init_tracer_provider(&resource, 1.0)?;
    let meter_provider = init_meter_provider(&resource, 30)?;
    let env_filter = init_env_filter(&Level::DEBUG);

    let _guard = init_tracing_subscriber(
        service_name,
        env_filter,
        vec![Box::new(tracing_subscriber::fmt::layer())],
        tracer_provider,
        meter_provider,
    )?;

    tracing::info!("Starting Groupify API server");

    let shared_state = Arc::new(RwLock::new(HeaderAppState::default()));

    let email_client = EmailClient::new(
        std::env::var("EMAIL_BASE_URL")?,
        std::env::var("EMAIL_TOKEN")?,
    );

    let db = init_db().await?;

    let (prometheus_layer, metric_handle) = PrometheusMetricLayer::pair();

    let session_store = MemoryStore::default();
    let session = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(120)));

    let oauth_id = std::env::var("GOOGLE_OAUTH_CLIENT_ID")?;
    let oauth_secret = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")?;

    let oauth_client = build_oauth_client(oauth_id.clone(), oauth_secret);

    let app_state = InnerState {
        db,
        email_client,
        oauth_client,
    };

    let origins = [
        "https://localhost".parse().unwrap(),
        "https://localhost/".parse().unwrap(),
        "http://localhost".parse().unwrap(),
        "http://localhost:3000".parse().unwrap(),
        "https://localhost:3000".parse().unwrap(),
        "https://groupify.dev".parse().unwrap(),
        "https://coolify.groupify.dev".parse().unwrap(),
        "https://www.youtube.com".parse().unwrap(),
        "https://youtube.com".parse().unwrap(),
    ];

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ])
        .allow_headers([CONTENT_TYPE])
        .allow_origin(origins)
        .allow_credentials(true);

    // Build the main application with versioned routes
    tracing::info!("Building application router with versioned routes");

    let app = Router::new()
        // System routes (non-versioned)
        .merge(create_system_router(app_state.db.clone()))
        .nest("/", create_v1_routes().with_state(app_state.clone()))
        // V2 API routes (future routes)
        .nest("/api/v2", create_v2_routes().with_state(app_state.clone()))
        // Legacy routes (for backward compatibility - can be deprecated later)
        // These maintain the old route structure for existing clients
        // Apply middleware layers
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .layer(prometheus_layer)
        .layer(session)
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(make_custom_span)
                        .on_request(on_custom_request)
                        .on_response(on_custom_response)
                        .on_failure(on_custom_failure),
                )
                .layer(PropagateRequestIdLayer::x_request_id()),
        )
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(AxumOtelSpanCreator::new().level(Level::DEBUG))
                        .on_response(AxumOtelOnResponse::new().level(Level::DEBUG))
                        .on_failure(AxumOtelOnFailure::new().level(Level::ERROR)),
                )
                .layer(PropagateRequestIdLayer::x_request_id()),
        )
        .layer(Extension(shared_state));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("Could not initialize TcpListener");

    tracing::info!(
        "Server listening on {} with versioned API routes",
        listener
            .local_addr()
            .expect("Could not convert listener address to local address")
    );

    tracing::info!("Available API versions:");
    tracing::info!("  - Legacy routes: / (for backward compatibility)");
    tracing::info!("  - V2 API: /api/v2/* (coming soon)");
    tracing::info!("  - System: /health, /metrics");

    axum::serve(listener, app)
        .await
        .expect("Could not successfully connect");

    Ok(())
}
