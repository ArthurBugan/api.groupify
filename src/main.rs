mod authentication;
mod db;
mod email;
mod errors;

mod api;
mod system;

use crate::api::v1::routes::create_v1_routes;
use crate::api::v2::create_v2_router;
use crate::email::EmailClient;

use crate::db::init_db;

use crate::system::create_system_router;
use crate::api::common::tracing::{make_custom_span, on_custom_request, on_custom_response, on_custom_failure};

use anyhow::Result;
use axum::extract::FromRef;
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use axum::{Extension, Router};
use bytes::BytesMut;
use hyper::Method;
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

use crate::api::v1::oauth::{build_google_oauth_client, build_discord_oauth_client, OAuthClients};

#[derive(Clone, Debug)]
struct InnerState {
    pub db: PgPool,
    pub email_client: EmailClient,
    pub oauth_clients: OAuthClients,
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
    let session_store = MemoryStore::default();
    let session = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(Duration::days(120)));

    let oauth_id = std::env::var("GOOGLE_OAUTH_CLIENT_ID")?;
    let oauth_secret = std::env::var("GOOGLE_OAUTH_CLIENT_SECRET")?;

    let google_oauth_client = build_google_oauth_client(oauth_id.clone(), oauth_secret);
    let discord_oauth_client = build_discord_oauth_client(
        std::env::var("DISCORD_OAUTH_CLIENT_ID")?,
        std::env::var("DISCORD_OAUTH_CLIENT_SECRET")?,
    );

    let app_state = InnerState {
        db,
        email_client,
        oauth_clients: OAuthClients {
            google: google_oauth_client,
            discord: discord_oauth_client,
        },
    };

   let origins = [
        "chrome-extension://dmdgaegnpjnnkcbdngfgkhlehlccbija".parse().unwrap(),
        "chrome-extension://jbifilepodgklfkblilibnbbbncjphde".parse().unwrap(),
        "https://localhost".parse().unwrap(),
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
            Method::PATCH,
        ])
        .allow_headers([CONTENT_TYPE])
        .allow_origin(origins)
        .allow_credentials(true);

    // Build the main application with versioned routes
    tracing::info!("Building application router with versioned routes");

    let app = Router::new()
        .merge(create_system_router(app_state.clone()).with_state(app_state.clone()))
        .merge(create_v1_routes(app_state.clone()).with_state(app_state.clone()))
        .merge(create_v2_router(app_state.clone()).with_state(app_state.clone()))
        // Apply middleware layers
        .layer(cors)
        .layer(CookieManagerLayer::new())
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
