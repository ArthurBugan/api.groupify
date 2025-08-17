mod auth;
mod authentication;
mod db;
mod email;
mod errors;
mod routes;

use crate::email::EmailClient;

use crate::db::init_db;
use crate::routes::{
    all_channels, all_channels_by_group, all_groups, confirm, create_channel, create_group,
    create_link, delete_account, delete_group, empty_debug, fetch_youtube_channels, get_language,
    get_link_statistics, handle_get, handle_post, health_check, insert_survey, login_user,
    logout_user, redirect, root, save_youtube_channels, subscribe, sync_channels_from_youtube,
    update_channels_in_group, update_group, update_link,
};

use crate::auth::{build_oauth_client, check_google_session, google_callback};

use crate::authentication::{change_password, forget_password};

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
use tracing::error;
use std::error::Error;
use time::Duration;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

use opentelemetry::global;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{WithExportConfig, OTEL_EXPORTER_OTLP_ENDPOINT};
use opentelemetry_otlp::{LogExporter, MetricExporter, Protocol, SpanExporter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::{
    logs::SdkLoggerProvider, metrics::SdkMeterProvider, trace::SdkTracerProvider,
};
use axum_tracing_opentelemetry::middleware::OtelInResponseLayer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use std::sync::{Arc, OnceLock, RwLock};

struct AppState {
    inner: InnerState,
}

#[derive(Clone)]
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

fn get_resource() -> Resource {
        static RESOURCE: OnceLock<Resource> = OnceLock::new();
        RESOURCE
            .get_or_init(|| {
                Resource::builder()
                    .with_service_name("groupify")
                    .build()
            })
            .clone()
    }

    fn init_logs() -> SdkLoggerProvider {
        let exporter = LogExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpJson)
            .with_endpoint("https://otlp.nr-data.net/v1/logs")
            .build()
            .expect("Failed to create log exporter");

        SdkLoggerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(get_resource())
            .build()
    }

    fn init_traces() -> SdkTracerProvider {
        let exporter = SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpJson) //can be changed to `Protocol::HttpJson` to export in JSON format
            .with_endpoint("https://otlp.nr-data.net/v1/traces")
            .build()
            .expect("Failed to create trace exporter");

        SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(get_resource())
            .build()
    }

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();
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
        "http://localhost:3000".parse().unwrap(),
        "https://localhost:3000".parse().unwrap(),
        "https://groupify.dev".parse().unwrap(),
        "https://www.youtube.com".parse().unwrap(),
        "https://youtube.com".parse().unwrap(),
    ];

    let logger_provider = init_logs();
    let otel_layer = OpenTelemetryTracingBridge::new(&logger_provider);
    let filter_otel = EnvFilter::new("info")
        .add_directive("hyper=off".parse().unwrap())
        .add_directive("tonic=off".parse().unwrap())
        .add_directive("h2=off".parse().unwrap())
        .add_directive("reqwest=off".parse().unwrap());
    let otel_layer = otel_layer.with_filter(filter_otel);

    let filter_fmt = EnvFilter::new("info").add_directive("opentelemetry=debug".parse().unwrap());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_thread_names(true)
        .with_filter(filter_fmt);

    tracing_subscriber::registry()
        .with(otel_layer)
        .with(fmt_layer)
        .init();

    let tracer_provider = init_traces();
    global::set_tracer_provider(tracer_provider.clone());

     let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint("https://otlp.nr-data.net/v1/metrics")
        .build()?;

    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        .build();
    global::set_meter_provider(meter_provider.clone());

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
        .route("/logout", post(logout_user))
        .route("/forget-password", post(forget_password))
        .route(
            "/forget-password/confirm/:forget_password_token",
            post(change_password),
        )
        .route("/youtube-channels", post(save_youtube_channels))
        .route("/youtube-channels", get(fetch_youtube_channels))
        .route("/account", delete(delete_account))
        .route("/debug", get(handle_get))
        .route("/language", get(get_language))
        .route("/debug", post(handle_post))
        .route("/empty-debug", post(empty_debug))
        .route("/auth/google_callback", get(google_callback))
        .route(
            "/sync-channels-from-youtube",
            post(sync_channels_from_youtube),
        )
        .route("/check-google-session", get(check_google_session))
        .route("/add-survey", post(insert_survey))
        .layer(cors)
        .layer(CookieManagerLayer::new())
        .layer(prometheus_layer)
        .layer(session)
        .layer(OtelInResponseLayer)
        .layer(Extension(shared_state))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001")
        .await
        .expect("Could not initialize TcpListener");

    tracing::info!(
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
