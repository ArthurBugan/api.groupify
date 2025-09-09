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

use axum::body::Body;
use axum::extract::{FromRef, Request};
use axum::http::header::CONTENT_TYPE;
use axum::http::HeaderMap;
use axum::routing::{delete, get, patch, post, put};
use axum::{Extension, Router};
use axum_prometheus::PrometheusMetricLayer;
use bytes::BytesMut;
use hyper::Method;
use oauth2::basic::BasicClient;
use opentelemetry::global;
use sentry::integrations::tracing::EventFilter;
use sqlx::PgPool;
use std::error::Error;
use time::Duration;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::CorsLayer;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use tracing_otel_extra::logs::init_env_filter;
use tracing_otel_extra::opentelemetry::KeyValue;
use tracing_otel_extra::{
    get_resource, init_meter_provider, init_tracer_provider, init_tracing_subscriber,
};
use tracing_subscriber::layer::SubscriberExt;

use tower_http::trace::TraceLayer;

use anyhow::Result;
use axum_otel::{AxumOtelOnFailure, AxumOtelOnResponse, AxumOtelSpanCreator, Level};
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};

use sentry::integrations::opentelemetry as sentry_opentelemetry;
use sentry::integrations::tower::NewSentryLayer;

use std::sync::{Arc, RwLock};

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv().ok();
    let service_name = "groupify";
    let resource = get_resource(service_name, &[KeyValue::new("environment", "production")]);
    let sentry_dns = std::env::var("SENTRY_DSN")?;

    let tracer_provider = init_tracer_provider(&resource, 1.0)?;
    let meter_provider = init_meter_provider(&resource, 30)?;
    let env_filter = init_env_filter(&Level::DEBUG);

    let sentry_layer =
    sentry::integrations::tracing::layer().event_filter(|md| match *md.level() {
        // Capture error level events as Sentry events
        // These are grouped into issues, representing high-severity errors to act upon
        tracing::Level::ERROR => EventFilter::Event,
        // Ignore trace level events, as they're too verbose
        tracing::Level::TRACE => EventFilter::Ignore,
        // Capture everything else as a traditional structured log
        _ => EventFilter::Log,
    });

    let _guard = init_tracing_subscriber(
        service_name,
        env_filter,
        vec![Box::new(tracing_subscriber::fmt::layer()), Box::new(sentry_layer)],
        tracer_provider,
        meter_provider,
    )?;

    let _guard = sentry::init((
        sentry_dns,
        sentry::ClientOptions {
            release: sentry::release_name!(),
            enable_logs: true,
            traces_sample_rate: 1.0,
            // Capture user IPs and potentially sensitive headers when using HTTP server integrations
            // see https://docs.sentry.io/platforms/rust/data-management/data-collected for more info
            send_default_pii: true,
            ..Default::default()
        },
    ));

    global::set_text_map_propagator(sentry_opentelemetry::SentryPropagator::new());

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
        .layer(sentry_tower::NewSentryLayer::<Request>::new_from_top())
        .layer(sentry_tower::SentryHttpLayer::new().enable_transaction())
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(AxumOtelSpanCreator::new().level(Level::DEBUG))
                        .on_response(AxumOtelOnResponse::new().level(Level::DEBUG))
                        .on_failure(AxumOtelOnFailure::new()),
                )
                .layer(PropagateRequestIdLayer::x_request_id()),
        )
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
