use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::error::Error as StdError; // Alias to avoid conflict with thiserror::Error

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    Authentication(#[source] anyhow::Error),

    #[error("Database error: {0}")]
    Database(#[source] anyhow::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("External service error: {0}")]
    ExternalService(#[source] anyhow::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("URL parsing error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("An unexpected error occurred: {0}")]
    Unexpected(#[from] anyhow::Error), // Catch-all for other anyhow errors
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials.")]
    InvalidCredentials(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Authentication(e) => (StatusCode::UNAUTHORIZED, format!("{}", e)),
            AppError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            ),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::ExternalService(e) => (
                StatusCode::BAD_GATEWAY,
                format!("External service error: {}", e),
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::UrlParse(e) => (StatusCode::BAD_REQUEST, format!("Invalid URL: {}", e)),
            AppError::Timeout(e) => (
                StatusCode::GATEWAY_TIMEOUT,
                format!("Operation timed out: {}", e),
            ),
            AppError::Unexpected(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("An unexpected error occurred: {}", e),
            ),
            
        };

        // Log the error with its specific variant and message
        tracing::error!(
            error_type = %self,
            error_message = %error_message,
            status_code = %status,
            "Request error"
        );

        // For unexpected errors, log the source chain if available for more detailed debugging
        if let AppError::Unexpected(e) = &self {
            let mut source_chain = String::new();
            let mut current_err: Option<&(dyn StdError + 'static)> = Some(e.as_ref());
            while let Some(err) = current_err {
                source_chain.push_str(&format!("\n  Caused by: {}", err));
                current_err = err.source();
            }
            if !source_chain.is_empty() {
                tracing::error!("Unexpected error source chain:{}", source_chain);
            }
        }

        let body = Json(json!({ "error": error_message }));
        (status, body).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound("Database record not found".to_string()),
            // You can match other specific sqlx errors here if needed
            _ => AppError::Database(anyhow::Error::new(err).context("SQLx operation failed")),
        }
    }
}

// Example for reqwest::Error, if you make HTTP calls
impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::ExternalService(anyhow::Error::new(err).context("External HTTP request failed"))
    }
}

impl From<AuthError> for AppError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials(source) => AppError::Authentication(source.into()),
            AuthError::UnexpectedError(source) => AppError::Unexpected(source.into()),
        }
    }
}