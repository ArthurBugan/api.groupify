use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::error::Error as StdError;
use std::collections::HashMap; // Alias to avoid conflict with thiserror::Error

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("Authentication failed: {0}")]
    Authentication(#[source] anyhow::Error),

    #[error("Database error: {0}")]
    Database(#[source] anyhow::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Conflict error: {0}")]
    Conflict(String),

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
    
    #[error("Validation errors")]
    ValidationErrors(HashMap<String, Vec<String>>),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message, errors) = match &self {
            AppError::Authentication(e) => (StatusCode::UNAUTHORIZED, format!("{}", e), None),
            AppError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
                None,
            ),
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, msg.clone(), None),
            AppError::ExternalService(e) => (
                StatusCode::BAD_GATEWAY,
                format!("External service error: {}", e),
                None,
            ),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone(), None),
            // Add this new case
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone(), None),
            AppError::UrlParse(e) => (StatusCode::BAD_REQUEST, format!("Invalid URL: {}", e), None),
            AppError::Timeout(e) => (
                StatusCode::GATEWAY_TIMEOUT,
                format!("Operation timed out: {}", e),
                None,
            ),
            AppError::Unexpected(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("An unexpected error occurred: {}", e),
                None,
            ),
            AppError::ValidationErrors(validation_errors) => (
                StatusCode::BAD_REQUEST,
                "Validation failed".to_string(),
                Some(validation_errors.clone()),
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

        // Format the response to match the frontend's expected format
        let body = match errors {
            Some(validation_errors) => Json(json!({
                "message": error_message,
                "status": status.as_u16(),
                "errors": validation_errors
            })),
            None => Json(json!({
                "message": error_message,
                "status": status.as_u16()
            })),
        };
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

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        let mut context_parts = Vec::new();
        
        // Add URL context
        if let Some(url) = err.url() {
            context_parts.push(format!("URL: {}", url));
        }
        
        // Add status code context
        if let Some(status) = err.status() {
            context_parts.push(format!("HTTP {}: {}", 
                status.as_u16(), 
                status.canonical_reason().unwrap_or("Unknown Status")
            ));
        }
        
        // Add detailed error type
        let error_type = match &err {
            e if e.is_timeout() => "Request Timeout",
            e if e.is_connect() => "Connection Failed",
            e if e.is_decode() => "Response Decode Failed", 
            e if e.is_redirect() => "Redirect Loop or Invalid Redirect",
            e if e.is_request() => "Invalid Request",
            e if e.is_body() => "Request Body Error",
            _ => "Unknown HTTP Error"
        };
        context_parts.push(format!("Type: {}", error_type));
        
        // Build comprehensive context message
        let context = if context_parts.is_empty() {
            "External HTTP request failed".to_string()
        } else {
            format!("External HTTP request failed - {}", context_parts.join(", "))
        };
        
        // Log the error with full context for debugging
        tracing::error!(
            error = %err,
            url = ?err.url(),
            status = ?err.status(),
            is_timeout = err.is_timeout(),
            is_connect = err.is_connect(),
            is_decode = err.is_decode(),
            "HTTP request failed with detailed context"
        );
        
        AppError::ExternalService(anyhow::Error::new(err).context(context))
    }
}