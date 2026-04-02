use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info};

use crate::{InnerState, api::common::ApiResponse, errors::AppError};

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateCheckoutSessionRequest {
    pub plan_name: String,
    pub user_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckoutSessionResponse {
    pub session_id: String,
    pub checkout_url: String,
}

/// Create a Dodo checkout session for subscription plans
#[tracing::instrument(name = "Create Dodo checkout session", skip(inner))]
pub async fn create_checkout_session(
    State(inner): State<InnerState>,
    Json(payload): Json<CreateCheckoutSessionRequest>,
) -> Result<Json<ApiResponse<CheckoutSessionResponse>>, AppError> {
    info!("Creating checkout session for user: {} - plan: {}", payload.user_id, payload.plan_name);
    
    // Determine product ID based on plan name
    let product_id = match payload.plan_name.as_str() {
        "Basic" => "pdt_0NbYgsWIfXnEi1M6g6q0P",
        "Pro" => "pdt_0NbYgvc8nuqUMN6xjCFhA",
        _ => {
            error!("Unknown plan name: {}", payload.plan_name);
            return Err(AppError::BadRequest(format!("Unknown plan: {}", payload.plan_name)));
        }
    };

    // Create Dodo client
    let client = reqwest::Client::new();
    
    // Prepare the request to Dodo API
    let request_body = serde_json::json!({
        "product_cart": [{
            "product_id": product_id,
            "quantity": 1
        }],
        "metadata": {
            "user_id": payload.user_id,
            "plan_name": payload.plan_name
        }
    });

    // Get Dodo API credentials from environment
    let dodo_api_key = std::env::var("DODO_API_KEY")
        .map_err(|_| AppError::BadRequest("DODO_API_KEY not set".to_string()))?;
    
    let environment = std::env::var("DODO_ENVIRONMENT")
        .unwrap_or_else(|_| "test_mode".to_string());

    let url = std::env::var("DODO_URL")
        .unwrap_or_else(|_| "test_mode".to_string());
    
    let checkout_url = std::env::var("DODO_CHECKOUT")
        .unwrap_or_else(|_| format!("{}{}", url, "/checkouts"));

    let response = client
        .post(format!("{}{}", url, "/checkouts"))
        .header("Authorization", format!("Bearer {}", dodo_api_key))
        .header("Content-Type", "application/json")
        .header("Dodo-Environment", environment)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| {
            error!("Failed to create Dodo checkout session: {}", e);
            AppError::BadRequest("Failed to create checkout session".to_string())
        })?;

    let response_status = response.status();
    if !response_status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        error!("Dodo API error: {} - {}", response_status, error_text);
        return Err(AppError::BadRequest("Failed to create checkout session with Dodo".to_string()));
    }

    let dodo_response: HashMap<String, serde_json::Value> = response.json().await.map_err(|e| {
        error!("Failed to parse Dodo response: {}", e);
        AppError::BadRequest("Failed to parse checkout session response".to_string())
    })?;

    debug!("Dodo checkout session response: {:?}", dodo_response);

    let session_id = dodo_response.get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            error!("Session ID not found in Dodo response: {:?}", dodo_response);
            AppError::BadRequest("Session ID not found in response".to_string())
        })?
        .to_string();

    let checkout_url = format!("{}/session/{}", checkout_url, session_id);

    info!("Successfully created checkout session: {} for user: {}", session_id, payload.user_id);

    Ok(Json(ApiResponse::success(CheckoutSessionResponse {
        session_id,
        checkout_url,
    })))
}

/// Webhook handler for Dodo payment events
#[tracing::instrument(name = "Handle Dodo webhook", skip(inner))]
pub async fn handle_dodo_webhook(
    State(inner): State<InnerState>,
    Json(payload): Json<HashMap<String, serde_json::Value>>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    info!("Received Dodo webhook: {:?}", payload);
    
    // Verify webhook signature (implement proper signature verification)
    // Extract event type and process accordingly
    let event_type = payload.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    match event_type {
        "checkout.session.completed" => {
            // Handle successful payment
            if let Some(data) = payload.get("data") {
                if let Some(object) = data.get("object") {
                    let session_id = object.get("session_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    
                    info!("Checkout session completed: {}", session_id);
                    
                    // TODO: Update user subscription status in database
                    // Extract user_id from metadata and update their plan
                }
            }
        }
        "checkout.session.expired" => {
            info!("Checkout session expired");
        }
        _ => {
            info!("Unhandled Dodo event type: {}", event_type);
        }
    }

    Ok(Json(ApiResponse::success("Webhook processed successfully".to_string())))
}