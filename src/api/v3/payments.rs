use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info};
use chrono::{Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use crate::{InnerState, api::common::ApiResponse, errors::AppError, api::v3::entities::{subscription_plans, subscription_plans_users, users}};

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateCheckoutSessionRequest {
    pub plan_name: String,
    pub user_id: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct CheckoutSessionResponse {
    pub session_id: String,
    pub checkout_url: String,
}

// Dodo webhook types
#[derive(Debug, Deserialize, Serialize)]
pub struct DodoCustomer {
    pub customer_id: String,
    pub email: String,
    pub name: String,
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub phone_number: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DodoSubscriptionData {
    pub subscription_id: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub next_billing_date: String,
    pub product_id: String,
    pub quantity: i32,
    pub customer: DodoCustomer,
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(default)]
    pub custom_field_responses: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DodoWebhookPayload {
    #[serde(rename = "type")]
    pub event_type: String,
    pub business_id: String,
    pub data: DodoSubscriptionData,
    pub timestamp: String,
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

/// Helper function to activate subscription from Dodo webhook data
#[tracing::instrument(name = "Activate subscription from Dodo webhook", skip(inner, payload))]
async fn activate_subscription_from_dodo_webhook(
    inner: &InnerState,
    payload: &DodoWebhookPayload,
) -> Result<(), AppError> {
    // Extract user_id from metadata
    let user_id = payload.data.metadata.get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            error!("User ID not found in Dodo webhook metadata: {:?}", payload.data.metadata);
            AppError::BadRequest("User ID not found in webhook metadata".to_string())
        })?;
    
    // Extract plan_name from metadata and map to database plan names
    let dodo_plan_name = payload.data.metadata.get("plan_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            error!("Plan name not found in Dodo webhook metadata: {:?}", payload.data.metadata);
            AppError::BadRequest("Plan name not found in webhook metadata".to_string())
        })?;
    
    // Map Dodo plan names to database plan names
    let db_plan_name = match dodo_plan_name {
        "Basic" => "Groupify Basic Monthly",
        "Pro" => "Groupify Pro Monthly",
        _ => {
            error!("Unknown Dodo plan name: {}", dodo_plan_name);
            return Err(AppError::BadRequest(format!("Unknown plan: {}", dodo_plan_name)));
        }
    };
    
    info!("Activating subscription for user: {} - Dodo plan: {} -> DB plan: {}", user_id, dodo_plan_name, db_plan_name);
    
    let db = &inner.sea_db;
    let txn = db.begin().await.map_err(AppError::SeaORM)?;

    // 1. Find user
    let user = match users::Entity::find()
        .filter(users::Column::Id.eq(user_id))
        .one(&txn)
        .await
        .map_err(AppError::SeaORM)?
    {
        Some(u) => u,
        None => {
            error!("User not found for user_id: {}", user_id);
            return Err(AppError::NotFound(format!(
                "User not found for user_id: {}",
                user_id
            )));
        }
    };

    // 2. Find subscription plan
    let subscription_plan = match subscription_plans::Entity::find()
        .filter(subscription_plans::Column::Name.eq(db_plan_name))
        .one(&txn)
        .await
        .map_err(AppError::SeaORM)?
    {
        Some(p) => p,
        None => {
            error!("Subscription plan not found for DB plan: {}", db_plan_name);
            return Err(AppError::NotFound(format!(
                "Subscription plan not found for plan: {}",
                db_plan_name
            )));
        }
    };

    // 3. Check for existing active subscriptions and end them
    let existing_subscriptions = subscription_plans_users::Entity::find()
        .filter(subscription_plans_users::Column::UserId.eq(user.id.clone()))
        .filter(subscription_plans_users::Column::EndedAt.is_null()) // Only active subscriptions
        .all(&txn)
        .await
        .map_err(AppError::SeaORM)?;

    // End all existing active subscriptions
    for mut existing_sub in existing_subscriptions {
        info!("Ending existing subscription {} for user {}", existing_sub.id, user.id);
        
        let mut active_model: subscription_plans_users::ActiveModel = existing_sub.into();
        active_model.ended_at = Set(Some(Utc::now().fixed_offset()));
        
        active_model.update(&txn).await.map_err(AppError::SeaORM)?;
    }

    // 4. Create new subscription_plans_users entry
    info!(
        "Assigning plan {} to user {} from Dodo subscription",
        subscription_plan.name, user.email
    );
    

    let new_subscription_user = subscription_plans_users::ActiveModel {
        user_id: Set(user.id.clone()),
        subscription_plan_id: Set(subscription_plan.id),
        started_at: Set(Some(chrono::DateTime::parse_from_rfc3339(&payload.data.created_at)
            .map_err(|e| {
                error!("Failed to parse created_at timestamp: {}", e);
                AppError::BadRequest("Invalid timestamp format".to_string())
            })?)),
        created_at: Set(Some(Utc::now().fixed_offset())),
        updated_at: Set(Some(Utc::now().fixed_offset())),
        ..Default::default()
    };

    new_subscription_user
        .insert(&txn)
        .await
        .map_err(AppError::SeaORM)?;

    txn.commit().await.map_err(AppError::SeaORM)?;
    
    info!("Subscription successfully activated for user {} from Dodo webhook", user_id);

    Ok(())
}

/// Handle Dodo webhook for subscription activation
#[tracing::instrument(name = "Handle Dodo subscription webhook", skip(inner, payload))]
pub async fn handle_dodo_subscription_webhook(
    State(inner): State<InnerState>,
    Json(payload): Json<DodoWebhookPayload>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    info!("Received Dodo webhook: {:?}", payload);
    
    // Only process subscription.active events
    if payload.event_type != "subscription.active" {
        info!("Ignoring Dodo event type: {}", payload.event_type);
        return Ok(Json(ApiResponse::success("Event ignored".to_string())));
    }
    
    activate_subscription_from_dodo_webhook(&inner, &payload).await?;
    
    Ok(Json(ApiResponse::success("Subscription activated successfully".to_string())))
}