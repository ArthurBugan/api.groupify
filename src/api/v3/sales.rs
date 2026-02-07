use axum::{extract::State, Form, Json};
use chrono::{DateTime, FixedOffset, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing;

use crate::{
    api::{
        common::ApiResponse,
        v3::entities::{subscription_plans, subscription_plans_users, users},
    },
    errors::AppError,
    InnerState,
};

#[derive(Debug, Deserialize, Serialize)]
pub struct MLSaleWebhookPayload {
    pub action: String,
    pub application_id: String,
    pub data: HashMap<String, String>,
    pub date: String,
    pub entity: String,
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub version: i32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SalePayload {
    pub sale_id: String,
    pub sale_timestamp: DateTime<FixedOffset>,
    pub order_number: i64,
    pub seller_id: String,
    pub product_id: String,
    pub product_permalink: String,
    pub short_product_id: String,
    pub product_name: String,
    pub email: String,

    #[serde(rename = "url_params[url_params[user_id]] ")]
    pub user_id_params: Option<String>,

    #[serde(default)]
    pub url_params: Option<HashMap<String, String>>,

    #[serde(default)]
    pub custom_fields: Option<HashMap<String, String>>,

    #[serde(rename = "custom_fields[user_id]")]
    pub user_id: String,

    pub full_name: Option<String>,
    pub purchaser_id: Option<String>,
    pub subscription_id: Option<String>,
    pub ip_country: Option<String>,
    pub price: i64,
    pub recurrence: Option<String>,
    pub variants: Option<HashMap<String, String>>,
    pub offer_code: Option<String>,
    pub test: bool,
    pub shipping_information: Option<HashMap<String, String>>,
    pub is_recurring_charge: Option<bool>,
    pub is_preorder_authorization: Option<bool>,
    pub license_key: Option<String>,
    pub quantity: i64,
    pub shipping_rate: Option<i64>,
    pub affiliate: Option<String>,
    pub affiliate_credit_amount_cents: Option<i64>,
    pub is_gift_receiver_purchase: bool,
    pub gifter_email: Option<String>,
    pub gift_price: Option<i64>,
    pub refunded: bool,
    pub discover_fee_charged: bool,
    pub can_contact: bool,
    pub referrer: Option<String>,
    pub gumroad_fee: i64,
    pub card: Option<HashMap<String, String>>, // Assuming card details as a HashMap for now
}

#[tracing::instrument(name = "Make a sale", skip(inner, payload))]
pub async fn make_sale(
    State(inner): State<InnerState>,
    Form(payload): Form<SalePayload>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    // Log the received payload for tracing purposes.
    tracing::info!("Received sale payload: {:?}", payload);

    let db = &inner.sea_db;
    let txn = db.begin().await.map_err(AppError::SeaORM)?;

    // 1. Find or create user
    let user = match users::Entity::find()
        .filter(users::Column::Id.eq(&payload.user_id))
        .one(&txn)
        .await
        .map_err(AppError::SeaORM)?
    {
        Some(u) => u,
        None => {
            tracing::warn!("User not found for user_id: {}", payload.user_id);
            return Err(AppError::NotFound(format!(
                "User not found for user_id: {}",
                payload.user_id
            )));
        }
    };

    // 2. Find or create subscription plan
    let subscription_plan = match subscription_plans::Entity::find()
        .filter(subscription_plans::Column::Name.eq(&payload.product_name))
        .one(&txn)
        .await
        .map_err(AppError::SeaORM)?
    {
        Some(p) => p,
        None => {
            tracing::warn!(
                "Subscription plan not found for product: {}",
                payload.product_name
            );
            return Err(AppError::NotFound(format!(
                "Subscription plan not found for product: {}",
                payload.product_name
            )));
        }
    };

    // 3. Create subscription_plans_users entry
    tracing::info!(
        "Assigning plan {} to user {}",
        subscription_plan.name,
        user.email
    );
    let new_subscription_user = subscription_plans_users::ActiveModel {
        user_id: Set(user.id.clone()),
        subscription_plan_id: Set(subscription_plan.id),
        started_at: Set(Some(payload.sale_timestamp)),
        created_at: Set(Some(Utc::now().fixed_offset())),
        updated_at: Set(Some(Utc::now().fixed_offset())),
        ..Default::default()
    };

    new_subscription_user
        .insert(&txn)
        .await
        .map_err(AppError::SeaORM)?;

    txn.commit().await.map_err(AppError::SeaORM)?;

    Ok(Json(ApiResponse::success(
        "Sale processed and subscription assigned successfully".to_string(),
    )))
}

pub async fn make_ml_sale(
    State(inner): State<InnerState>,
    Json(payload): Json<MLSaleWebhookPayload>,
) -> Result<Json<ApiResponse<String>>, AppError> {
    // Log the received ML sale webhook payload for tracing purposes
    tracing::info!("Received ML sale webhook payload: {:#?}", payload);

    // Extract specific fields for detailed logging
    tracing::info!(
        "ML Sale Details - Action: {}, Entity: {}, Event Type: {}, ID: {}",
        payload.action,
        payload.entity,
        payload.event_type,
        payload.id
    );

    // Log the data field contents
    if !payload.data.is_empty() {
        tracing::info!("ML Sale Data: {:?}", payload.data);
    }

    // Handle different event types
    match payload.event_type.as_str() {
        "subscription_authorized_payment" => {
            tracing::info!("Processing subscription authorized payment for user");

            // Extract user ID from data - adjust this based on your actual data structure
            let user_id = payload
                .data
                .get("user_id")
                .or_else(|| payload.data.get("id"))
                .ok_or_else(|| {
                    tracing::error!("User ID not found in ML sale data: {:?}", payload.data);
                    AppError::BadRequest("User ID not found in sale data".to_string())
                })?;

            // Extract product/plan information - adjust based on your data structure
            let product_name = payload
                .data
                .get("product_name")
                .or_else(|| payload.data.get("plan_name"))
                .ok_or_else(|| {
                    tracing::error!("Product name not found in ML sale data: {:?}", payload.data);
                    AppError::BadRequest("Product/Plan name not found in sale data".to_string())
                })?;

            // Create subscription similar to make_sale function
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
                    tracing::warn!("User not found for user_id: {}", user_id);
                    return Err(AppError::NotFound(format!(
                        "User not found for user_id: {}",
                        user_id
                    )));
                }
            };

            // 2. Find or create subscription plan
            let subscription_plan = match subscription_plans::Entity::find()
                .filter(subscription_plans::Column::Name.eq(product_name))
                .one(&txn)
                .await
                .map_err(AppError::SeaORM)?
            {
                Some(p) => p,
                None => {
                    tracing::warn!("Subscription plan not found for product: {}", product_name);
                    return Err(AppError::NotFound(format!(
                        "Subscription plan not found for product: {}",
                        product_name
                    )));
                }
            };

            // 3. Create subscription_plans_users entry
            tracing::info!(
                "Assigning plan {} to user {} from ML sale",
                subscription_plan.name,
                user.email
            );

            let new_subscription_user = subscription_plans_users::ActiveModel {
                user_id: Set(user.id.clone()),
                subscription_plan_id: Set(subscription_plan.id),
                started_at: Set(Some(Utc::now().fixed_offset())),
                created_at: Set(Some(Utc::now().fixed_offset())),
                updated_at: Set(Some(Utc::now().fixed_offset())),
                ..Default::default()
            };

            new_subscription_user
                .insert(&txn)
                .await
                .map_err(AppError::SeaORM)?;

            txn.commit().await.map_err(AppError::SeaORM)?;

            tracing::info!(
                "Subscription successfully created for user {} from ML sale",
                user_id
            );
        }

        "subscription_preapproval" | "subscription_preapproval_plan" => {
            tracing::info!(
                "Processing {} event - no subscription creation needed",
                payload.event_type
            );
            // Handle preapproval events - typically just logging or validation
        }

        _ => {
            tracing::warn!("Unknown ML sale event type: {}", payload.event_type);
            return Err(AppError::BadRequest(format!(
                "Unknown event type: {}",
                payload.event_type
            )));
        }
    }

    Ok(Json(ApiResponse::success(
        "ML sale webhook processed successfully".to_string(),
    )))
}
