use axum::{Form, Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing;
use std::collections::HashMap;
use chrono::{DateTime, FixedOffset, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};

use crate::{
    InnerState, api::{common::ApiResponse, v3::entities::{subscription_plans, subscription_plans_users, users}}, errors::AppError
};

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
            tracing::warn!("Subscription plan not found for product: {}", payload.product_name);
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

