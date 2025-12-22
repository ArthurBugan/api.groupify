use axum::{Form, Json, extract::State};
use serde::{Deserialize, Serialize};
use tracing;
use std::collections::HashMap;
use chrono::{DateTime, FixedOffset};

use crate::{
    api::common::ApiResponse,
    errors::AppError,
    InnerState,
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
    pub url_params: Option<HashMap<String, String>>,
    pub full_name: Option<String>,
    pub purchaser_id: Option<String>,
    pub subscription_id: Option<String>,
    pub ip_country: Option<String>,
    pub price: i64,
    pub recurrence: Option<String>,
    pub variants: Option<HashMap<String, String>>,
    pub offer_code: Option<String>,
    pub test: bool,
    pub custom_fields: Option<HashMap<String, String>>,
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
    // In a real application, you would typically process this sale data,
    // e.g., save it to a database, trigger other business logic, etc.
    tracing::info!("Received sale payload: {:?}", payload);

    // For now, we'll just return a success response indicating the payload was received.
    Ok(Json(ApiResponse::success("Sale processed successfully".to_string())))
}
