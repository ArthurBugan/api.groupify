use crate::routes::get_email_from_token;
use crate::utils::internal_error;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;
use tower_cookies::Cookies;

use crate::InnerState;

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Survey {
    pub id: Option<i32>,
    pub survey_text: String,
}

pub async fn insert_survey(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(survey): Json<Survey>,
) -> Result<Json<Survey>, (StatusCode, String)> {
    let InnerState { db, .. } = inner;

    let insert_survey_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("auth_token {}", auth_token.len(),);

    if auth_token.clone().len() == 0 {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Missing token" })).to_string(),
        ));
    }

    let survey_created = tokio::time::timeout(
        insert_survey_timeout,
        sqlx::query_as::<_, Survey>(r#"INSERT INTO survey (survey_text) values ($1) returning *"#)
            .bind(survey.survey_text)
            .fetch_one(&db),
    )
    .await
    .map_err(internal_error)?
    .map_err(internal_error)?;

    Ok(Json(survey_created))
}
