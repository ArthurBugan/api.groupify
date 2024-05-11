use crate::authentication::{validate_credentials, Credentials};
use crate::{COUNTER_KEY, InnerState};

use axum::extract::State;
use axum::{Form, Json};
use axum::http::{HeaderMap, Response};
use reqwest::StatusCode;

use serde::{Deserialize, Serialize};
use axum::body::Body;
use axum::response::{Html};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use axum_typed_multipart::{TryFromMultipart, TypedMultipart};
use serde_json::{json, Value};


use crate::authentication::AuthError;

#[derive(thiserror::Error, Debug)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    role: String,
    exp: usize,
}

#[derive(Default, Deserialize, Serialize)]
pub struct Counter(pub(crate) usize);

#[derive(serde::Deserialize, TryFromMultipart)]
pub struct FormData {
    email: String,
    password: String,
}

pub async fn login_user(
    State(inner): State<InnerState>,
    form: TypedMultipart<FormData>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let InnerState { db, .. } = inner;

    let credentials = Credentials {
        email: form.email.clone(),
        password: form.password.clone(),
    };

    match validate_credentials(&credentials, &db).await {
        Ok(user_id) => {
            let token = generate_token(&credentials.email.clone());

            Ok(Json(json!({"access_token": token})))
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.into()),
            };

            Err((StatusCode::BAD_REQUEST, Json(json!({"error": e.to_string()}))))
        }
    }
}

pub async fn root(headers: HeaderMap) -> Html<String> {
    Html(format!("<h1>{:?}</h1>", headers))
}

fn generate_token(username: &str) -> String {
    let key = std::env::var("SECRET_TOKEN").expect("SECRET_TOKEN Env variable must exists");

    let claims = Claims {
        sub: username.to_owned(),
        role: "user".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::days(90)).timestamp() as usize,
    };
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(key.as_bytes())).unwrap()
}
