use crate::authentication::{validate_credentials, Credentials};
use crate::{COUNTER_KEY, InnerState};

use axum::extract::State;
use axum::Form;
use axum::http::{HeaderMap, Response};
use reqwest::StatusCode;

use serde::{Deserialize, Serialize};
use axum::body::Body;
use axum::response::{Html};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use tower_sessions::Session;

use crate::authentication::AuthError;

#[derive(thiserror::Error, Debug)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error("Something went wrong")]
    UnexpectedError(#[from] anyhow::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

#[derive(Default, Deserialize, Serialize)]
pub struct Counter(pub(crate) usize);

#[derive(serde::Deserialize)]
pub struct FormData {
    email: String,
    password: String,
}

pub async fn login_user(
    State(inner): State<InnerState>,
    Form(form): Form<FormData>
) -> Result<Response<Body>, String> {
    let InnerState { db, .. } = inner;

    let credentials = Credentials {
        email: form.email,
        password: form.password,
    };

    match validate_credentials(&credentials, &db).await {
        Ok(user_id) => {
            let token = generate_token(&credentials.email.clone());

           Ok(Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("Location", "/admin/dashboard")
            .body(Body::from(token))
            .expect("This response should always be constructable"))
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.into()),
            };

            Err(e.to_string().into())
        }
    }
}

pub async fn root(headers: HeaderMap) -> Html<String> {
    Html(format!("<h1>{:?}</h1>", headers))
}

fn generate_token(username: &str) -> String {
    let key = "CJleHAiOjE3MTc1MzMyMzV9";
    let claims = Claims {
        sub: username.to_owned(),
        role: "user".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::days(90)).timestamp() as usize,
    };
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(key.as_ref())).unwrap()
}
