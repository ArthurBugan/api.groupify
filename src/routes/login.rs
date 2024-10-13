use crate::authentication::{validate_credentials, Credentials};
use crate::InnerState;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use reqwest::StatusCode;

use axum::response::Html;
use axum_typed_multipart::{TryFromMultipart, TypedMultipart};
use cookie::time::{Duration, OffsetDateTime};
use cookie::SameSite;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower_cookies::{Cookie, Cookies};

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
    pub user_id: String,
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
    cookies: Cookies,
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
            let token = generate_token(&credentials.email.clone(), &user_id.clone());

            let mut now = OffsetDateTime::now_utc();
            now += Duration::days(60);

            let domain = std::env::var("GROUPIFY_HOST").expect("GROUPIFY_HOST must be set.");
            let mut cookie = Cookie::new("auth-token", token);

            // cookie.set_domain(domain);
            cookie.set_same_site(SameSite::None);
            cookie.set_secure(true);
            cookie.set_path("/");
            cookie.set_expires(now);
            cookies.add(cookie);

            Ok(Json(json!({"data": "login completed"})))
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnexpectedError(_) => LoginError::UnexpectedError(e.into()),
            };

            Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            ))
        }
    }
}

pub async fn root(headers: HeaderMap) -> Html<String> {
    Html(format!("<h1>{:?}</h1>", headers))
}

fn generate_token(username: &str, user_id: &str) -> String {
    let key = std::env::var("SECRET_TOKEN").expect("SECRET_TOKEN Env variable must exists");

    let claims = Claims {
        user_id: user_id.to_owned(),
        sub: username.to_owned(),
        role: "user".to_owned(),
        exp: (chrono::Utc::now() + chrono::Duration::days(90)).timestamp() as usize,
    };
    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(key.as_bytes())).unwrap()
}
