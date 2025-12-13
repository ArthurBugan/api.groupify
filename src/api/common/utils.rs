use time::OffsetDateTime;
use cookie::{Cookie, SameSite};
use tower_cookies::Cookies;

use crate::errors::AppError;
use sqlx::PgPool;

pub fn setup_auth_cookie(token: &str, domain: &str, cookies: &Cookies) {

    let mut cookie = Cookie::new("auth-token", token.to_string());

    // Check if we're in development mode
    let is_development = std::env::var("ENVIRONMENT")
        .unwrap_or_else(|_| "production".to_string())
        .to_lowercase()
        == "development";

    if is_development {
        // Development settings - works with HTTP
        cookie.set_domain("localhost".to_string());
        cookie.set_same_site(SameSite::None); // More permissive for development
        cookie.set_secure(true); // Allow HTTP in development
    } else {
        // Production settings - requires HTTPS
        let cookie_domain = if domain.starts_with('.') {
            domain.to_string()
        } else {
            format!(".{}", domain)
        };
        cookie.set_domain(cookie_domain);
        cookie.set_same_site(SameSite::None);
        cookie.set_secure(true);
    }

    let mut now = OffsetDateTime::now_utc();
    now += time::Duration::days(60);

    cookie.set_path("/");
    cookie.set_expires(now);
    cookie.set_http_only(true);
    cookies.add(cookie);
}

pub async fn timeout_query<T, F>(duration: std::time::Duration, fut: F) -> Result<T, AppError>
where
    F: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    match tokio::time::timeout(duration, fut).await {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(e)) => Err(AppError::from(e)),
        Err(_) => Err(AppError::Database(anyhow::anyhow!(
            "Query timeout after {:?}",
            duration
        ))),
    }
}

pub async fn is_owner_or_admin(
    db: &PgPool,
    group_id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let timeout_duration = std::time::Duration::from_millis(5000); // 5 seconds timeout

    // Check if user is the group owner
    let is_owner = timeout_query(
        timeout_duration,
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND user_id = $2)",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_one(db),
    )
    .await?;

    if is_owner {
        return Ok(true);
    }

    // Check if user is an admin in group_members
    let is_admin = timeout_query(
        timeout_duration,
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND role = 'admin')",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_one(db),
    )
    .await?;

    Ok(is_admin)
}

pub async fn is_editor_or_admin(
    db: &PgPool,
    group_id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let timeout_duration = std::time::Duration::from_millis(5000); // 5 seconds timeout

    let is_editor_or_admin = timeout_query(
        timeout_duration,
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND (role = 'editor' OR role = 'admin'))",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_one(db),
    )
    .await?;

    Ok(is_editor_or_admin)
}

pub async fn is_editor_or_owner(
    db: &PgPool,
    group_id: &str,
    user_id: &str,
) -> Result<bool, AppError> {
    let timeout_duration = std::time::Duration::from_millis(5000); // 5 seconds timeout

    // Check if user is the group owner
    let is_owner = timeout_query(
        timeout_duration,
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM groups WHERE id = $1 AND user_id = $2)",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_one(db),
    )
    .await?;

    if is_owner {
        return Ok(true);
    }

    // Check if user is an editor or admin in group_members
    let is_editor_or_admin = timeout_query(
        timeout_duration,
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2 AND (role = 'editor' OR role = 'admin'))",
        )
        .bind(group_id)
        .bind(user_id)
        .fetch_one(db),
    )
    .await?;

    Ok(is_editor_or_admin)
}