use crate::api::common::{PaginatedResponse, PaginationInfo, PaginationParams};
use crate::errors::AppError;
use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::api::v1::user::{get_email_from_token, get_user_id_from_token};
use crate::api::v2::channels::{all_channels_by_group_id, ChannelWithGroup};
use crate::InnerState;

#[derive(Debug, Serialize, Deserialize, FromRow, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: Option<String>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
    pub name: String,
    pub icon: String,
    pub user_id: String,
    pub description: Option<String>,
    pub category: Option<String>,
    pub parent_id: Option<String>,
    pub nesting_level: Option<i32>,
    pub display_order: Option<f64>,
    #[sqlx(skip)]
    pub channel_count: Option<i64>,
    #[sqlx(skip)]
    pub channels: Vec<ChannelWithGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub icon: String,
    pub parent_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub icon: String,
    pub parent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateGroupResponse {
    pub success: bool,
    pub message: String,
    pub data: Group,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDisplayOrderRequest {
    pub display_order: f64,
}

#[derive(Debug, Serialize)]
pub struct UpdateDisplayOrderResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct GetGroupResponse {
    pub success: bool,
    pub message: String,
    pub data: Group,
}

#[tracing::instrument(name = "Get all groups for user", skip(cookies, inner))]
#[axum::debug_handler]
pub async fn all_groups(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<PaginatedResponse<Group>>, AppError> {
    tracing::info!("Starting to fetch paginated groups for user");

    let InnerState { db, .. } = inner;
    let fetch_groups_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("Auth token length: {}", auth_token.len());

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting user ID from auth token");
    let user_id = get_user_id_from_token(auth_token).await?;
    tracing::info!("Successfully extracted user_id for user: {}", user_id);

    // Set default pagination values
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(10).max(1).min(100); // Cap at 100 items per page
    let offset = (page - 1) * limit;

    tracing::debug!(
        "Pagination: page={}, limit={}, offset={}, search={:?}",
        page,
        limit,
        offset,
        params.search
    );

    // Build the search condition if provided
    let search_condition = if let Some(search_term) = &params.search {
        format!(
            "AND (g.name ILIKE '%{}%' OR g.description ILIKE '%{}%')",
            search_term, search_term
        )
    } else {
        String::new()
    };

    // Count total groups for pagination
    let count_query = format!(
        r#"SELECT COUNT(DISTINCT g.id) as total 
           FROM groups g 
           INNER JOIN users u ON u.id = g.user_id 
           LEFT JOIN channels c ON c.group_id = g.id
           WHERE u.id = $1 {} 
           "#,
        search_condition
    );

    let total_result = match tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_scalar::<_, i64>(&count_query)
            .bind(&user_id)
            .fetch_one(&db),
    )
    .await
    {
        Ok(Ok(total)) => total,
        Ok(Err(e)) => {
            tracing::error!(
                "Database error while counting groups for user {}: {:?}",
                user_id,
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "Timeout elapsed while counting groups for user {}: {:?}",
                user_id,
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_groups_timeout
            )));
        }
    };

    tracing::debug!("Total groups found: {}", total_result);

    // Calculate pagination info
    let total_pages = ((total_result as f64) / (limit as f64)).ceil() as u32;
    let has_next = page < total_pages;
    let has_prev = page > 1;

    // Fetch paginated groups
    let groups_query = format!(
        r#"SELECT g.*, 
           (SELECT COUNT(*) FROM channels WHERE group_id = g.id) as channel_count
           FROM groups g 
           INNER JOIN users u ON u.id = g.user_id 
           WHERE u.id = $1 {} 
           ORDER BY g.nesting_level ASC, g.display_order ASC, g.name ASC
           LIMIT $2 OFFSET $3"#,
        search_condition
    );

    tracing::debug!("Executing database query to fetch paginated groups");
    let groups = match tokio::time::timeout(
        fetch_groups_timeout,
        sqlx::query_as::<_, Group>(&groups_query)
            .bind(&user_id)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(groups)) => {
            tracing::info!(
                "Successfully fetched {} groups for user: {}",
                groups.len(),
                user_id
            );
            groups
        }
        Ok(Err(e)) => {
            tracing::error!(
                "Database error while fetching groups for user {}: {:?}",
                user_id,
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "Timeout elapsed while fetching groups for user {}: {:?}",
                user_id,
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_groups_timeout
            )));
        }
    };

    let mut groups_with_channels: Vec<Group> = Vec::new();

    for mut group in groups {
        let channels = all_channels_by_group_id(
            State(InnerState { db: db.clone(), email_client: inner.email_client.clone(), oauth_clients: inner.oauth_clients.clone() }),
            Path(group.id.clone().unwrap_or_default()),
            user_id.clone(),
        ).await?;
        group.channels = channels;
        group.channel_count = Some(group.channels.len() as i64);
        groups_with_channels.push(group);
    }

    let pagination_info = PaginationInfo {
        page,
        limit,
        total: total_result,
        total_pages,
        has_next,
        has_prev,
    };

    let response = PaginatedResponse {
        data: groups_with_channels,
        pagination: pagination_info,
    };

    tracing::debug!(
        "Returning {} groups with pagination info to client",
        response.data.len()
    );
    Ok(Json(response))
}

#[tracing::instrument(
    name = "Update group display order (gap-based)",
    skip(cookies, inner, payload)
)]
pub async fn update_display_order(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(payload): Json<UpdateDisplayOrderRequest>,
) -> Result<Json<UpdateDisplayOrderResponse>, AppError> {
    tracing::info!(
        "Starting gap-based display order update for group: {}",
        group_id
    );

    let InnerState { db, .. } = inner;
    let update_timeout = tokio::time::Duration::from_millis(5000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("Auth token length: {}", auth_token.len());

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting email from auth token");
    let email = get_email_from_token(auth_token).await?;
    tracing::info!("Successfully extracted email for user: {}", email);

    // Get user ID first
    let user_id_query = r#"
        SELECT id FROM users WHERE email = $1
    "#;

    let user_id = match tokio::time::timeout(
        update_timeout,
        sqlx::query_scalar::<_, String>(user_id_query)
            .bind(&email)
            .fetch_one(&db),
    )
    .await
    {
        Ok(Ok(id)) => {
            tracing::debug!("Found user ID: {} for email: {}", id, email);
            id
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while fetching user ID: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while fetching user ID: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_timeout
            )));
        }
    };

    // Verify the user owns this group and get current info
    let verify_query = r#"
        SELECT g.id, g.display_order, g.nesting_level
        FROM groups g 
        WHERE g.id = $1 AND g.user_id = $2
    "#;

    let (current_display_order, nesting_level) = match tokio::time::timeout(
        update_timeout,
        sqlx::query_as::<_, (String, f64, i32)>(verify_query)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_optional(&db),
    )
    .await
    {
        Ok(Ok(Some((_, display_order, nesting_level)))) => (display_order, nesting_level),
        Ok(Ok(None)) => {
            tracing::warn!(
                "Group {} not found or user {} does not own it",
                group_id,
                email
            );
            return Err(AppError::NotFound(format!(
                "Group '{}' not found",
                group_id
            )));
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while verifying group ownership: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while verifying group ownership: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_timeout
            )));
        }
    };

    tracing::debug!(
        "Current display_order: {}, target display_order: {}, nesting_level: {}",
        current_display_order,
        payload.display_order,
        nesting_level
    );

    // Get neighboring groups for gap calculation
    let neighbors_query = r#"
        SELECT display_order
        FROM groups 
        WHERE user_id = $1 AND nesting_level = $2
        ORDER BY display_order ASC
    "#;

    let all_orders = match tokio::time::timeout(
        update_timeout,
        sqlx::query_scalar::<_, f64>(neighbors_query)
            .bind(&user_id)
            .bind(&nesting_level)
            .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(orders)) => orders,
        Ok(Err(e)) => {
            tracing::error!("Database error while fetching neighboring groups: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while fetching neighboring groups: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_timeout
            )));
        }
    };

    // Calculate the new display_order using gap-based approach
    let new_display_order = if all_orders.is_empty() {
        // No other groups, use a base value
        1000.0
    } else if payload.display_order <= 0.0 {
        // Moving to the beginning
        all_orders.first().unwrap_or(&1000.0) / 2.0
    } else if payload.display_order >= (all_orders.len() - 1) as f64 {
        // Moving to the end
        all_orders.last().unwrap_or(&1000.0) + 1000.0
    } else {
        // Moving between two items
        let target_index = payload.display_order.min((all_orders.len() - 1) as f64) as usize;
        let prev_order = all_orders
            .get(target_index.saturating_sub(1))
            .unwrap_or(&0.0);
        let fallback = prev_order + 2000.0;
        let next_order = all_orders.get(target_index).unwrap_or(&fallback);
        (prev_order + next_order) / 2.0
    };

    // Ensure the new order is not too close to existing values (minimum gap of 1.0)
    let final_display_order = new_display_order.max(0.1);

    tracing::info!(
        "Calculated new display_order: {} for group {}",
        final_display_order,
        group_id
    );

    // Update the display order
    let update_query = r#"
        UPDATE groups 
        SET display_order = $1, updated_at = NOW() 
        WHERE id = $2
        RETURNING id
    "#;

    match tokio::time::timeout(
        update_timeout,
        sqlx::query_scalar::<_, Option<String>>(update_query)
            .bind(&final_display_order)
            .bind(&group_id)
            .fetch_optional(&db),
    )
    .await
    {
        Ok(Ok(_)) => {
            tracing::info!(
                "Successfully updated display order for group {} to {:.2}",
                group_id,
                final_display_order
            );
            Ok(Json(UpdateDisplayOrderResponse {
                success: true,
                message: format!(
                    "Display order updated successfully to position {:.2}",
                    final_display_order
                ),
            }))
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while updating display order: {:?}", e);
            Err(AppError::from(e))
        }
        Err(elapsed) => {
            tracing::error!("Timeout while updating display order: {:?}", elapsed);
            Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_timeout
            )))
        }
    }
}

#[tracing::instrument(name = "Create new group", skip(cookies, inner))]
pub async fn create_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, AppError> {
    tracing::info!("Starting to create new group with name: {}", payload.name);

    let InnerState { db, .. } = inner;
    let create_timeout = tokio::time::Duration::from_millis(5000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("Auth token length: {}", auth_token.len());

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting email from auth token");
    let user_id = get_user_id_from_token(auth_token).await?;
    tracing::info!("Successfully extracted user_id for user: {}", user_id);

    // Validate parent group if provided
    if let Some(parent_id) = &payload.parent_id {
        let verify_parent_query = r#"
            SELECT g.id, g.nesting_level 
            FROM groups g 
            INNER JOIN users u ON u.id = g.user_id 
            WHERE g.id = $1 AND u.id = $2
        "#;

        let parent_info = match tokio::time::timeout(
            create_timeout,
            sqlx::query_as::<_, (String, Option<i32>)>(verify_parent_query)
                .bind(parent_id)
                .bind(&user_id)
                .fetch_optional(&db),
        )
        .await
        {
            Ok(Ok(Some((_, nesting_level)))) => {
                tracing::debug!(
                    "Parent group {} validated successfully with nesting level: {:?}",
                    parent_id,
                    nesting_level
                );
                Some(nesting_level.unwrap_or(0))
            }
            Ok(Ok(None)) => {
                tracing::warn!(
                    "Parent group {} not found or user {} does not own it",
                    parent_id,
                    user_id
                );
                return Err(AppError::NotFound(format!(
                    "Parent group '{}' not found",
                    parent_id
                )));
            }
            Ok(Err(e)) => {
                tracing::error!("Database error while validating parent group: {:?}", e);
                return Err(AppError::from(e));
            }
            Err(elapsed) => {
                tracing::error!("Timeout while validating parent group: {:?}", elapsed);
                return Err(AppError::Database(anyhow::anyhow!(
                    "Database query timeout after {:?}",
                    create_timeout
                )));
            }
        };

        // Validate nesting level (prevent too deep nesting)
        if let Some(parent_nesting) = parent_info {
            if parent_nesting >= 5 {
                tracing::warn!(
                    "Parent group {} has maximum nesting level (5), cannot create subgroup",
                    parent_id
                );
                return Err(AppError::Validation(String::from(
                    "Maximum nesting level reached (5 levels)",
                )));
            }
        }
    }

    // Generate new group ID
    let group_id = Uuid::new_v4().to_string();
    tracing::debug!(
        "Generated new group ID: {} and parent ID: {:?}",
        group_id,
        payload.parent_id
    );

    // Calculate nesting level and display order
    let (nesting_level, display_order) = if let Some(parent_id) = &payload.parent_id {
        // Get parent's nesting level and max display order for siblings
        let parent_info_query = r#"
            SELECT g.nesting_level, COALESCE(MAX(g2.display_order), 0.0) + 1.0 as next_order
            FROM groups g
            LEFT JOIN groups g2 ON g2.parent_id = g.id
            WHERE g.id = $1 AND g.user_id = $2
            GROUP BY g.nesting_level
        "#;

        match tokio::time::timeout(
            create_timeout,
            sqlx::query_as::<_, (Option<i32>, Option<f64>)>(parent_info_query)
                .bind(parent_id)
                .bind(&user_id)
                .fetch_one(&db),
        )
        .await
        {
            Ok(Ok((parent_nesting, max_order))) => {
                let nesting = parent_nesting.unwrap_or(0) + 1;
                let order = max_order.unwrap_or(1.0);
                tracing::debug!(
                    "Calculated nesting level: {} and display order: {} for subgroup",
                    nesting,
                    order
                );
                (nesting, order)
            }
            Ok(Err(e)) => {
                tracing::error!("Database error while fetching parent info: {:?}", e);
                return Err(AppError::from(e));
            }
            Err(elapsed) => {
                tracing::error!("Timeout while fetching parent info: {:?}", elapsed);
                return Err(AppError::Database(anyhow::anyhow!(
                    "Database query timeout after {:?}",
                    create_timeout
                )));
            }
        }
    } else {
        // Top-level group
        let max_order_query = r#"
            SELECT COALESCE(MAX(display_order), 0.0) + 1.0 
            FROM groups 
            WHERE user_id = $1 AND parent_id IS NULL
        "#;

        let next_order = match tokio::time::timeout(
            create_timeout,
            sqlx::query_scalar::<_, Option<f64>>(max_order_query)
                .bind(&user_id)
                .fetch_one(&db),
        )
        .await
        {
            Ok(Ok(Some(order))) => order,
            Ok(Ok(None)) => 1.0,
            Ok(Err(e)) => {
                tracing::error!("Database error while fetching max display order: {:?}", e);
                return Err(AppError::from(e));
            }
            Err(elapsed) => {
                tracing::error!("Timeout while fetching max display order: {:?}", elapsed);
                return Err(AppError::Database(anyhow::anyhow!(
                    "Database query timeout after {:?}",
                    create_timeout
                )));
            }
        };

        tracing::debug!(
            "Calculated display order: {} for top-level group",
            next_order
        );
        (0, next_order)
    };

    // Insert the new group
    let insert_query = r#"
        INSERT INTO groups (id, name, icon, user_id, description, category, parent_id, nesting_level, display_order)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id, created_at, updated_at, name, icon, user_id, description, category, parent_id, nesting_level, display_order
    "#;

    let new_group = match tokio::time::timeout(
        create_timeout,
        sqlx::query_as::<_, Group>(insert_query)
            .bind(&group_id)
            .bind(&payload.name)
            .bind(&payload.icon)
            .bind(&user_id)
            .bind(&payload.description)
            .bind(&payload.category)
            .bind(&payload.parent_id)
            .bind(&nesting_level)
            .bind(&display_order)
            .fetch_one(&db),
    )
    .await
    {
        Ok(Ok(group)) => {
            tracing::info!(
                "Successfully created group {} with name '{}' for user_id {}",
                group_id,
                payload.name,
                user_id
            );
            group
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while creating group: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while creating group: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                create_timeout
            )));
        }
    };

    Ok(Json(CreateGroupResponse {
        success: true,
        message: "Group created successfully".to_string(),
        data: new_group,
    }))
}

#[tracing::instrument(
    name = "Delete group with cascade",
    skip(cookies, inner),
    fields(group_id = %group_id)
)]
pub async fn delete_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<UpdateDisplayOrderResponse>, AppError> {
    tracing::info!("Starting to delete group with cascade: {}", group_id);

    let InnerState { db, .. } = inner;
    let delete_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token for group deletion");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting email from auth token");
    let email = get_email_from_token(auth_token).await?;
    tracing::info!("Deleting group {} for user: {}", group_id, email);

    // Get user ID first
    let user_id_query = r#"
        SELECT id FROM users WHERE email = $1
    "#;

    let user_id = match tokio::time::timeout(
        delete_timeout,
        sqlx::query_scalar::<_, String>(user_id_query)
            .bind(&email)
            .fetch_one(&db),
    )
    .await
    {
        Ok(Ok(id)) => {
            tracing::debug!("Found user ID: {} for email: {}", id, email);
            id
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while fetching user ID: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while fetching user ID: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                delete_timeout
            )));
        }
    };

    // Verify the user owns this group
    let verify_query = r#"
        SELECT id FROM groups WHERE id = $1 AND user_id = $2
    "#;

    let group_exists = match tokio::time::timeout(
        delete_timeout,
        sqlx::query_scalar::<_, String>(verify_query)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_optional(&db),
    )
    .await
    {
        Ok(Ok(Some(_))) => true,
        Ok(Ok(None)) => false,
        Ok(Err(e)) => {
            tracing::error!("Database error while verifying group ownership: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while verifying group ownership: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                delete_timeout
            )));
        }
    };

    if !group_exists {
        tracing::warn!(
            "Group {} not found or user {} does not own it",
            group_id,
            email
        );
        return Err(AppError::NotFound(format!(
            "Group '{}' not found",
            group_id
        )));
    }

    // Get all child groups recursively using CTE
    let get_children_query = r#"
        WITH RECURSIVE child_groups AS (
            SELECT id, parent_id FROM groups WHERE id = $1 AND user_id = $2
            UNION ALL
            SELECT g.id, g.parent_id 
            FROM groups g
            INNER JOIN child_groups cg ON g.parent_id = cg.id
            WHERE g.user_id = $2
        )
        SELECT id FROM child_groups WHERE id != $1
    "#;

    let child_group_ids = match tokio::time::timeout(
        delete_timeout,
        sqlx::query_scalar::<_, String>(get_children_query)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(ids)) => {
            tracing::info!(
                "Found {} child groups to delete for group {}",
                ids.len(),
                group_id
            );
            ids
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while fetching child groups: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while fetching child groups: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                delete_timeout
            )));
        }
    };

    // Delete all child groups first (to avoid foreign key constraints)
    if !child_group_ids.is_empty() {
        let child_ids_placeholder = child_group_ids
            .iter()
            .map(|_| "$3")
            .collect::<Vec<_>>()
            .join(",");

        let delete_children_query = format!(
            r#"DELETE FROM groups WHERE id IN ({}) AND user_id = $1"#,
            child_ids_placeholder
        );

        let mut delete_children = sqlx::query(&delete_children_query).bind(&user_id);

        // Bind all child IDs
        for child_id in &child_group_ids {
            delete_children = delete_children.bind(child_id);
        }

        match tokio::time::timeout(delete_timeout, delete_children.execute(&db)).await {
            Ok(Ok(result)) => {
                tracing::info!(
                    "Successfully deleted {} child groups for group {}",
                    result.rows_affected(),
                    group_id
                );
            }
            Ok(Err(e)) => {
                tracing::error!("Database error while deleting child groups: {:?}", e);
                return Err(AppError::from(e));
            }
            Err(elapsed) => {
                tracing::error!("Timeout while deleting child groups: {:?}", elapsed);
                return Err(AppError::Database(anyhow::anyhow!(
                    "Database query timeout after {:?}",
                    delete_timeout
                )));
            }
        }
    }

    // Delete the main group
    let delete_main_query = r#"
        DELETE FROM groups WHERE id = $1 AND user_id = $2
    "#;

    match tokio::time::timeout(
        delete_timeout,
        sqlx::query(&delete_main_query)
            .bind(&group_id)
            .bind(&user_id)
            .execute(&db),
    )
    .await
    {
        Ok(Ok(result)) => {
            if result.rows_affected() > 0 {
                tracing::info!(
                    "Successfully deleted group {} and {} child groups for user {}",
                    group_id,
                    child_group_ids.len(),
                    email
                );
                Ok(Json(UpdateDisplayOrderResponse {
                    success: true,
                    message: format!(
                        "Group '{}' and {} child groups deleted successfully",
                        group_id,
                        child_group_ids.len()
                    ),
                }))
            } else {
                tracing::warn!("Group {} not found or already deleted", group_id);
                Err(AppError::NotFound(format!(
                    "Group '{}' not found",
                    group_id
                )))
            }
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while deleting main group: {:?}", e);
            Err(AppError::from(e))
        }
        Err(elapsed) => {
            tracing::error!("Timeout while deleting main group: {:?}", elapsed);
            Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                delete_timeout
            )))
        }
    }
}

#[tracing::instrument(name = "Get group by ID", skip(cookies, inner))]
pub async fn get_group_by_id(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
) -> Result<Json<GetGroupResponse>, AppError> {
    tracing::info!("Starting to fetch group by ID: {}", group_id);

    let InnerState { db, .. } = inner;
    let fetch_timeout = tokio::time::Duration::from_millis(5000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    tracing::debug!("Auth token length: {}", auth_token.len());

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting user ID from auth token");
    let user_id = get_user_id_from_token(auth_token.clone()).await?;
    tracing::info!("Successfully extracted user ID for user: {}", user_id);

    // Query to get the group by ID and verify user ownership
    let group_query = r#"
        SELECT 
            g.*
        FROM 
            groups g
        INNER JOIN 
            users u ON u.id = g.user_id 
        WHERE 
            g.id = $1 AND u.id = $2
    "#;

    tracing::debug!("Executing database query to fetch group by ID");
    let mut group = match tokio::time::timeout(
        fetch_timeout,
        sqlx::query_as::<_, Group>(group_query)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_optional(&db),
    )
    .await
    {
        Ok(Ok(Some(group))) => {
            tracing::info!(
                "Successfully fetched group {} for user: {}",
                group_id,
                user_id
            );
            group
        }
        Ok(Ok(None)) => {
            tracing::warn!(
                "Group {} not found or user {} does not own it",
                group_id,
                user_id
            );
            return Err(AppError::NotFound(format!(
                "Group '{}' not found",
                group_id
            )));
        }
        Ok(Err(e)) => {
            tracing::error!(
                "Database error while fetching group {} for user {}: {:?}",
                group_id,
                user_id,
                e
            );
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!(
                "Timeout while fetching group {} for user {}: {:?}",
                group_id,
                user_id,
                elapsed
            );
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_timeout
            )));
        }
    };

    let channels_query = r#"
        SELECT 
            c.*,
            g.name as group_name, g.icon as group_icon
        FROM 
            channels c
        LEFT JOIN
            groups g ON c.group_id = g.id
        WHERE 
            c.group_id = $1 AND c.user_id = $2
        ORDER BY c.name ASC
    "#;

    tracing::debug!("Executing database query to fetch channels for group {}", group_id);
    let channels = match tokio::time::timeout(
        fetch_timeout,
        sqlx::query_as::<_, ChannelWithGroup>(channels_query)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_all(&db),
    )
    .await
    {
        Ok(Ok(channels)) => {
            tracing::info!("Successfully fetched {} channels for group {}", channels.len(), group_id);
            channels
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while fetching channels for group {}: {:?}", group_id, e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while fetching channels for group {}: {:?}", group_id, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                fetch_timeout
            )));
        }
    };

    group.channels = channels;
    group.channel_count = Some(group.channels.len() as i64);

    tracing::debug!(
        "Returning group {} with {:?} channels to client",
        group_id,
        group.channel_count
    );
    Ok(Json(GetGroupResponse { success: true, message: "Group fetched successfully".to_string(), data: group }))
}

#[tracing::instrument(
    name = "Update existing group",
    skip(cookies, inner, payload),
    fields(group_id = %group_id)
)]
pub async fn update_group(
    cookies: Cookies,
    State(inner): State<InnerState>,
    Path(group_id): Path<String>,
    Json(payload): Json<UpdateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, AppError> {
    tracing::info!("Starting to update group ID: {}", group_id);

    let InnerState { db, .. } = inner;
    let update_timeout = tokio::time::Duration::from_millis(10000);

    let auth_token = cookies
        .get("auth-token")
        .map(|c| c.value().to_string())
        .unwrap_or_default();

    if auth_token.is_empty() {
        tracing::warn!("Authentication failed: Missing auth token for group update");
        return Err(AppError::Authentication(anyhow::anyhow!("Missing token")));
    }

    tracing::debug!("Extracting email from auth token");
    let email = get_email_from_token(auth_token.clone()).await?;
    tracing::info!("Updating group {} for user: {}", group_id, email);

    let user_id = get_user_id_from_token(auth_token.clone()).await?;
    tracing::info!("Successfully extracted user ID for user: {}", user_id);

    // Verify the user owns this group
    let verify_query = r#"
        SELECT id FROM groups WHERE id = $1 AND user_id = $2
    "#;

    let group_exists = match tokio::time::timeout(
        update_timeout,
        sqlx::query_scalar::<_, String>(verify_query)
            .bind(&group_id)
            .bind(&user_id)
            .fetch_optional(&db),
    )
    .await
    {
        Ok(Ok(Some(_))) => true,
        Ok(Ok(None)) => false,
        Ok(Err(e)) => {
            tracing::error!("Database error while verifying group ownership: {:?}", e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while verifying group ownership: {:?}", elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_timeout
            )));
        }
    };

    if !group_exists {
        tracing::warn!(
            "Group {} not found or user {} does not own it",
            group_id,
            email
        );
        return Err(AppError::NotFound(format!(
            "Group '{}' not found",
            group_id
        )));
    }

    // Validate parent group if provided
    if let Some(parent_id) = &payload.parent_id {
        if parent_id != "none" {
            let parent_verify_query = r#"
                SELECT id FROM groups WHERE id = $1 AND user_id = $2
            "#;

            let parent_exists = match tokio::time::timeout(
                update_timeout,
                sqlx::query_scalar::<_, String>(parent_verify_query)
                    .bind(parent_id)
                    .bind(&user_id)
                    .fetch_optional(&db),
            )
            .await
            {
                Ok(Ok(Some(_))) => true,
                Ok(Ok(None)) => false,
                Ok(Err(e)) => {
                    tracing::error!("Database error while verifying parent group: {:?}", e);
                    return Err(AppError::from(e));
                }
                Err(elapsed) => {
                    tracing::error!("Timeout while verifying parent group: {:?}", elapsed);
                    return Err(AppError::Database(anyhow::anyhow!(
                        "Database query timeout after {:?}",
                        update_timeout
                    )));
                }
            };

            if !parent_exists {
                tracing::warn!("Parent group {} not found for user {}", parent_id, email);
                return Err(AppError::NotFound(format!(
                    "Parent group '{}' not found",
                    parent_id
                )));
            }
        }
    }

    // Update the group
    let update_query = r#"
        UPDATE groups 
        SET name = $2, 
            description = $3, 
            category = $4, 
            icon = $5, 
            parent_id = $6,
            updated_at = CURRENT_TIMESTAMP 
        WHERE id = $1 AND user_id = $7 
        RETURNING *
    "#;

    let updated_group = match tokio::time::timeout(
        update_timeout,
        sqlx::query_as::<_, Group>(update_query)
            .bind(&group_id)
            .bind(&payload.name)
            .bind(&payload.description)
            .bind(&payload.category)
            .bind(&payload.icon)
            .bind(&payload.parent_id)
            .bind(&user_id)
            .fetch_one(&db),
    )
    .await
    {
        Ok(Ok(group)) => {
            tracing::info!("Successfully updated group {} for user {}", group_id, email);
            group
        }
        Ok(Err(e)) => {
            tracing::error!("Database error while updating group {}: {:?}", group_id, e);
            return Err(AppError::from(e));
        }
        Err(elapsed) => {
            tracing::error!("Timeout while updating group {}: {:?}", group_id, elapsed);
            return Err(AppError::Database(anyhow::anyhow!(
                "Database query timeout after {:?}",
                update_timeout
            )));
        }
    };

    Ok(Json(CreateGroupResponse {
        success: true,
        message: "Group updated successfully".to_string(),
        data: updated_group,
    }))
}
