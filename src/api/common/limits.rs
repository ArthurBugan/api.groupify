use crate::errors::AppError;

#[derive(Debug, sqlx::FromRow)]
pub struct PlanLimits {
    max_channels: i32,
    max_groups: i32,
    can_create_subgroups: bool,
}

#[derive(Debug)]
pub struct UsageCounts {
    channels_total: i64,
    groups_total: i64,
    channels_in_group: i64,
}

pub async fn get_active_plan_limits(db: &sqlx::PgPool, user_id: &str) -> Result<PlanLimits, AppError> {
    let plan = sqlx::query_as::<_, PlanLimits>(
        r#"SELECT sp.max_channels, sp.max_groups, sp.can_create_subgroups
           FROM subscription_plans_users spu
           INNER JOIN subscription_plans sp ON sp.id = spu.subscription_plan_id
           WHERE spu.user_id = $1
             AND (spu.ended_at IS NULL OR spu.ended_at > CURRENT_TIMESTAMP)
           ORDER BY spu.started_at DESC
           LIMIT 1"#
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to fetch subscription plan limits")))?;

    match plan {
        Some(p) => Ok(p),
        None => Err(AppError::NotFound("No active subscription plan found".to_string())),
    }
}

pub async fn get_usage_counts(db: &sqlx::PgPool, user_id: &str, group_id: &str) -> Result<UsageCounts, AppError> {
    let channels_total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM channels WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to count channels")))?;

    let channels_in_group = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM channels WHERE user_id = $1 AND group_id = $2")
        .bind(user_id)
        .bind(group_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to count channels in group")))?;

    let groups_total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM groups WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to count groups")))?;

    tracing::info!("Channels total: {}, channels in group: {}, groups total: {}", channels_total, channels_in_group, groups_total);
    Ok(UsageCounts { channels_total, groups_total, channels_in_group })
}

pub async fn enforce_channel_addition_limit(
    db: &sqlx::PgPool,
    user_id: &str,
    group_id: &str,
    incoming_count: i64,
) -> Result<(), AppError> {
    let plan = get_active_plan_limits(db, user_id).await?;
    let usage = get_usage_counts(db, user_id, group_id).await?;

    let remaining_channels = (plan.max_channels as i64) - usage.channels_in_group;
    tracing::info!("Remaining channels: {}, incoming count: {}", remaining_channels, incoming_count);
    if incoming_count > remaining_channels {
        return Err(AppError::Permission(anyhow::anyhow!(format!(
            "Channel limit exceeded: attempting to add {}, remaining {}",
            incoming_count, remaining_channels
        ))));
    }

    if usage.groups_total > plan.max_groups as i64 {
        return Err(AppError::Permission(anyhow::anyhow!("Group limit exceeded for current plan")));
    }

    Ok(())
}

pub async fn enforce_group_creation_limit(
    db: &sqlx::PgPool,
    user_id: &str,
    is_subgroup: bool,
) -> Result<(), AppError> {
    let plan = get_active_plan_limits(db, user_id).await?;

    if is_subgroup && !plan.can_create_subgroups {
        return Err(AppError::Permission(anyhow::anyhow!(
            "Current plan does not allow creating subgroups"
        )));
    }

    let groups_total = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM groups WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(db)
        .await
        .map_err(|e| AppError::Database(anyhow::Error::from(e).context("Failed to count groups")))?;

    if groups_total >= plan.max_groups as i64 {
        return Err(AppError::Permission(anyhow::anyhow!(
            "Group limit exceeded for current plan: used {} of {}",
            groups_total,
            plan.max_groups
        )));
    }

    Ok(())
}