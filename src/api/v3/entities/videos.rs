//! `SeaORM` Entity for videos

use sea_orm::entity::prelude::*;

#[sea_orm::model]
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "videos")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    #[sea_orm(column_type = "Text")]
    pub channel_id: String,
    #[sea_orm(column_type = "Text")]
    pub group_id: String,
    #[sea_orm(column_type = "Text")]
    pub user_id: String,
    #[sea_orm(column_type = "Text")]
    pub title: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub description: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub thumbnail: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub url: Option<String>,
    pub published_at: Option<DateTime>,
    #[sea_orm(column_type = "Text")]
    pub content_type: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub external_id: Option<String>,
    pub duration_seconds: Option<i32>,
    pub views_count: Option<i32>,
    pub created_at: Option<DateTime>,
    pub updated_at: Option<DateTime>,
}

impl ActiveModelBehavior for ActiveModel {}
