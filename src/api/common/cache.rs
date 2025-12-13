use deadpool_redis::{Pool as RedisPool};
use deadpool_redis::redis::AsyncCommands;

#[derive(Clone, Debug)]
pub struct RedisCache {
    pub pool: RedisPool,
}

impl RedisCache {
    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> anyhow::Result<Option<T>> {
        let mut conn = self.pool.get().await?;
        let v: Option<String> = conn.get(key).await?;
        Ok(match v { Some(s) => Some(serde_json::from_str(&s)?), None => None })
    }

    pub async fn set_json<T: serde::Serialize>(&self, key: &str, value: &T, ttl_secs: u64) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let s = serde_json::to_string(value)?;
        conn.set_ex::<_, _, ()>(key, s, ttl_secs).await?;
        Ok(())
    }

    pub async fn del(&self, key: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        conn.del::<_, ()>(key).await?;
        Ok(())
    }

    pub async fn del_pattern(&self, pattern: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let keys: Vec<String> = conn.keys(pattern).await?;
        if !keys.is_empty() {
            conn.del::<_, ()>(keys).await?;
        }
        Ok(())
    }
}