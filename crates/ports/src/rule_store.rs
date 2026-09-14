use crate::RuleError;
use async_trait::async_trait;
use model::Rule;

#[async_trait]
pub trait RuleStore: Send + Sync {
    async fn load_all(&self) -> Result<Vec<Rule>, RuleError>;
    async fn reload(&self) -> Result<(), RuleError>;
    fn count(&self) -> usize;
}
