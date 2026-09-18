use crate::RuleError;
use model::Rule;

pub trait RuleStore: Send + Sync {
    fn load_all(&self) -> Result<Vec<Rule>, RuleError>;
    fn reload(&self) -> Result<(), RuleError>;
    fn count(&self) -> usize;
}
