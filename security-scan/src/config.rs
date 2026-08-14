use std::{collections::HashSet, path::Path};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::SecurityScanError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryConfigV1 {
    pub id: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalysisConfigV1 {
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub max_turns: u32,
    pub max_output_tokens: u64,
    pub max_total_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_usd: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfig {
    pub repositories: Vec<RepositoryConfigV1>,
    pub analysis: AnalysisConfigV1,
}

impl WorkerConfig {
    pub fn validate(&self) -> Result<(), SecurityScanError> {
        let mut ids = HashSet::new();
        for repository in &self.repositories {
            if repository.id.trim().is_empty() {
                return Err(invalid("repository id cannot be empty"));
            }
            if !ids.insert(repository.id.as_str()) {
                return Err(invalid(format!(
                    "repository id {} is configured more than once",
                    repository.id
                )));
            }
            if !Path::new(&repository.path).is_absolute() {
                return Err(invalid(format!(
                    "repository {} path must be absolute",
                    repository.id
                )));
            }
        }
        if !self.repositories.is_empty() && self.analysis.model.trim().is_empty() {
            return Err(invalid("analysis.model cannot be empty"));
        }
        if self
            .analysis
            .provider
            .as_ref()
            .is_some_and(|provider| provider.trim().is_empty())
        {
            return Err(invalid("analysis.provider cannot be empty when set"));
        }
        if !(1..=10).contains(&self.analysis.max_turns) {
            return Err(invalid("analysis.max_turns must be between 1 and 10"));
        }
        if self.analysis.max_output_tokens == 0 {
            return Err(invalid("analysis.max_output_tokens must be positive"));
        }
        if self.analysis.max_total_tokens < self.analysis.max_output_tokens {
            return Err(invalid(
                "analysis.max_total_tokens must be at least max_output_tokens",
            ));
        }
        if self
            .analysis
            .max_cost_usd
            .is_some_and(|cost| !cost.is_finite() || cost <= 0.0)
        {
            return Err(invalid(
                "analysis.max_cost_usd must be finite and positive when set",
            ));
        }
        Ok(())
    }

    pub(crate) fn repository(&self, id: &str) -> Option<&RepositoryConfigV1> {
        self.repositories
            .iter()
            .find(|repository| repository.id == id)
    }
}

fn invalid(message: impl Into<String>) -> SecurityScanError {
    SecurityScanError::InvalidRequest(message.into())
}
