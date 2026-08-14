use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SecurityScanError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanModeV1 {
    Scan,
    Suggest,
}

impl ScanModeV1 {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Suggest => "suggest",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityScanRequestV1 {
    pub repository: String,
    pub target_sha: String,
    pub mode: ScanModeV1,
    /// Metadata injected by the iii engine. It is accepted on the wire but is
    /// not part of the public function schema or the request identity.
    #[serde(rename = "_caller_worker_id", default, skip_serializing)]
    #[schemars(skip)]
    _caller_worker_id: Option<String>,
}

impl SecurityScanRequestV1 {
    pub fn new(repository: String, target_sha: String, mode: ScanModeV1) -> Self {
        Self {
            repository,
            target_sha,
            mode,
            _caller_worker_id: None,
        }
    }

    pub(crate) fn normalize(mut self) -> Result<Self, SecurityScanError> {
        if self.target_sha.len() != 40
            || !self.target_sha.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SecurityScanError::InvalidRequest(
                "target_sha must be an immutable 40-character Git commit SHA".into(),
            ));
        }
        self.target_sha.make_ascii_lowercase();
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunStatusV1 {
    Queued,
    Materializing,
    Materialized,
    Dispatching,
    Analyzing,
    Completed,
    Failed,
    Cancelling,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterializedTargetV1 {
    pub worktree_id: String,
    pub path: String,
    pub base_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HarnessRunV1 {
    pub session_id: String,
    pub turn_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunErrorV1 {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunRecordV1 {
    pub schema_version: String,
    pub run_id: String,
    pub repository: String,
    pub target_sha: String,
    pub mode: ScanModeV1,
    /// Opaque private identity for dependency sessions. This field is not
    /// included in the public run projection.
    pub operation_nonce: String,
    pub status: RunStatusV1,
    pub attempt: u32,
    pub step: u64,
    #[serde(default)]
    pub step_failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialized: Option<MaterializedTargetV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<HarnessRunV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<SecurityReportV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RunErrorV1>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityScanResponseV1 {
    pub run_id: String,
    pub status: RunStatusV1,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityScanReadRequestV1 {
    pub run_id: String,
    #[serde(rename = "_caller_worker_id", default, skip_serializing)]
    #[schemars(skip)]
    _caller_worker_id: Option<String>,
}

impl SecurityScanReadRequestV1 {
    pub fn new(run_id: String) -> Self {
        Self {
            run_id,
            _caller_worker_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PublicRunV1 {
    pub schema_version: String,
    pub run_id: String,
    pub repository: String,
    pub target_sha: String,
    pub mode: ScanModeV1,
    pub status: RunStatusV1,
    pub attempt: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<SecurityReportV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RunErrorV1>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
}

impl From<&RunRecordV1> for PublicRunV1 {
    fn from(run: &RunRecordV1) -> Self {
        Self {
            schema_version: run.schema_version.clone(),
            run_id: run.run_id.clone(),
            repository: run.repository.clone(),
            target_sha: run.target_sha.clone(),
            mode: run.mode,
            status: run.status,
            attempt: run.attempt,
            report: run.report.clone(),
            error: run.error.clone(),
            created_at: run.created_at,
            updated_at: run.updated_at,
            completed_at: run.completed_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityScanReadResponseV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<PublicRunV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SeverityV1 {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingLocationV1 {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityFindingV1 {
    pub rule_id: String,
    pub severity: SeverityV1,
    pub title: String,
    pub description: String,
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocationV1>,
    pub remediation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_patch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityReportV1 {
    pub summary: String,
    pub findings: Vec<SecurityFindingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnqueueRequest {
    pub run_id: String,
    pub repository: String,
    pub attempt: u32,
    pub step: u64,
    #[serde(rename = "_caller_worker_id", default, skip_serializing)]
    #[schemars(skip)]
    _caller_worker_id: Option<String>,
}

impl EnqueueRequest {
    pub fn new(run_id: String, repository: String, attempt: u32, step: u64) -> Self {
        Self {
            run_id,
            repository,
            attempt,
            step,
            _caller_worker_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecuteResponseV1 {
    pub skipped: bool,
    pub status: RunStatusV1,
    pub step: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
pub struct TurnCompletedEventV1 {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub turn_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub terminal: bool,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub result_error: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TurnCompletedResponseV1 {
    pub woke: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<RunStatusV1>,
}
