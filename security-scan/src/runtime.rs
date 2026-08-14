use async_trait::async_trait;

use crate::{EnqueueRequest, RunRecordV1, SecurityScanError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateRunOutcome {
    Created,
    Existing(Box<RunRecordV1>),
}

#[async_trait]
pub trait SecurityRuntime: Send + Sync {
    async fn get_run(&self, run_id: &str) -> Result<Option<RunRecordV1>, SecurityScanError>;

    async fn create_run_if_absent(
        &self,
        run: RunRecordV1,
    ) -> Result<CreateRunOutcome, SecurityScanError>;

    async fn replace_run(
        &self,
        expected: &RunRecordV1,
        replacement: RunRecordV1,
    ) -> Result<bool, SecurityScanError>;

    async fn delete_run_if_unchanged(&self, run: &RunRecordV1) -> Result<(), SecurityScanError>;

    async fn enqueue_execute(&self, request: EnqueueRequest) -> Result<(), SecurityScanError>;
}
