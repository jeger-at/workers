use std::sync::Arc;

use crate::{
    ids, CreateRunOutcome, EnqueueRequest, RunRecordV1, RunStatusV1, SecurityRuntime,
    SecurityScanError, SecurityScanReadRequestV1, SecurityScanReadResponseV1,
    SecurityScanRequestV1, SecurityScanResponseV1, WorkerConfig,
};

pub struct SecurityScanService<R> {
    runtime: Arc<R>,
    config: WorkerConfig,
}

impl<R> SecurityScanService<R>
where
    R: SecurityRuntime,
{
    pub fn new(runtime: Arc<R>, config: WorkerConfig) -> Self {
        Self { runtime, config }
    }

    pub fn configured_repository_count(&self) -> usize {
        self.config.repositories.len()
    }

    pub async fn request(
        &self,
        request: SecurityScanRequestV1,
    ) -> Result<SecurityScanResponseV1, SecurityScanError> {
        let request = request.normalize()?;
        if self.config.repository(&request.repository).is_none() {
            return Err(SecurityScanError::InvalidRequest(format!(
                "repository {} is not configured",
                request.repository
            )));
        }
        let now = ids::now_ms();
        let run = RunRecordV1 {
            schema_version: "1".into(),
            run_id: ids::run_id(&request),
            repository: request.repository,
            target_sha: request.target_sha,
            mode: request.mode,
            operation_nonce: ids::operation_nonce(),
            status: RunStatusV1::Queued,
            attempt: 1,
            step: 0,
            step_failures: 0,
            materialized: None,
            harness: None,
            report: None,
            error: None,
            created_at: now,
            updated_at: now,
            completed_at: None,
        };

        match self.runtime.create_run_if_absent(run.clone()).await? {
            CreateRunOutcome::Created => {
                self.enqueue(&run).await?;
                Ok(scan_response(run, false))
            }
            CreateRunOutcome::Existing(existing)
                if existing.status == RunStatusV1::Failed
                    && existing.error.as_ref().is_some_and(|error| error.retryable)
                    && existing.materialized.is_none() =>
            {
                let mut retried = (*existing).clone();
                retried.status = RunStatusV1::Queued;
                retried.operation_nonce = ids::operation_nonce();
                retried.attempt = retried.attempt.checked_add(1).ok_or_else(|| {
                    SecurityScanError::Dependency("security scan attempt overflow".into())
                })?;
                retried.step = 0;
                retried.step_failures = 0;
                retried.harness = None;
                retried.report = None;
                retried.error = None;
                retried.completed_at = None;
                retried.updated_at = now;
                if !self.runtime.replace_run(&existing, retried.clone()).await? {
                    let current =
                        self.runtime
                            .get_run(&retried.run_id)
                            .await?
                            .ok_or_else(|| {
                                SecurityScanError::Dependency(format!(
                                    "run {} disappeared during retry",
                                    retried.run_id
                                ))
                            })?;
                    return Ok(scan_response(current, true));
                }
                self.enqueue(&retried).await?;
                Ok(scan_response(retried, false))
            }
            CreateRunOutcome::Existing(existing) => Ok(scan_response(*existing, true)),
        }
    }

    async fn enqueue(&self, run: &RunRecordV1) -> Result<(), SecurityScanError> {
        self.runtime
            .enqueue_execute(EnqueueRequest::new(
                run.run_id.clone(),
                run.repository.clone(),
                run.attempt,
                run.step,
            ))
            .await
    }

    pub async fn read(
        &self,
        request: SecurityScanReadRequestV1,
    ) -> Result<SecurityScanReadResponseV1, SecurityScanError> {
        if request.run_id.trim().is_empty() {
            return Err(SecurityScanError::InvalidRequest(
                "run_id cannot be empty".into(),
            ));
        }
        Ok(SecurityScanReadResponseV1 {
            run: self
                .runtime
                .get_run(&request.run_id)
                .await?
                .as_ref()
                .map(Into::into),
        })
    }
}

fn scan_response(run: RunRecordV1, deduplicated: bool) -> SecurityScanResponseV1 {
    SecurityScanResponseV1 {
        run_id: run.run_id,
        status: run.status,
        deduplicated,
    }
}
