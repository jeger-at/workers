use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use async_trait::async_trait;
use security_scan::{
    AnalysisConfigV1, CreateRunOutcome, EnqueueRequest, RepositoryConfigV1, RunErrorV1,
    RunRecordV1, RunStatusV1, ScanModeV1, SecurityRuntime, SecurityScanError,
    SecurityScanReadRequestV1, SecurityScanRequestV1, SecurityScanService, WorkerConfig,
};
use tokio::sync::Mutex;

#[test]
fn typed_inputs_accept_engine_metadata_without_loosening_unknown_field_checks() {
    let request: SecurityScanRequestV1 = serde_json::from_value(serde_json::json!({
        "repository": "iii-hq/iii",
        "target_sha": "0123456789abcdef0123456789abcdef01234567",
        "mode": "scan",
        "_caller_worker_id": "console"
    }))
    .unwrap();
    assert_eq!(request.repository, "iii-hq/iii");

    let read: SecurityScanReadRequestV1 = serde_json::from_value(serde_json::json!({
        "run_id": "sec_x",
        "_caller_worker_id": "console"
    }))
    .unwrap();
    assert_eq!(read.run_id, "sec_x");

    let execute: EnqueueRequest = serde_json::from_value(serde_json::json!({
        "run_id": "sec_x",
        "repository": "iii-hq/iii",
        "attempt": 1,
        "step": 0,
        "_caller_worker_id": "queue"
    }))
    .unwrap();
    assert_eq!(execute.step, 0);

    assert!(
        serde_json::from_value::<SecurityScanRequestV1>(serde_json::json!({
            "repository": "iii-hq/iii",
            "target_sha": "0123456789abcdef0123456789abcdef01234567",
            "mode": "scan",
            "unexpected": true
        }))
        .is_err()
    );

    let schema = serde_json::to_value(schemars::schema_for!(SecurityScanRequestV1)).unwrap();
    assert!(schema["properties"].get("_caller_worker_id").is_none());
}

#[derive(Default)]
struct FakeRuntime {
    run: Mutex<Option<RunRecordV1>>,
    enqueued: Mutex<Vec<EnqueueRequest>>,
    fail_enqueue_once: AtomicBool,
}

fn service(runtime: Arc<FakeRuntime>) -> SecurityScanService<FakeRuntime> {
    SecurityScanService::new(
        runtime,
        WorkerConfig {
            repositories: vec![RepositoryConfigV1 {
                id: "iii-hq/iii".into(),
                path: "/srv/repos/iii".into(),
            }],
            analysis: AnalysisConfigV1 {
                model: "security-review-model".into(),
                provider: None,
                max_turns: 4,
                max_output_tokens: 8_000,
                max_total_tokens: 50_000,
                max_cost_usd: Some(2.0),
            },
        },
    )
}

#[async_trait]
impl SecurityRuntime for FakeRuntime {
    async fn get_run(&self, _run_id: &str) -> Result<Option<RunRecordV1>, SecurityScanError> {
        Ok(self.run.lock().await.clone())
    }

    async fn create_run_if_absent(
        &self,
        run: RunRecordV1,
    ) -> Result<CreateRunOutcome, SecurityScanError> {
        let mut stored = self.run.lock().await;
        if let Some(existing) = stored.clone() {
            return Ok(CreateRunOutcome::Existing(Box::new(existing)));
        }
        *stored = Some(run);
        Ok(CreateRunOutcome::Created)
    }

    async fn replace_run(
        &self,
        expected: &RunRecordV1,
        replacement: RunRecordV1,
    ) -> Result<bool, SecurityScanError> {
        let mut stored = self.run.lock().await;
        if stored.as_ref() != Some(expected) {
            return Ok(false);
        }
        *stored = Some(replacement);
        Ok(true)
    }

    async fn delete_run_if_unchanged(&self, run: &RunRecordV1) -> Result<(), SecurityScanError> {
        let mut stored = self.run.lock().await;
        if stored.as_ref() == Some(run) {
            *stored = None;
        }
        Ok(())
    }

    async fn enqueue_execute(&self, request: EnqueueRequest) -> Result<(), SecurityScanError> {
        if self.fail_enqueue_once.swap(false, Ordering::SeqCst) {
            return Err(SecurityScanError::Dependency("queue unavailable".into()));
        }
        self.enqueued.lock().await.push(request);
        Ok(())
    }
}

#[tokio::test]
async fn duplicate_manual_request_returns_the_same_run_and_enqueues_once() {
    let runtime = Arc::new(FakeRuntime::default());
    let service = service(runtime.clone());
    let request = SecurityScanRequestV1::new(
        "iii-hq/iii".into(),
        "0123456789abcdef0123456789abcdef01234567".into(),
        ScanModeV1::Suggest,
    );

    let first = service.request(request.clone()).await.unwrap();
    let second = service.request(request).await.unwrap();

    assert_eq!(first.run_id, second.run_id);
    assert!(!first.deduplicated);
    assert!(second.deduplicated);
    let enqueued = runtime.enqueued.lock().await;
    assert_eq!(enqueued.len(), 1);
    assert_eq!(enqueued[0].attempt, 1);
    assert_eq!(enqueued[0].step, 0);
}

#[tokio::test]
async fn request_rejects_a_symbolic_ref_instead_of_persisting_a_mutable_target() {
    let runtime = Arc::new(FakeRuntime::default());
    let service = service(runtime.clone());

    let error = service
        .request(SecurityScanRequestV1::new(
            "iii-hq/iii".into(),
            "main".into(),
            ScanModeV1::Scan,
        ))
        .await
        .unwrap_err();

    assert!(matches!(error, SecurityScanError::InvalidRequest(_)));
    assert!(runtime.run.lock().await.is_none());
    assert!(runtime.enqueued.lock().await.is_empty());
}

#[tokio::test]
async fn request_rejects_a_repository_that_is_not_operator_configured() {
    let runtime = Arc::new(FakeRuntime::default());
    let service = service(runtime.clone());

    let error = service
        .request(SecurityScanRequestV1::new(
            "attacker/untrusted".into(),
            "0123456789abcdef0123456789abcdef01234567".into(),
            ScanModeV1::Scan,
        ))
        .await
        .unwrap_err();

    assert!(matches!(error, SecurityScanError::InvalidRequest(_)));
    assert!(runtime.run.lock().await.is_none());
    assert!(runtime.enqueued.lock().await.is_empty());
}

#[tokio::test]
async fn enqueue_failure_keeps_a_durable_outbox_checkpoint_for_recovery() {
    let runtime = Arc::new(FakeRuntime::default());
    runtime.fail_enqueue_once.store(true, Ordering::SeqCst);
    let service = service(runtime.clone());
    let request = SecurityScanRequestV1::new(
        "iii-hq/iii".into(),
        "0123456789abcdef0123456789abcdef01234567".into(),
        ScanModeV1::Scan,
    );

    let error = service.request(request.clone()).await.unwrap_err();
    assert!(matches!(error, SecurityScanError::Dependency(_)));
    let stored = runtime
        .run
        .lock()
        .await
        .clone()
        .expect("durable queued run");
    assert_eq!(stored.status, RunStatusV1::Queued);

    let recovered = service.request(request).await.unwrap();
    assert!(recovered.deduplicated);
    assert!(runtime.enqueued.lock().await.is_empty());
}

#[tokio::test]
async fn read_returns_a_sanitized_public_run_without_internal_paths_or_session_ids() {
    let runtime = Arc::new(FakeRuntime::default());
    let service = service(runtime);
    let requested = service
        .request(SecurityScanRequestV1::new(
            "iii-hq/iii".into(),
            "0123456789abcdef0123456789abcdef01234567".into(),
            ScanModeV1::Suggest,
        ))
        .await
        .unwrap();

    let response = service
        .read(SecurityScanReadRequestV1::new(requested.run_id))
        .await
        .unwrap();

    let run = response.run.unwrap();
    assert_eq!(run.repository, "iii-hq/iii");
    assert_eq!(run.status, security_scan::RunStatusV1::Queued);
    let encoded = serde_json::to_value(run).unwrap();
    assert!(encoded.get("materialized").is_none());
    assert!(encoded.get("harness").is_none());
    assert!(encoded.get("operation_nonce").is_none());
}

#[tokio::test]
async fn repeating_a_retryable_failed_request_atomically_starts_a_new_attempt() {
    let runtime = Arc::new(FakeRuntime::default());
    let service = service(runtime.clone());
    let request = SecurityScanRequestV1::new(
        "iii-hq/iii".into(),
        "0123456789abcdef0123456789abcdef01234567".into(),
        ScanModeV1::Suggest,
    );
    let first = service.request(request.clone()).await.unwrap();
    {
        let mut stored = runtime.run.lock().await;
        let run = stored.as_mut().unwrap();
        run.status = RunStatusV1::Failed;
        run.error = Some(RunErrorV1 {
            code: "analysis_failed".into(),
            message: "temporary dependency failure".into(),
            retryable: true,
        });
        run.completed_at = Some(run.updated_at);
    }
    runtime.enqueued.lock().await.clear();

    let retry = service.request(request).await.unwrap();

    assert_eq!(retry.run_id, first.run_id);
    assert_eq!(retry.status, RunStatusV1::Queued);
    assert!(!retry.deduplicated);
    let stored = runtime.run.lock().await.clone().unwrap();
    assert_eq!(stored.attempt, 2);
    assert_eq!(stored.step, 0);
    assert!(stored.error.is_none());
    let enqueued = runtime.enqueued.lock().await;
    assert_eq!(enqueued.len(), 1);
    assert_eq!(enqueued[0].attempt, 2);
}
