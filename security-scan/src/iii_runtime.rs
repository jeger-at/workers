use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use iii_sdk::protocol::TriggerRequest;
use iii_sdk::{IIIClient, TriggerAction};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    AnalysisHandle, AnalysisPlan, CreateRunOutcome, EnqueueRequest, ExecutionRuntime,
    MaterializedTargetV1, RepositoryConfigV1, RunRecordV1, RunStatusV1, SecurityRuntime,
    SecurityScanError,
};

pub const RUN_SCOPE: &str = "security_scan_runs";
pub const RUN_QUEUE: &str = "security-scan-run";
const STATE_PREFIX: &str = "security-scan";
const STATE_GET_ID: &str = "security-scan::state::get";
const STATE_LIST_ID: &str = "security-scan::state::list";
const STATE_CAS_ID: &str = "security-scan::state::compare-and-set";
const CLAIM_NAMESPACE_ID: &str = "state::claim-namespace";
const EXECUTE_ID: &str = "security-scan::execute";
const RPC_TIMEOUT_MS: u64 = 30_000;
const BOOT_ATTEMPTS: u32 = 20;
const BOOT_RETRY_MS: u64 = 250;

#[derive(Clone)]
pub struct IiiRuntime {
    iii: Arc<IIIClient>,
}

impl IiiRuntime {
    pub fn new(iii: Arc<IIIClient>) -> Self {
        Self { iii }
    }

    pub async fn claim_private_state(&self) -> Result<(), SecurityScanError> {
        self.retry_boot_call(CLAIM_NAMESPACE_ID, || {
            self.call(
                CLAIM_NAMESPACE_ID,
                json!({
                    "functions_prefix": STATE_PREFIX,
                    "scopes": [RUN_SCOPE],
                }),
                None,
                Some(5_000),
            )
        })
        .await
        .map(|_| ())
    }

    pub async fn ensure_queue(&self) -> Result<(), SecurityScanError> {
        let definition = queue_definition();
        self.retry_boot_call("queue::define", || {
            self.call("queue::define", definition.clone(), None, Some(5_000))
        })
        .await
        .map(|_| ())
    }

    pub async fn list_runs(&self) -> Result<Vec<RunRecordV1>, SecurityScanError> {
        let value = self
            .call_private(STATE_LIST_ID, json!({ "scope": RUN_SCOPE }))
            .await?;
        parse_list(&value)
    }

    pub async fn recover_queueable_runs(&self) -> Result<usize, SecurityScanError> {
        let mut recovered = 0;
        for run in self.list_runs().await? {
            if matches!(
                run.status,
                RunStatusV1::Queued
                    | RunStatusV1::Materializing
                    | RunStatusV1::Materialized
                    | RunStatusV1::Dispatching
            ) {
                self.enqueue_execute(EnqueueRequest::new(
                    run.run_id,
                    run.repository,
                    run.attempt,
                    run.step,
                ))
                .await?;
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    async fn retry_boot_call<F, Fut>(
        &self,
        dependency: &str,
        mut call: F,
    ) -> Result<Value, SecurityScanError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<Value, SecurityScanError>>,
    {
        let mut last_error = None;
        for attempt in 1..=BOOT_ATTEMPTS {
            match call().await {
                Ok(value) => return Ok(value),
                Err(error) => {
                    last_error = Some(error);
                    if attempt < BOOT_ATTEMPTS {
                        tokio::time::sleep(Duration::from_millis(BOOT_RETRY_MS)).await;
                    }
                }
            }
        }
        Err(SecurityScanError::Dependency(format!(
            "{dependency} failed after {BOOT_ATTEMPTS} attempts: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unknown error".into())
        )))
    }

    async fn call_private(
        &self,
        function_id: &str,
        payload: Value,
    ) -> Result<Value, SecurityScanError> {
        match self
            .call(function_id, payload.clone(), None, Some(RPC_TIMEOUT_MS))
            .await
        {
            Err(error) if accessor_is_missing(&error) => {
                self.claim_private_state().await?;
                self.call(function_id, payload, None, Some(RPC_TIMEOUT_MS))
                    .await
            }
            result => result,
        }
    }

    async fn call(
        &self,
        function_id: &str,
        payload: Value,
        action: Option<TriggerAction>,
        timeout_ms: Option<u64>,
    ) -> Result<Value, SecurityScanError> {
        self.iii
            .trigger(TriggerRequest {
                function_id: function_id.into(),
                payload,
                action,
                timeout_ms,
            })
            .await
            .map_err(|error| {
                SecurityScanError::Dependency(format!("{function_id} failed: {error}"))
            })
    }

    async fn compare_and_set(
        &self,
        key: &str,
        expected: Option<Value>,
        value: Value,
    ) -> Result<CasOutcome, SecurityScanError> {
        let mut payload = json!({
            "scope": RUN_SCOPE,
            "key": key,
            "value": value,
        });
        if let Some(expected) = expected {
            payload["expected"] = expected;
        }
        let response = self.call_private(STATE_CAS_ID, payload).await?;
        let swapped = response
            .get("swapped")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                SecurityScanError::Dependency(format!(
                    "{STATE_CAS_ID} returned no boolean `swapped` field"
                ))
            })?;
        Ok(if swapped {
            CasOutcome::Swapped
        } else {
            CasOutcome::Current(response.get("current").cloned().unwrap_or(Value::Null))
        })
    }
}

#[async_trait]
impl SecurityRuntime for IiiRuntime {
    async fn get_run(&self, run_id: &str) -> Result<Option<RunRecordV1>, SecurityScanError> {
        let value = self
            .call_private(STATE_GET_ID, json!({ "scope": RUN_SCOPE, "key": run_id }))
            .await?;
        parse_optional_run(value, run_id)
    }

    async fn create_run_if_absent(
        &self,
        run: RunRecordV1,
    ) -> Result<CreateRunOutcome, SecurityScanError> {
        let value = serialize(&run, "run record")?;
        match self.compare_and_set(&run.run_id, None, value).await? {
            CasOutcome::Swapped => Ok(CreateRunOutcome::Created),
            CasOutcome::Current(current) => {
                let existing = parse_run(current, &run.run_id)?;
                if existing.run_id != run.run_id
                    || existing.repository != run.repository
                    || existing.target_sha != run.target_sha
                    || existing.mode != run.mode
                    || existing.schema_version != run.schema_version
                {
                    return Err(SecurityScanError::Dependency(format!(
                        "state collision or corruption for run {}",
                        run.run_id
                    )));
                }
                Ok(CreateRunOutcome::Existing(Box::new(existing)))
            }
        }
    }

    async fn replace_run(
        &self,
        expected: &RunRecordV1,
        replacement: RunRecordV1,
    ) -> Result<bool, SecurityScanError> {
        if expected.run_id != replacement.run_id
            || expected.repository != replacement.repository
            || expected.target_sha != replacement.target_sha
            || expected.mode != replacement.mode
        {
            return Err(SecurityScanError::Dependency(
                "run replacement changed immutable identity fields".into(),
            ));
        }
        let expected_value = serialize(expected, "expected run record")?;
        let replacement_value = serialize(&replacement, "replacement run record")?;
        Ok(matches!(
            self.compare_and_set(&expected.run_id, Some(expected_value), replacement_value,)
                .await?,
            CasOutcome::Swapped
        ))
    }

    async fn delete_run_if_unchanged(&self, run: &RunRecordV1) -> Result<(), SecurityScanError> {
        let expected = serialize(run, "run record")?;
        let _ = self
            .compare_and_set(&run.run_id, Some(expected), Value::Null)
            .await?;
        Ok(())
    }

    async fn enqueue_execute(&self, request: EnqueueRequest) -> Result<(), SecurityScanError> {
        self.call(
            EXECUTE_ID,
            serialize(&request, "queue request")?,
            Some(TriggerAction::Enqueue {
                queue: RUN_QUEUE.into(),
            }),
            None,
        )
        .await
        .map(|_| ())
    }
}

#[async_trait]
impl ExecutionRuntime for IiiRuntime {
    async fn get_run_by_session(
        &self,
        session_id: &str,
    ) -> Result<Option<RunRecordV1>, SecurityScanError> {
        let mut matches = self.list_runs().await?.into_iter().filter(|run| {
            run.harness
                .as_ref()
                .is_some_and(|harness| harness.session_id == session_id)
        });
        let found = matches.next();
        if matches.next().is_some() {
            return Err(SecurityScanError::Dependency(format!(
                "multiple runs reference Harness session {session_id}"
            )));
        }
        Ok(found)
    }

    async fn materialize_target(
        &self,
        repository: &RepositoryConfigV1,
        run: &RunRecordV1,
    ) -> Result<MaterializedTargetV1, SecurityScanError> {
        let session_id = materialization_session_id(run);
        let existing = self
            .call(
                "worktree::list",
                json!({
                    "repo_path": repository.path,
                    "session_id": session_id,
                    "include_status": false,
                }),
                None,
                Some(RPC_TIMEOUT_MS),
            )
            .await?;
        let mut worktrees = serde_json::from_value::<WorktreeListWire>(existing)
            .map_err(|error| dependency_parse("worktree::list", error))?
            .worktrees;
        if worktrees.len() > 1 {
            return Err(SecurityScanError::Dependency(format!(
                "worktree::list returned multiple checkouts for {session_id}"
            )));
        }
        if let Some(worktree) = worktrees.pop() {
            match worktree.lifecycle.as_str() {
                "orphaned" => {
                    let removed = self
                        .call(
                            "worktree::remove",
                            json!({
                                "worktree_id": worktree.worktree_id,
                                "force": false,
                                "delete_branch": true,
                            }),
                            None,
                            Some(RPC_TIMEOUT_MS),
                        )
                        .await?;
                    if removed.get("removed").and_then(Value::as_bool) != Some(true) {
                        return Err(SecurityScanError::Dependency(
                            "worktree::remove did not clear an orphaned scanner checkout".into(),
                        ));
                    }
                }
                "active" | "claimed" => {
                    return materialized_from_existing(worktree, repository, run)
                }
                lifecycle => {
                    return Err(SecurityScanError::Dependency(format!(
                        "scanner checkout {} has unexpected lifecycle {lifecycle}",
                        worktree.worktree_id
                    )))
                }
            }
        }

        let created = self
            .call(
                "worktree::create",
                json!({
                    "repo_path": repository.path,
                    "base_ref": run.target_sha,
                    "session_id": session_id,
                    "copy_ignored": false,
                }),
                None,
                Some(RPC_TIMEOUT_MS),
            )
            .await?;
        let worktree: WorktreeCreateWire = serde_json::from_value(created)
            .map_err(|error| dependency_parse("worktree::create", error))?;
        materialized_from_created(worktree, run)
    }

    async fn cleanup_target(&self, target: &MaterializedTargetV1) -> Result<(), SecurityScanError> {
        let response = match self
            .call(
                "worktree::remove",
                json!({
                    "worktree_id": target.worktree_id,
                    "force": false,
                    "delete_branch": true,
                }),
                None,
                Some(RPC_TIMEOUT_MS),
            )
            .await
        {
            Ok(response) => response,
            Err(error) if worktree_is_missing(&error) => return Ok(()),
            Err(error) => return Err(error),
        };
        if response.get("removed").and_then(Value::as_bool) != Some(true) {
            return Err(SecurityScanError::Dependency(format!(
                "worktree::remove did not remove scanner checkout {}",
                target.worktree_id
            )));
        }
        if response.get("branch_deleted").and_then(Value::as_bool) != Some(true) {
            tracing::warn!(
                worktree_id = %target.worktree_id,
                "scanner checkout was removed but its branch was not deleted"
            );
        }
        Ok(())
    }

    async fn start_analysis(
        &self,
        plan: AnalysisPlan,
    ) -> Result<AnalysisHandle, SecurityScanError> {
        let existing = self
            .call(
                "harness::status",
                json!({ "session_id": plan.session_id }),
                None,
                Some(RPC_TIMEOUT_MS),
            )
            .await?;
        if !existing.is_null() {
            let status: HarnessStatusWire = serde_json::from_value(existing)
                .map_err(|error| dependency_parse("harness::status", error))?;
            if let Some(turn_id) = status.turn_id {
                return Ok(AnalysisHandle {
                    session_id: plan.session_id,
                    turn_id,
                });
            }
        }
        let request = harness_request(&plan);
        let response = self
            .call("harness::send", request, None, Some(RPC_TIMEOUT_MS))
            .await?;
        let response: HarnessSendWire = serde_json::from_value(response)
            .map_err(|error| dependency_parse("harness::send", error))?;
        if !response.accepted {
            return Err(SecurityScanError::Dependency(
                "harness::send did not accept the analysis turn".into(),
            ));
        }
        Ok(AnalysisHandle {
            session_id: response.session_id,
            turn_id: response.turn_id,
        })
    }

    async fn completed_analysis(
        &self,
        run: &RunRecordV1,
    ) -> Result<Option<crate::TurnCompletedEventV1>, SecurityScanError> {
        let harness = run.harness.as_ref().ok_or_else(|| {
            SecurityScanError::Dependency(format!(
                "analyzing run {} has no Harness checkpoint",
                run.run_id
            ))
        })?;
        let response = self
            .call(
                "harness::status",
                json!({ "session_id": harness.session_id }),
                None,
                Some(RPC_TIMEOUT_MS),
            )
            .await?;
        if response.is_null() {
            return Ok(None);
        }
        let status: HarnessStatusWire = serde_json::from_value(response)
            .map_err(|error| dependency_parse("harness::status", error))?;
        completion_event(status, harness)
    }
}

#[derive(Debug)]
enum CasOutcome {
    Swapped,
    Current(Value),
}

#[derive(Debug, Deserialize)]
struct WorktreeListWire {
    #[serde(default)]
    worktrees: Vec<WorktreeWire>,
}

#[derive(Debug, Deserialize)]
struct WorktreeWire {
    worktree_id: String,
    repo_path: String,
    path: String,
    base_sha: String,
    lifecycle: String,
}

#[derive(Debug, Deserialize)]
struct WorktreeCreateWire {
    worktree_id: String,
    path: String,
    base_sha: String,
}

#[derive(Debug, Deserialize)]
struct HarnessSendWire {
    session_id: String,
    turn_id: String,
    accepted: bool,
}

#[derive(Debug, Deserialize)]
struct HarnessStatusWire {
    #[serde(default)]
    turn_id: Option<String>,
    status: String,
    #[serde(default)]
    expects_wake: bool,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    result_error: Option<String>,
}

fn materialization_session_id(run: &RunRecordV1) -> String {
    format!(
        "security-scan-worktree-{}-attempt-{}",
        run.operation_nonce, run.attempt
    )
}

fn materialized_from_existing(
    worktree: WorktreeWire,
    repository: &RepositoryConfigV1,
    run: &RunRecordV1,
) -> Result<MaterializedTargetV1, SecurityScanError> {
    if worktree.repo_path != repository.path {
        return Err(SecurityScanError::Dependency(format!(
            "recovered worktree {} belongs to an unexpected repository",
            worktree.worktree_id
        )));
    }
    materialized(worktree.worktree_id, worktree.path, worktree.base_sha, run)
}

fn materialized_from_created(
    worktree: WorktreeCreateWire,
    run: &RunRecordV1,
) -> Result<MaterializedTargetV1, SecurityScanError> {
    materialized(worktree.worktree_id, worktree.path, worktree.base_sha, run)
}

fn materialized(
    worktree_id: String,
    path: String,
    base_sha: String,
    run: &RunRecordV1,
) -> Result<MaterializedTargetV1, SecurityScanError> {
    if !base_sha.eq_ignore_ascii_case(&run.target_sha) {
        return Err(SecurityScanError::Dependency(format!(
            "worktree resolved {} instead of requested {}",
            base_sha, run.target_sha
        )));
    }
    Ok(MaterializedTargetV1 {
        worktree_id,
        path,
        base_sha,
    })
}

fn harness_request(plan: &AnalysisPlan) -> Value {
    json!({
        "session_id": plan.session_id,
        "message": plan.message,
        "model": plan.model,
        "provider": plan.provider,
        "idempotency_key": plan.idempotency_key,
        "session": {
            "title": "Security review",
            "metadata": { "security_scan": true },
        },
        "options": {
            "system_prompt": plan.system_prompt,
            "system_prompt_strategy": "override",
            "mode": "agent",
            "max_turns": plan.max_turns,
            "max_output_tokens": plan.max_output_tokens,
            "max_total_tokens": plan.max_total_tokens,
            "max_cost_usd": plan.max_cost_usd,
            "output": {
                "type": "json",
                "schema": plan.output_schema,
            },
            "functions": {
                "allow": plan.allowed_functions,
                "deny": [
                    "shell::*",
                    "state::*",
                    "queue::*",
                    "worktree::*",
                    "harness::*",
                    "github::*",
                    "approval::*",
                    "configuration::*",
                    "storage::*",
                    "database::*",
                    "security-scan::*",
                ],
                "expose": "agent_trigger",
            },
            "metadata": {
                "fs_scope": { "root": plan.filesystem_root },
            },
        },
    })
}

fn completion_event(
    status: HarnessStatusWire,
    harness: &crate::HarnessRunV1,
) -> Result<Option<crate::TurnCompletedEventV1>, SecurityScanError> {
    if status.turn_id.as_deref() != Some(harness.turn_id.as_str()) {
        return Ok(None);
    }
    if status.expects_wake || matches!(status.status.as_str(), "running" | "awaiting_functions") {
        return Ok(None);
    }
    if !matches!(status.status.as_str(), "completed" | "cancelled" | "failed") {
        return Err(SecurityScanError::Dependency(format!(
            "harness::status returned unknown status {}",
            status.status
        )));
    }
    Ok(Some(crate::TurnCompletedEventV1 {
        session_id: harness.session_id.clone(),
        turn_id: harness.turn_id.clone(),
        status: status.status,
        terminal: true,
        result: status.result,
        result_error: status.result_error,
        reason: None,
    }))
}

fn queue_definition() -> Value {
    json!({
        "queue": RUN_QUEUE,
        "config": {
            "type": "fifo",
            "message_group_field": "repository",
            "concurrency": 4,
            "max_retries": 3,
            "backoff_ms": 1_000,
            "poll_interval_ms": 100,
            "redeliver_on_engine_restart": true,
        },
    })
}

fn serialize<T: serde::Serialize>(value: &T, label: &str) -> Result<Value, SecurityScanError> {
    serde_json::to_value(value).map_err(|error| {
        SecurityScanError::Dependency(format!("could not serialize {label}: {error}"))
    })
}

fn parse_optional_run(
    value: Value,
    run_id: &str,
) -> Result<Option<RunRecordV1>, SecurityScanError> {
    if value.is_null() {
        return Ok(None);
    }
    parse_run(value, run_id).map(Some)
}

fn parse_run(value: Value, run_id: &str) -> Result<RunRecordV1, SecurityScanError> {
    serde_json::from_value(value).map_err(|error| {
        SecurityScanError::Dependency(format!(
            "could not parse private state record {run_id}: {error}"
        ))
    })
}

fn parse_list(value: &Value) -> Result<Vec<RunRecordV1>, SecurityScanError> {
    let candidates: Vec<&Value> = match value {
        Value::Array(values) => values.iter().collect(),
        Value::Object(map) => {
            if let Some(Value::Array(values)) = map.get("values").or_else(|| map.get("items")) {
                values.iter().collect()
            } else {
                map.values().collect()
            }
        }
        Value::Null => Vec::new(),
        _ => {
            return Err(SecurityScanError::Dependency(
                "private state list returned an unsupported shape".into(),
            ))
        }
    };
    let mut records = Vec::new();
    for value in candidates {
        if value.is_null() {
            continue;
        }
        records.push(serde_json::from_value(value.clone()).map_err(|error| {
            SecurityScanError::Dependency(format!(
                "could not parse private state list record: {error}"
            ))
        })?);
    }
    Ok(records)
}

fn dependency_parse(dependency: &str, error: serde_json::Error) -> SecurityScanError {
    SecurityScanError::Dependency(format!("could not parse {dependency} response: {error}"))
}

fn accessor_is_missing(error: &SecurityScanError) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("function_not_found") || message.contains("not found")
}

fn worktree_is_missing(error: &SecurityScanError) -> bool {
    error.to_string().contains("W200")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AnalysisConfigV1, ScanModeV1};

    #[test]
    fn run_queue_uses_the_existing_durable_fifo_worker() {
        let definition = queue_definition();
        assert_eq!(definition["queue"], RUN_QUEUE);
        assert_eq!(definition["config"]["type"], "fifo");
        assert_eq!(definition["config"]["message_group_field"], "repository");
        assert_eq!(definition["config"]["redeliver_on_engine_restart"], true);
    }

    #[test]
    fn harness_request_is_read_only_and_scoped_to_the_materialized_checkout() {
        let run = RunRecordV1 {
            schema_version: "1".into(),
            run_id: "sec_123".into(),
            repository: "repo".into(),
            target_sha: "a".repeat(40),
            mode: ScanModeV1::Scan,
            operation_nonce: "private_nonce".into(),
            status: RunStatusV1::Materialized,
            attempt: 1,
            step: 1,
            step_failures: 0,
            materialized: None,
            harness: None,
            report: None,
            error: None,
            created_at: 1,
            updated_at: 1,
            completed_at: None,
        };
        let plan = crate::build_analysis_plan(
            &run,
            "/isolated/repo",
            &AnalysisConfigV1 {
                model: "model".into(),
                provider: None,
                max_turns: 4,
                max_output_tokens: 8_000,
                max_total_tokens: 50_000,
                max_cost_usd: Some(2.0),
            },
        );
        let request = harness_request(&plan);
        assert_eq!(
            request["options"]["metadata"]["fs_scope"]["root"],
            "/isolated/repo"
        );
        assert_eq!(request["options"]["mode"], "agent");
        assert_eq!(request["options"]["output"]["type"], "json");
        let allow = request["options"]["functions"]["allow"]
            .as_array()
            .expect("allow array");
        assert!(allow
            .iter()
            .all(|value| !value.as_str().unwrap_or_default().contains("shell")));
        assert!(allow
            .iter()
            .all(|value| !value.as_str().unwrap_or_default().contains("create-file")));
        assert_eq!(request["options"]["system_prompt_strategy"], "override");
    }

    #[test]
    fn private_state_list_parser_accepts_supported_worker_shapes() {
        let record = json!({
            "schema_version": "1",
            "run_id": "sec_x",
            "repository": "repo",
            "target_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "mode": "scan",
            "operation_nonce": "private_nonce",
            "status": "queued",
            "attempt": 1,
            "step": 0,
            "created_at": 1,
            "updated_at": 1
        });
        assert_eq!(parse_list(&json!([record.clone()])).unwrap().len(), 1);
        assert_eq!(
            parse_list(&json!({ "values": [record.clone()] }))
                .unwrap()
                .len(),
            1
        );
        assert_eq!(parse_list(&json!({ "sec_x": record })).unwrap().len(), 1);
    }

    #[test]
    fn harness_status_reconciliation_ignores_running_and_recovers_terminal_results() {
        let harness = crate::HarnessRunV1 {
            session_id: "s1".into(),
            turn_id: "t1".into(),
        };
        assert!(completion_event(
            HarnessStatusWire {
                turn_id: Some("t1".into()),
                status: "running".into(),
                expects_wake: false,
                result: None,
                result_error: None,
            },
            &harness,
        )
        .unwrap()
        .is_none());

        let completed = completion_event(
            HarnessStatusWire {
                turn_id: Some("t1".into()),
                status: "completed".into(),
                expects_wake: false,
                result: Some(json!({ "summary": "ok", "findings": [] })),
                result_error: None,
            },
            &harness,
        )
        .unwrap()
        .expect("terminal event");
        assert!(completed.terminal);
        assert_eq!(completed.status, "completed");
    }

    #[test]
    fn missing_worktree_record_is_an_idempotent_cleanup_success() {
        assert!(worktree_is_missing(&SecurityScanError::Dependency(
            "worktree::remove failed: W200 no record".into()
        )));
        assert!(!worktree_is_missing(&SecurityScanError::Dependency(
            "worktree::remove failed: W300 state unavailable".into()
        )));
    }

    #[test]
    fn materialization_identity_is_attempt_scoped() {
        let mut run = RunRecordV1 {
            schema_version: "1".into(),
            run_id: "sec_retry".into(),
            repository: "repo".into(),
            target_sha: "a".repeat(40),
            mode: ScanModeV1::Scan,
            operation_nonce: "private_nonce".into(),
            status: RunStatusV1::Queued,
            attempt: 2,
            step: 0,
            step_failures: 0,
            materialized: None,
            harness: None,
            report: None,
            error: None,
            created_at: 1,
            updated_at: 1,
            completed_at: None,
        };
        assert_eq!(
            materialization_session_id(&run),
            "security-scan-worktree-private_nonce-attempt-2"
        );
        run.attempt = 3;
        assert_ne!(
            materialization_session_id(&run),
            "security-scan-worktree-private_nonce-attempt-2"
        );
    }
}
