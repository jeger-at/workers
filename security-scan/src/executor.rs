use std::{path::Component, sync::Arc};

use async_trait::async_trait;

use crate::{
    build_analysis_plan, ids, AnalysisPlan, EnqueueRequest, ExecuteResponseV1, HarnessRunV1,
    MaterializedTargetV1, RepositoryConfigV1, RunErrorV1, RunRecordV1, RunStatusV1,
    SecurityReportV1, SecurityRuntime, SecurityScanError, TurnCompletedEventV1,
    TurnCompletedResponseV1, WorkerConfig,
};

const MAX_STEP_FAILURES: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisHandle {
    pub session_id: String,
    pub turn_id: String,
}

#[async_trait]
pub trait ExecutionRuntime: SecurityRuntime {
    async fn get_run_by_session(
        &self,
        session_id: &str,
    ) -> Result<Option<RunRecordV1>, SecurityScanError>;

    async fn materialize_target(
        &self,
        repository: &RepositoryConfigV1,
        run: &RunRecordV1,
    ) -> Result<MaterializedTargetV1, SecurityScanError>;

    async fn cleanup_target(
        &self,
        _target: &MaterializedTargetV1,
    ) -> Result<(), SecurityScanError> {
        Ok(())
    }

    async fn start_analysis(&self, plan: AnalysisPlan)
        -> Result<AnalysisHandle, SecurityScanError>;

    async fn completed_analysis(
        &self,
        _run: &RunRecordV1,
    ) -> Result<Option<TurnCompletedEventV1>, SecurityScanError> {
        Ok(None)
    }
}

pub struct SecurityScanExecutor<R> {
    runtime: Arc<R>,
    config: WorkerConfig,
}

impl<R> SecurityScanExecutor<R>
where
    R: ExecutionRuntime,
{
    pub fn new(runtime: Arc<R>, config: WorkerConfig) -> Self {
        Self { runtime, config }
    }

    pub async fn execute(
        &self,
        request: EnqueueRequest,
    ) -> Result<ExecuteResponseV1, SecurityScanError> {
        match self.execute_inner(&request).await {
            Ok(response) => Ok(response),
            Err(error) => match self.record_step_failure(&request, &error).await? {
                Some(response) => Ok(response),
                None => Err(error),
            },
        }
    }

    async fn execute_inner(
        &self,
        request: &EnqueueRequest,
    ) -> Result<ExecuteResponseV1, SecurityScanError> {
        let Some(run) = self.runtime.get_run(&request.run_id).await? else {
            return Err(SecurityScanError::InvalidRequest(format!(
                "unknown run {}",
                request.run_id
            )));
        };
        if run.repository != request.repository
            || run.attempt != request.attempt
            || request.step > run.step
        {
            return Ok(response(&run, true));
        }
        match run.status {
            RunStatusV1::Queued | RunStatusV1::Materializing => self.materialize(run).await,
            RunStatusV1::Materialized | RunStatusV1::Dispatching => self.start_analysis(run).await,
            RunStatusV1::Analyzing => {
                let woke = self.reconcile_analysis(&run).await?;
                if woke {
                    let current =
                        self.runtime
                            .get_run(&request.run_id)
                            .await?
                            .ok_or_else(|| {
                                SecurityScanError::Dependency(format!(
                                    "run {} disappeared during reconciliation",
                                    request.run_id
                                ))
                            })?;
                    Ok(response(&current, false))
                } else {
                    Ok(response(&run, true))
                }
            }
            RunStatusV1::Completed
            | RunStatusV1::Failed
            | RunStatusV1::Cancelling
            | RunStatusV1::Cancelled => Ok(response(&run, true)),
        }
    }

    async fn record_step_failure(
        &self,
        request: &EnqueueRequest,
        error: &SecurityScanError,
    ) -> Result<Option<ExecuteResponseV1>, SecurityScanError> {
        let Some(run) = self.runtime.get_run(&request.run_id).await? else {
            return Ok(None);
        };
        if run.repository != request.repository
            || run.attempt != request.attempt
            || request.step > run.step
            || !matches!(
                run.status,
                RunStatusV1::Queued
                    | RunStatusV1::Materializing
                    | RunStatusV1::Materialized
                    | RunStatusV1::Dispatching
            )
        {
            return Ok(Some(response(&run, true)));
        }

        let mut failed = run.clone();
        failed.step_failures = failed.step_failures.saturating_add(1);
        failed.updated_at = ids::now_ms();
        let terminal = matches!(error, SecurityScanError::InvalidRequest(_))
            || failed.step_failures >= MAX_STEP_FAILURES;
        if terminal {
            failed.status = RunStatusV1::Failed;
            failed.completed_at = Some(failed.updated_at);
        }
        let stage = if run.step == 0 {
            "target materialization"
        } else {
            "analysis dispatch"
        };
        failed.error = Some(RunErrorV1 {
            code: if terminal {
                "step_failed".into()
            } else {
                "step_retrying".into()
            },
            message: format!("{stage} failed; dependency details are available in worker logs"),
            retryable: !matches!(error, SecurityScanError::InvalidRequest(_)),
        });
        if !self.runtime.replace_run(&run, failed.clone()).await? {
            return Ok(None);
        }
        if terminal {
            if let Err(cleanup_error) = self.cleanup_terminal(&failed).await {
                tracing::warn!(
                    run_id = %failed.run_id,
                    error = %cleanup_error,
                    "failed run checkout cleanup failed"
                );
            }
        }
        Ok(terminal.then(|| response(&failed, false)))
    }

    pub async fn on_turn_completed(
        &self,
        event: TurnCompletedEventV1,
    ) -> Result<TurnCompletedResponseV1, SecurityScanError> {
        if !event.terminal {
            return Ok(TurnCompletedResponseV1 {
                woke: false,
                status: None,
            });
        }
        let Some(run) = self.runtime.get_run_by_session(&event.session_id).await? else {
            return Ok(TurnCompletedResponseV1 {
                woke: false,
                status: None,
            });
        };
        if run.status != RunStatusV1::Analyzing
            || run
                .harness
                .as_ref()
                .is_none_or(|harness| harness.turn_id != event.turn_id)
        {
            return Ok(TurnCompletedResponseV1 {
                woke: false,
                status: Some(run.status),
            });
        }

        // A trigger event is only a wake-up signal. Read the terminal result
        // back from Harness so a forged or duplicated callback cannot inject
        // a report into the durable run record.
        let Some(authoritative) = self.runtime.completed_analysis(&run).await? else {
            return Ok(TurnCompletedResponseV1 {
                woke: false,
                status: Some(run.status),
            });
        };
        self.finish_analysis(run, authoritative).await
    }

    async fn finish_analysis(
        &self,
        run: RunRecordV1,
        event: TurnCompletedEventV1,
    ) -> Result<TurnCompletedResponseV1, SecurityScanError> {
        if !event.terminal
            || run.harness.as_ref().is_none_or(|harness| {
                harness.session_id != event.session_id || harness.turn_id != event.turn_id
            })
        {
            return Ok(TurnCompletedResponseV1 {
                woke: false,
                status: Some(run.status),
            });
        }

        let now = ids::now_ms();
        let mut finished = run.clone();
        finished.completed_at = Some(now);
        finished.updated_at = now;
        if event.status == "completed" {
            match event
                .result
                .ok_or_else(|| "Harness completed without a result".to_string())
                .and_then(|value| {
                    serde_json::from_value::<SecurityReportV1>(value)
                        .map_err(|error| format!("invalid security report: {error}"))
                })
                .and_then(|report| validate_report(report, &run))
            {
                Ok(report) => {
                    finished.status = RunStatusV1::Completed;
                    finished.report = Some(report);
                    finished.error = None;
                }
                Err(message) => {
                    finished.status = RunStatusV1::Failed;
                    finished.error = Some(RunErrorV1 {
                        code: "invalid_report".into(),
                        message,
                        retryable: true,
                    });
                }
            }
        } else if event.status == "cancelled" {
            finished.status = RunStatusV1::Cancelled;
            finished.error = None;
        } else {
            finished.status = RunStatusV1::Failed;
            finished.error = Some(RunErrorV1 {
                code: "analysis_failed".into(),
                message: sanitize_failure_message(
                    &run,
                    event.result_error.or(event.reason).unwrap_or_else(|| {
                        format!("Harness turn ended with status {}", event.status)
                    }),
                ),
                retryable: true,
            });
        }

        if !self.runtime.replace_run(&run, finished.clone()).await? {
            return Ok(TurnCompletedResponseV1 {
                woke: false,
                status: Some(run.status),
            });
        }
        if let Err(error) = self.cleanup_terminal(&finished).await {
            tracing::warn!(run_id = %finished.run_id, %error, "terminal checkout cleanup failed");
        }
        Ok(TurnCompletedResponseV1 {
            woke: true,
            status: Some(finished.status),
        })
    }

    pub async fn reconcile_analysis(&self, run: &RunRecordV1) -> Result<bool, SecurityScanError> {
        if run.status != RunStatusV1::Analyzing {
            return Ok(false);
        }
        let Some(event) = self.runtime.completed_analysis(run).await? else {
            return Ok(false);
        };
        Ok(self.finish_analysis(run.clone(), event).await?.woke)
    }

    pub async fn cleanup_terminal(&self, run: &RunRecordV1) -> Result<bool, SecurityScanError> {
        if !matches!(
            run.status,
            RunStatusV1::Completed | RunStatusV1::Failed | RunStatusV1::Cancelled
        ) {
            return Ok(false);
        }
        let Some(target) = run.materialized.as_ref() else {
            return Ok(false);
        };
        self.runtime.cleanup_target(target).await?;
        let mut cleaned = run.clone();
        cleaned.materialized = None;
        cleaned.updated_at = ids::now_ms();
        self.runtime.replace_run(run, cleaned).await
    }

    async fn materialize(
        &self,
        mut run: RunRecordV1,
    ) -> Result<ExecuteResponseV1, SecurityScanError> {
        if run.status == RunStatusV1::Queued {
            let mut claimed = run.clone();
            claimed.status = RunStatusV1::Materializing;
            claimed.updated_at = ids::now_ms();
            if !self.runtime.replace_run(&run, claimed.clone()).await? {
                return Ok(response(&run, true));
            }
            run = claimed;
        } else if run.status != RunStatusV1::Materializing {
            return Ok(response(&run, true));
        }

        let repository = self.config.repository(&run.repository).ok_or_else(|| {
            SecurityScanError::InvalidRequest(format!(
                "repository {} is no longer configured",
                run.repository
            ))
        })?;
        let target = self.runtime.materialize_target(repository, &run).await?;
        if !target.base_sha.eq_ignore_ascii_case(&run.target_sha) {
            return Err(SecurityScanError::Dependency(format!(
                "materialized commit {} does not match requested {}",
                target.base_sha, run.target_sha
            )));
        }

        let mut materialized = run.clone();
        materialized.status = RunStatusV1::Materialized;
        materialized.step = 1;
        materialized.step_failures = 0;
        materialized.materialized = Some(target);
        materialized.updated_at = ids::now_ms();
        if !self.runtime.replace_run(&run, materialized.clone()).await? {
            return Ok(response(&run, true));
        }
        self.runtime
            .enqueue_execute(EnqueueRequest::new(
                materialized.run_id.clone(),
                materialized.repository.clone(),
                materialized.attempt,
                materialized.step,
            ))
            .await?;
        Ok(response(&materialized, false))
    }

    async fn start_analysis(
        &self,
        mut run: RunRecordV1,
    ) -> Result<ExecuteResponseV1, SecurityScanError> {
        if run.status == RunStatusV1::Materialized {
            let mut claimed = run.clone();
            claimed.status = RunStatusV1::Dispatching;
            claimed.updated_at = ids::now_ms();
            if !self.runtime.replace_run(&run, claimed.clone()).await? {
                return Ok(response(&run, true));
            }
            run = claimed;
        } else if run.status != RunStatusV1::Dispatching {
            return Ok(response(&run, true));
        }
        let target = run.materialized.as_ref().ok_or_else(|| {
            SecurityScanError::Dependency(format!(
                "run {} is materialized without a target checkpoint",
                run.run_id
            ))
        })?;
        let plan = build_analysis_plan(&run, &target.path, &self.config.analysis);
        let handle = self.runtime.start_analysis(plan).await?;
        let mut analyzing = run.clone();
        analyzing.status = RunStatusV1::Analyzing;
        analyzing.step = 2;
        analyzing.step_failures = 0;
        analyzing.harness = Some(HarnessRunV1 {
            session_id: handle.session_id,
            turn_id: handle.turn_id,
        });
        analyzing.updated_at = ids::now_ms();
        if !self.runtime.replace_run(&run, analyzing.clone()).await? {
            return Ok(response(&run, true));
        }
        self.reconcile_analysis(&analyzing).await?;
        Ok(response(&analyzing, false))
    }
}

fn response(run: &RunRecordV1, skipped: bool) -> ExecuteResponseV1 {
    ExecuteResponseV1 {
        skipped,
        status: run.status,
        step: run.step,
    }
}

fn sanitize_failure_message(run: &RunRecordV1, message: String) -> String {
    let mut sanitized = message;
    if let Some(root) = run
        .materialized
        .as_ref()
        .map(|target| target.path.as_str())
        .filter(|root| !root.is_empty())
    {
        sanitized = sanitized.replace(root, "<checkout>");
    }
    if sanitized.chars().count() > 2_000 {
        sanitized = sanitized.chars().take(2_000).collect();
        sanitized.push('…');
    }
    sanitized
}

fn validate_report(
    mut report: SecurityReportV1,
    run: &RunRecordV1,
) -> Result<SecurityReportV1, String> {
    validate_text("summary", &report.summary, 8_000, true)?;
    if report.findings.len() > 200 {
        return Err("invalid security report: more than 200 findings".into());
    }
    let internal_root = run
        .materialized
        .as_ref()
        .map(|target| target.path.as_str())
        .filter(|path| !path.is_empty());
    reject_internal_root("summary", &report.summary, internal_root)?;
    for (index, finding) in report.findings.iter_mut().enumerate() {
        let prefix = format!("finding {index}");
        validate_text(&format!("{prefix} rule_id"), &finding.rule_id, 256, true)?;
        validate_text(&format!("{prefix} title"), &finding.title, 512, true)?;
        validate_text(
            &format!("{prefix} description"),
            &finding.description,
            16_000,
            true,
        )?;
        validate_text(
            &format!("{prefix} evidence"),
            &finding.evidence,
            16_000,
            true,
        )?;
        validate_text(
            &format!("{prefix} remediation"),
            &finding.remediation,
            16_000,
            true,
        )?;
        for (field, text) in [
            ("rule_id", finding.rule_id.as_str()),
            ("title", finding.title.as_str()),
            ("description", finding.description.as_str()),
            ("evidence", finding.evidence.as_str()),
            ("remediation", finding.remediation.as_str()),
        ] {
            reject_internal_root(&format!("{prefix} {field}"), text, internal_root)?;
        }
        if let Some(location) = &finding.location {
            validate_location(&prefix, location)?;
        }
        if run.mode == crate::ScanModeV1::Scan {
            finding.suggested_patch = None;
        } else if let Some(patch) = &finding.suggested_patch {
            validate_text(&format!("{prefix} suggested_patch"), patch, 64_000, false)?;
            reject_internal_root(&format!("{prefix} suggested_patch"), patch, internal_root)?;
        }
    }
    Ok(report)
}

fn reject_internal_root(
    label: &str,
    value: &str,
    internal_root: Option<&str>,
) -> Result<(), String> {
    if internal_root.is_some_and(|root| value.contains(root)) {
        return Err(format!(
            "invalid security report: {label} exposes the internal checkout root"
        ));
    }
    Ok(())
}

fn reject_secret_material(label: &str, value: &str) -> Result<(), String> {
    const PRIVATE_KEY_MARKERS: [&str; 3] = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ];
    const TOKEN_PREFIXES: [(&str, usize); 10] = [
        ("github_pat_", 20),
        ("ghp_", 20),
        ("gho_", 20),
        ("ghs_", 20),
        ("glpat-", 20),
        ("xoxb-", 20),
        ("sk_live_", 16),
        ("npm_", 20),
        ("AKIA", 16),
        ("ASIA", 16),
    ];

    let has_private_key = PRIVATE_KEY_MARKERS
        .iter()
        .any(|marker| value.contains(marker));
    let has_token = TOKEN_PREFIXES.iter().any(|(prefix, minimum_tail)| {
        value.match_indices(prefix).any(|(index, _)| {
            value[index + prefix.len()..]
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                })
                .count()
                >= *minimum_tail
        })
    });
    if has_private_key || has_token {
        return Err(format!(
            "invalid security report: {label} contains credential-like secret material"
        ));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max_chars: usize, required: bool) -> Result<(), String> {
    if required && value.trim().is_empty() {
        return Err(format!("invalid security report: {label} is empty"));
    }
    if value.chars().count() > max_chars {
        return Err(format!(
            "invalid security report: {label} exceeds {max_chars} characters"
        ));
    }
    if value.contains('\0') {
        return Err(format!("invalid security report: {label} contains NUL"));
    }
    reject_secret_material(label, value)?;
    Ok(())
}

fn validate_location(prefix: &str, location: &crate::FindingLocationV1) -> Result<(), String> {
    validate_text(
        &format!("{prefix} location.path"),
        &location.path,
        4_096,
        true,
    )?;
    let path = std::path::Path::new(&location.path);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "invalid security report: {prefix} location must be a repository-relative path"
        ));
    }
    if location.line_start == Some(0) || location.line_end == Some(0) {
        return Err(format!(
            "invalid security report: {prefix} location lines are one-based"
        ));
    }
    if let (Some(start), Some(end)) = (location.line_start, location.line_end) {
        if end < start {
            return Err(format!(
                "invalid security report: {prefix} location line_end precedes line_start"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use crate::{FindingLocationV1, ScanModeV1, SecurityFindingV1, SeverityV1};

    fn run(mode: ScanModeV1) -> RunRecordV1 {
        RunRecordV1 {
            schema_version: "1".into(),
            run_id: "sec_x".into(),
            repository: "repo".into(),
            target_sha: "a".repeat(40),
            mode,
            operation_nonce: "private_nonce".into(),
            status: RunStatusV1::Analyzing,
            attempt: 1,
            step: 2,
            step_failures: 0,
            materialized: Some(MaterializedTargetV1 {
                worktree_id: "wt_x".into(),
                path: "/private/internal/wt_x".into(),
                base_sha: "a".repeat(40),
            }),
            harness: None,
            report: None,
            error: None,
            created_at: 1,
            updated_at: 1,
            completed_at: None,
        }
    }

    fn report(path: &str) -> SecurityReportV1 {
        SecurityReportV1 {
            summary: "one finding".into(),
            findings: vec![SecurityFindingV1 {
                rule_id: "SEC-1".into(),
                severity: SeverityV1::High,
                title: "Unsafe input".into(),
                description: "Untrusted input reaches a command".into(),
                evidence: "The call is not escaped".into(),
                location: Some(FindingLocationV1 {
                    path: path.into(),
                    line_start: Some(10),
                    line_end: Some(10),
                }),
                remediation: "Use an argv API".into(),
                suggested_patch: Some("diff --git a/src/x.rs b/src/x.rs".into()),
            }],
        }
    }

    #[test]
    fn report_rejects_internal_or_parent_paths() {
        assert!(validate_report(
            report("/private/internal/wt_x/src/x.rs"),
            &run(ScanModeV1::Suggest)
        )
        .is_err());
        assert!(validate_report(report("../outside"), &run(ScanModeV1::Suggest)).is_err());
    }

    #[test]
    fn report_rejects_internal_roots_in_every_public_text_surface() {
        let mut summary = report("src/x.rs");
        summary.summary = "reviewed /private/internal/wt_x".into();
        assert!(validate_report(summary, &run(ScanModeV1::Suggest)).is_err());

        let mut title = report("src/x.rs");
        title.findings[0].title = "leak /private/internal/wt_x".into();
        assert!(validate_report(title, &run(ScanModeV1::Suggest)).is_err());
    }

    #[test]
    fn scan_mode_strips_suggested_patches() {
        let report = validate_report(report("src/x.rs"), &run(ScanModeV1::Scan)).unwrap();
        assert!(report.findings[0].suggested_patch.is_none());
    }

    #[test]
    fn failure_messages_redact_the_internal_checkout_root() {
        let message = sanitize_failure_message(
            &run(ScanModeV1::Scan),
            "could not read /private/internal/wt_x/src/main.rs".into(),
        );
        assert_eq!(message, "could not read <checkout>/src/main.rs");
    }

    #[test]
    fn report_rejects_secret_values_without_echoing_them() {
        let canary = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
        let mut leaked = report("src/x.rs");
        leaked.findings[0].evidence = format!("hard-coded credential: {canary}");

        let error = validate_report(leaked, &run(ScanModeV1::Suggest)).unwrap_err();
        assert!(error.contains("credential-like secret material"));
        assert!(!error.contains(canary));

        let mut path_leak = report("src/x.rs");
        path_leak.findings[0].location.as_mut().unwrap().path = canary.into();
        let error = validate_report(path_leak, &run(ScanModeV1::Suggest)).unwrap_err();
        assert!(error.contains("credential-like secret material"));
        assert!(!error.contains(canary));
    }
}
