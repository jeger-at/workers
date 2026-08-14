use security_scan::{
    build_analysis_plan, AnalysisConfigV1, RunRecordV1, RunStatusV1, ScanModeV1,
    ANALYSIS_READ_FUNCTIONS,
};

fn analysis_config() -> AnalysisConfigV1 {
    AnalysisConfigV1 {
        model: "security-review-model".into(),
        provider: Some("router".into()),
        max_turns: 4,
        max_output_tokens: 8_000,
        max_total_tokens: 50_000,
        max_cost_usd: Some(2.0),
    }
}

fn queued_run() -> RunRecordV1 {
    RunRecordV1 {
        schema_version: "1".into(),
        run_id: "sec_0123456789abcdef01234567".into(),
        repository: "iii-hq/iii".into(),
        target_sha: "0123456789abcdef0123456789abcdef01234567".into(),
        mode: ScanModeV1::Suggest,
        operation_nonce: "private_nonce".into(),
        status: RunStatusV1::Queued,
        attempt: 1,
        step: 0,
        step_failures: 0,
        materialized: None,
        harness: None,
        report: None,
        error: None,
        created_at: 1,
        updated_at: 1,
        completed_at: None,
    }
}

#[test]
fn analysis_plan_is_scoped_to_an_isolated_worktree_and_read_only_functions() {
    let plan = build_analysis_plan(
        &queued_run(),
        "/private/tmp/wt_security_scan",
        &analysis_config(),
    );

    assert_eq!(plan.filesystem_root, "/private/tmp/wt_security_scan");
    assert_eq!(plan.allowed_functions, ANALYSIS_READ_FUNCTIONS);
    assert!(plan.allowed_functions.iter().all(|function| {
        !function.starts_with("shell::")
            && !function.contains("create")
            && !function.contains("update")
            && !function.contains("delete")
            && !function.contains("move")
    }));
    assert!(plan.system_prompt.contains("untrusted review data"));
    assert!(plan.system_prompt.contains("Never execute repository code"));
    assert!(plan.output_schema.get("properties").is_some());
    assert_eq!(plan.model, "security-review-model");
    assert_eq!(plan.max_turns, 4);
    assert_eq!(plan.max_total_tokens, 50_000);
}

#[test]
fn analysis_plan_is_deterministic_for_queue_redelivery() {
    let run = queued_run();
    let first = build_analysis_plan(&run, "/private/tmp/wt_security_scan", &analysis_config());
    let second = build_analysis_plan(&run, "/private/tmp/wt_security_scan", &analysis_config());

    assert_eq!(first.session_id, second.session_id);
    assert_eq!(first.idempotency_key, second.idempotency_key);
    assert_eq!(first.idempotency_key, "private_nonce:attempt:1:analysis");

    let mut retry = run;
    retry.attempt = 2;
    let retried = build_analysis_plan(&retry, "/private/tmp/wt_security_scan", &analysis_config());
    assert_ne!(first.session_id, retried.session_id);
    assert_ne!(first.idempotency_key, retried.idempotency_key);
}
