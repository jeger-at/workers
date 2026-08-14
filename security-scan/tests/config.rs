use security_scan::{AnalysisConfigV1, RepositoryConfigV1, SecurityScanError, WorkerConfig};

fn valid_config() -> WorkerConfig {
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
    }
}

#[test]
fn config_fails_closed_without_an_operator_model() {
    let mut config = valid_config();
    config.analysis.model.clear();

    let error = config.validate().unwrap_err();
    assert!(matches!(error, SecurityScanError::InvalidRequest(_)));
}

#[test]
fn config_rejects_duplicate_repository_ids_and_relative_paths() {
    let mut duplicate = valid_config();
    duplicate
        .repositories
        .push(duplicate.repositories[0].clone());
    assert!(duplicate.validate().is_err());

    let mut relative = valid_config();
    relative.repositories[0].path = "repos/iii".into();
    assert!(relative.validate().is_err());
}

#[test]
fn valid_operator_config_is_accepted() {
    valid_config().validate().unwrap();
}

#[test]
fn empty_registry_defaults_boot_in_an_idle_fail_closed_state() {
    let mut config = valid_config();
    config.repositories.clear();
    config.analysis.model.clear();

    config.validate().unwrap();
}
