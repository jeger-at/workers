//! Read-only repository security alerts. These wrappers deliberately return a
//! small, stable projection of GitHub's REST objects instead of forwarding the
//! raw alert payload (which also contains users, dismissal details, and large
//! advisory/help fields).

use std::time::Duration;

use iii_sdk::errors::Error;
use iii_sdk::{IIIClient, RegisterFunction};
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::argv;
use crate::config::Config;
use crate::configuration::ConfigCell;
use crate::events::{self, CalledEmitter};
use crate::gh::{self, GhError, GhOutcome};

pub const DEPENDABOT_ALERTS_ID: &str = "github::security::dependabot-alerts";
pub const DEPENDABOT_ALERTS_DESC: &str = "List open Dependabot alerts for one repository: { repo: \"owner/name\", limit?, timeout_ms? } -> bounded public alert metadata plus completeness, collected_count, and a sanitized availability classification. limit defaults to 100 and is capped at 500.";

pub const CODE_SCANNING_ALERTS_ID: &str = "github::security::code-scanning-alerts";
pub const CODE_SCANNING_ALERTS_DESC: &str = "List open code-scanning alerts for one repository: { repo: \"owner/name\", limit?, timeout_ms? } -> bounded public alert metadata plus completeness, collected_count, and a sanitized availability classification. limit defaults to 100 and is capped at 500.";

const DEFAULT_ALERT_LIMIT: u16 = 100;
const MAX_ALERT_LIMIT: u16 = 500;
const API_PAGE_SIZE: u16 = 100;

/// Input shared by both read-only repository security functions.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct AlertsRequest {
    /// Target repository in the exact form `owner/name`.
    pub repo: String,
    /// Maximum alerts returned. Defaults to 100; valid range is 1..=500.
    #[schemars(range(min = 1, max = 500))]
    pub limit: Option<u16>,
    /// Per-call timeout in ms, clamped to the configured max_timeout_ms.
    pub timeout_ms: Option<u64>,
}

/// Whether the returned alert list represents the whole open-alert result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CollectionCompleteness {
    Complete,
    Partial,
}

/// Sanitized result classification. This is intentionally finite and never
/// includes `gh` stderr or GitHub's response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AlertAvailability {
    Available,
    AuthenticationRequired,
    PermissionDenied,
    FeatureDisabled,
    RepositoryUnavailable,
    TemporarilyUnavailable,
    ClientUnavailable,
    MalformedResponse,
}

/// Why an otherwise available result is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    RecordLimit,
    OutputLimit,
}

/// Stable, public subset of a Dependabot alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DependabotAlert {
    /// Repository-local Dependabot alert number.
    pub number: u64,
    /// GitHub alert state (this function requests `open`).
    pub state: String,
    /// Advisory severity such as `critical`, `high`, `medium`, or `low`.
    pub severity: String,
    /// Affected package name.
    pub package_name: String,
    /// Package ecosystem, for example `cargo` or `npm`.
    pub ecosystem: String,
    /// Manifest path reported by GitHub.
    pub manifest_path: String,
    /// Dependency scope when GitHub provides one.
    pub dependency_scope: Option<String>,
    /// Dependency relationship when GitHub provides one.
    pub relationship: Option<String>,
    /// GitHub Security Advisory identifier.
    pub ghsa_id: String,
    /// CVE identifier when assigned.
    pub cve_id: Option<String>,
    /// Short advisory summary. The full advisory description is not returned.
    pub advisory_summary: String,
    /// Vulnerable version range.
    pub vulnerable_version_range: String,
    /// First patched package version when known.
    pub first_patched_version: Option<String>,
    /// Public GitHub URL for the alert.
    pub html_url: String,
    /// GitHub creation timestamp.
    pub created_at: String,
    /// GitHub update timestamp.
    pub updated_at: String,
}

/// Stable, public subset of a code-scanning alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeScanningAlert {
    /// Repository-local code-scanning alert number.
    pub number: u64,
    /// GitHub alert state (this function requests `open`).
    pub state: String,
    /// Rule identifier emitted by the scanning tool.
    pub rule_id: String,
    /// Human-readable rule name when provided.
    pub rule_name: Option<String>,
    /// Short rule description. Rule help and code snippets are not returned.
    pub rule_description: String,
    /// Security severity when GitHub provides one.
    pub security_severity: Option<String>,
    /// Tool severity such as `error`, `warning`, or `note`.
    pub severity: String,
    /// Name of the scanning tool.
    pub tool_name: String,
    /// Public GitHub URL for the alert.
    pub html_url: String,
    /// Git ref for the most recent instance when provided.
    pub git_ref: Option<String>,
    /// Commit SHA for the most recent instance when provided.
    pub commit_sha: Option<String>,
    /// Short diagnostic message for the most recent instance.
    pub message: Option<String>,
    /// Repository-relative location path when provided.
    pub path: Option<String>,
    /// First line of the most recent location when provided.
    pub start_line: Option<u64>,
    /// Last line of the most recent location when provided.
    pub end_line: Option<u64>,
    /// GitHub creation timestamp.
    pub created_at: String,
    /// GitHub update timestamp.
    pub updated_at: Option<String>,
}

/// Typed response for `github::security::dependabot-alerts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DependabotAlertsResponse {
    /// Repository that was queried.
    pub repository: String,
    /// Whole-result versus partial-result marker. Never infer a total from a
    /// partial response.
    pub completeness: CollectionCompleteness,
    /// Sanitized API/client availability classification.
    pub availability: AlertAvailability,
    /// Number of alert records actually returned; always equals alerts.len().
    pub collected_count: usize,
    /// Present only when a configured record or output cap caused partial data.
    pub truncation_reason: Option<TruncationReason>,
    /// Bounded normalized open alerts.
    pub alerts: Vec<DependabotAlert>,
}

/// Typed response for `github::security::code-scanning-alerts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct CodeScanningAlertsResponse {
    /// Repository that was queried.
    pub repository: String,
    /// Whole-result versus partial-result marker. Never infer a total from a
    /// partial response.
    pub completeness: CollectionCompleteness,
    /// Sanitized API/client availability classification.
    pub availability: AlertAvailability,
    /// Number of alert records actually returned; always equals alerts.len().
    pub collected_count: usize,
    /// Present only when a configured record or output cap caused partial data.
    pub truncation_reason: Option<TruncationReason>,
    /// Bounded normalized open alerts.
    pub alerts: Vec<CodeScanningAlert>,
    /// Bounded health metadata from the latest code-scanning analysis. This
    /// is queried separately so configuration/upload failures remain visible
    /// even when they produced no open alert.
    pub latest_analysis: LatestCodeScanningAnalysis,
}

/// Latest code-scanning analysis health, without SARIF, rule, or result data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct LatestCodeScanningAnalysis {
    /// Sanitized availability classification for the analysis endpoint.
    pub availability: AlertAvailability,
    /// Scanning tool name when an analysis exists.
    pub tool_name: Option<String>,
    /// Commit SHA analyzed.
    pub commit_sha: Option<String>,
    /// Git ref analyzed.
    pub git_ref: Option<String>,
    /// GitHub analysis creation timestamp.
    pub created_at: Option<String>,
    /// Bounded analysis error text when GitHub reports a configuration or
    /// upload failure.
    pub error: Option<String>,
    /// Bounded analysis warning text when GitHub provides one.
    pub warning: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawDependabotAlert {
    number: u64,
    state: String,
    dependency: RawDependency,
    security_advisory: RawSecurityAdvisory,
    security_vulnerability: RawSecurityVulnerability,
    html_url: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct RawDependency {
    package: RawPackage,
    manifest_path: String,
    scope: Option<String>,
    relationship: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawSecurityAdvisory {
    ghsa_id: String,
    cve_id: Option<String>,
    summary: String,
    severity: String,
}

#[derive(Debug, Deserialize)]
struct RawSecurityVulnerability {
    vulnerable_version_range: String,
    first_patched_version: Option<RawPatchedVersion>,
}

#[derive(Debug, Deserialize)]
struct RawPatchedVersion {
    identifier: String,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningAlert {
    number: u64,
    state: String,
    rule: RawCodeScanningRule,
    tool: RawCodeScanningTool,
    most_recent_instance: Option<RawCodeScanningInstance>,
    html_url: String,
    created_at: String,
    updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningRule {
    id: String,
    name: Option<String>,
    description: String,
    security_severity_level: Option<String>,
    severity: String,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningTool {
    name: String,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningInstance {
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    commit_sha: Option<String>,
    message: Option<RawCodeScanningMessage>,
    location: Option<RawCodeScanningLocation>,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningMessage {
    text: String,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningLocation {
    path: String,
    start_line: Option<u64>,
    end_line: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawCodeScanningAnalysis {
    tool: RawCodeScanningTool,
    commit_sha: Option<String>,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    created_at: Option<String>,
    error: Option<String>,
    warning: Option<String>,
}

struct Collection<T> {
    alerts: Vec<T>,
    completeness: CollectionCompleteness,
    availability: AlertAvailability,
    truncation_reason: Option<TruncationReason>,
}

impl<T> Collection<T> {
    fn complete(alerts: Vec<T>) -> Self {
        Self {
            alerts,
            completeness: CollectionCompleteness::Complete,
            availability: AlertAvailability::Available,
            truncation_reason: None,
        }
    }

    fn partial(
        alerts: Vec<T>,
        availability: AlertAvailability,
        truncation_reason: Option<TruncationReason>,
    ) -> Self {
        Self {
            alerts,
            completeness: CollectionCompleteness::Partial,
            availability,
            truncation_reason,
        }
    }
}

fn code_scanning_args(repo: &str, page: usize) -> Result<Vec<String>, Error> {
    let endpoint = repository_endpoint(repo, "code-scanning/alerts")?;
    let mut args = argv([
        "api",
        endpoint.as_str(),
        "-X",
        "GET",
        "-f",
        "state=open",
        "-f",
        "per_page=100",
    ]);
    args.push("-f".to_string());
    args.push(format!("page={page}"));
    Ok(args)
}

pub fn dependabot_alerts_args(
    request: &AlertsRequest,
    after: Option<&str>,
) -> Result<Vec<String>, Error> {
    dependabot_args(&request.repo, after)
}

fn dependabot_args(repo: &str, after: Option<&str>) -> Result<Vec<String>, Error> {
    let endpoint = repository_endpoint(repo, "dependabot/alerts")?;
    let mut args = argv([
        "api",
        endpoint.as_str(),
        "-X",
        "GET",
        "-f",
        "state=open",
        "-f",
        "per_page=100",
        "--include",
    ]);
    if let Some(after) = after {
        if !valid_cursor(after) {
            return Err(Error::Handler(
                "Dependabot pagination cursor was invalid".to_string(),
            ));
        }
        args.push("-f".to_string());
        args.push(format!("after={after}"));
    }
    Ok(args)
}

pub fn code_scanning_alerts_args(
    request: &AlertsRequest,
    page: usize,
) -> Result<Vec<String>, Error> {
    code_scanning_args(&request.repo, page)
}

pub fn code_scanning_analysis_args(request: &AlertsRequest) -> Result<Vec<String>, Error> {
    let endpoint = repository_endpoint(&request.repo, "code-scanning/analyses")?;
    Ok(argv([
        "api",
        endpoint.as_str(),
        "-X",
        "GET",
        "-f",
        "per_page=1",
    ]))
}

fn repository_endpoint(repo: &str, resource: &str) -> Result<String, Error> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    if parts.next().is_some() || !valid_repo_part(owner) || !valid_repo_part(name) {
        return Err(Error::Handler(
            "repository must be exactly owner/name using letters, digits, '.', '_' or '-'"
                .to_string(),
        ));
    }
    Ok(format!("repos/{owner}/{name}/{resource}"))
}

fn valid_repo_part(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && part
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn alert_limit(requested: Option<u16>) -> Result<usize, Error> {
    let limit = requested.unwrap_or(DEFAULT_ALERT_LIMIT);
    if !(1..=MAX_ALERT_LIMIT).contains(&limit) {
        return Err(Error::Handler(format!(
            "limit must be between 1 and {MAX_ALERT_LIMIT}"
        )));
    }
    Ok(usize::from(limit))
}

enum ParsedPage<T> {
    Alerts(Vec<T>),
    Unavailable(AlertAvailability),
    OutputLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageProgress {
    Continue,
    Complete,
    RecordLimit,
}

fn parse_alert_page<Raw>(outcome: Result<GhOutcome, GhError>) -> ParsedPage<Raw>
where
    Raw: DeserializeOwned,
{
    let out = match outcome {
        Ok(out) => out,
        Err(_) => return ParsedPage::Unavailable(AlertAvailability::ClientUnavailable),
    };

    if out.timed_out {
        return ParsedPage::Unavailable(AlertAvailability::TemporarilyUnavailable);
    }
    if out.exit_code != Some(0) {
        return ParsedPage::Unavailable(classify_api_failure(&out.stderr));
    }
    if out.stdout_truncated {
        return ParsedPage::OutputLimited;
    }

    match serde_json::from_str(out.stdout.trim()) {
        Ok(alerts) => ParsedPage::Alerts(alerts),
        Err(_) => ParsedPage::Unavailable(AlertAvailability::MalformedResponse),
    }
}

fn append_alert_page<Raw, Normalized>(
    collected: &mut Vec<Normalized>,
    page: Vec<Raw>,
    limit: usize,
    normalize: fn(Raw) -> Normalized,
) -> PageProgress {
    let page_len = page.len();
    let remaining = limit.saturating_sub(collected.len());
    let has_more_than_limit = page_len > remaining;
    collected.extend(page.into_iter().take(remaining).map(normalize));
    if has_more_than_limit {
        PageProgress::RecordLimit
    } else if page_len < usize::from(API_PAGE_SIZE) {
        PageProgress::Complete
    } else {
        PageProgress::Continue
    }
}

fn max_alert_pages(limit: usize) -> usize {
    let page_size = usize::from(API_PAGE_SIZE);
    limit.div_ceil(page_size) + 1
}

async fn fetch_numbered_alerts<Raw, Normalized>(
    config: &Config,
    repo: &str,
    limit: usize,
    timeout_ms: Option<u64>,
    normalize: fn(Raw) -> Normalized,
) -> Collection<Normalized>
where
    Raw: DeserializeOwned,
{
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(config.resolve_timeout(timeout_ms));
    let mut collected = Vec::with_capacity(limit.min(usize::from(API_PAGE_SIZE)));

    for page_number in 1..=max_alert_pages(limit) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Collection::partial(collected, AlertAvailability::TemporarilyUnavailable, None);
        }
        let args = match code_scanning_args(repo, page_number) {
            Ok(args) => args,
            Err(_) => {
                return Collection::partial(collected, AlertAvailability::MalformedResponse, None)
            }
        };
        let remaining_ms = remaining.as_millis().min(u128::from(u64::MAX)) as u64;
        let outcome = gh::run(config, &args, None, Some(remaining_ms)).await;
        match parse_alert_page(outcome) {
            ParsedPage::Alerts(page) => {
                match append_alert_page(&mut collected, page, limit, normalize) {
                    PageProgress::Continue => {}
                    PageProgress::Complete => return Collection::complete(collected),
                    PageProgress::RecordLimit => {
                        return Collection::partial(
                            collected,
                            AlertAvailability::Available,
                            Some(TruncationReason::RecordLimit),
                        )
                    }
                }
            }
            ParsedPage::Unavailable(availability) => {
                return Collection::partial(collected, availability, None)
            }
            ParsedPage::OutputLimited => {
                return Collection::partial(
                    collected,
                    AlertAvailability::Available,
                    Some(TruncationReason::OutputLimit),
                )
            }
        }
    }

    Collection::partial(
        collected,
        AlertAvailability::Available,
        Some(TruncationReason::RecordLimit),
    )
}

struct CursorPage<T> {
    alerts: Vec<T>,
    next_after: Option<String>,
}

enum ParsedCursorPage<T> {
    Page(CursorPage<T>),
    Unavailable(AlertAvailability),
    OutputLimited,
}

fn parse_dependabot_page<Raw>(outcome: Result<GhOutcome, GhError>) -> ParsedCursorPage<Raw>
where
    Raw: DeserializeOwned,
{
    let out = match outcome {
        Ok(out) => out,
        Err(_) => return ParsedCursorPage::Unavailable(AlertAvailability::ClientUnavailable),
    };
    if out.timed_out {
        return ParsedCursorPage::Unavailable(AlertAvailability::TemporarilyUnavailable);
    }
    if out.exit_code != Some(0) {
        return ParsedCursorPage::Unavailable(classify_api_failure(&out.stderr));
    }
    if out.stdout_truncated {
        return ParsedCursorPage::OutputLimited;
    }
    let Some((headers, body)) = split_included_response(&out.stdout) else {
        return ParsedCursorPage::Unavailable(AlertAvailability::MalformedResponse);
    };
    let next_after = match next_after_cursor(headers) {
        Ok(cursor) => cursor,
        Err(()) => {
            return ParsedCursorPage::Unavailable(AlertAvailability::MalformedResponse);
        }
    };
    match serde_json::from_str(body.trim()) {
        Ok(alerts) => ParsedCursorPage::Page(CursorPage { alerts, next_after }),
        Err(_) => ParsedCursorPage::Unavailable(AlertAvailability::MalformedResponse),
    }
}

fn split_included_response(output: &str) -> Option<(&str, &str)> {
    output
        .split_once("\r\n\r\n")
        .or_else(|| output.split_once("\n\n"))
}

fn next_after_cursor(headers: &str) -> Result<Option<String>, ()> {
    for line in headers.lines() {
        let Some((name, value)) = line.trim_end_matches('\r').split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("link") {
            continue;
        }
        for link in value.split(',') {
            if !link.to_ascii_lowercase().contains("rel=\"next\"") {
                continue;
            }
            let start = link.find('<').ok_or(())? + 1;
            let end = link[start..].find('>').ok_or(())? + start;
            return after_from_link_url(&link[start..end]).map(Some);
        }
    }
    Ok(None)
}

fn after_from_link_url(url: &str) -> Result<String, ()> {
    let query = url.split_once('?').ok_or(())?.1;
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_query(key).ok_or(())?;
        if key == "after" {
            let cursor = percent_decode_query(value).ok_or(())?;
            return valid_cursor(&cursor).then_some(cursor).ok_or(());
        }
    }
    Err(())
}

fn percent_decode_query(input: &str) -> Option<String> {
    if input.len() > 12_288 {
        return None;
    }
    let input = input.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'%' => {
                let high = *input.get(index + 1)?;
                let low = *input.get(index + 2)?;
                decoded.push(hex_value(high)? * 16 + hex_value(low)?);
                index += 3;
            }
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty() && cursor.len() <= 4096 && cursor.bytes().all(|byte| byte.is_ascii_graphic())
}

async fn fetch_dependabot_alerts(
    config: &Config,
    repo: &str,
    limit: usize,
    timeout_ms: Option<u64>,
) -> Collection<DependabotAlert> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(config.resolve_timeout(timeout_ms));
    let mut collected = Vec::with_capacity(limit.min(usize::from(API_PAGE_SIZE)));
    let mut after: Option<String> = None;

    for _ in 0..max_alert_pages(limit) {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Collection::partial(collected, AlertAvailability::TemporarilyUnavailable, None);
        }
        let args = match dependabot_args(repo, after.as_deref()) {
            Ok(args) => args,
            Err(_) => {
                return Collection::partial(collected, AlertAvailability::MalformedResponse, None)
            }
        };
        let remaining_ms = remaining.as_millis().min(u128::from(u64::MAX)) as u64;
        let outcome = gh::run(config, &args, None, Some(remaining_ms)).await;
        match parse_dependabot_page(outcome) {
            ParsedCursorPage::Page(page) => {
                let page_len = page.alerts.len();
                let remaining_records = limit.saturating_sub(collected.len());
                if page_len > remaining_records {
                    collected.extend(
                        page.alerts
                            .into_iter()
                            .take(remaining_records)
                            .map(normalize_dependabot),
                    );
                    return Collection::partial(
                        collected,
                        AlertAvailability::Available,
                        Some(TruncationReason::RecordLimit),
                    );
                }
                collected.extend(page.alerts.into_iter().map(normalize_dependabot));
                if page_len == 0 || page.next_after.is_none() {
                    return Collection::complete(collected);
                }
                if collected.len() == limit {
                    return Collection::partial(
                        collected,
                        AlertAvailability::Available,
                        Some(TruncationReason::RecordLimit),
                    );
                }
                if page.next_after == after {
                    return Collection::partial(
                        collected,
                        AlertAvailability::MalformedResponse,
                        None,
                    );
                }
                after = page.next_after;
            }
            ParsedCursorPage::Unavailable(availability) => {
                return Collection::partial(collected, availability, None)
            }
            ParsedCursorPage::OutputLimited => {
                return Collection::partial(
                    collected,
                    AlertAvailability::Available,
                    Some(TruncationReason::OutputLimit),
                )
            }
        }
    }

    Collection::partial(
        collected,
        AlertAvailability::Available,
        Some(TruncationReason::RecordLimit),
    )
}

fn classify_api_failure(stderr: &str) -> AlertAvailability {
    let message = stderr.to_ascii_lowercase();
    if contains_any(
        &message,
        &[
            "not enabled",
            "must be enabled",
            "dependabot alerts are disabled",
            "code scanning is disabled",
            "advanced security is disabled",
        ],
    ) {
        AlertAvailability::FeatureDisabled
    } else if contains_any(
        &message,
        &[
            "http 401",
            "bad credentials",
            "authentication required",
            "gh auth login",
            "not logged into",
        ],
    ) {
        AlertAvailability::AuthenticationRequired
    } else if contains_any(
        &message,
        &[
            "http 403",
            "forbidden",
            "resource not accessible",
            "insufficient permission",
        ],
    ) {
        AlertAvailability::PermissionDenied
    } else if contains_any(&message, &["http 404", "not found"]) {
        AlertAvailability::RepositoryUnavailable
    } else {
        AlertAvailability::TemporarilyUnavailable
    }
}

fn contains_any(message: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| message.contains(needle))
}

fn normalize_dependabot(raw: RawDependabotAlert) -> DependabotAlert {
    DependabotAlert {
        number: raw.number,
        state: sanitize(&raw.state, 32),
        severity: sanitize(&raw.security_advisory.severity, 32),
        package_name: sanitize(&raw.dependency.package.name, 256),
        ecosystem: sanitize(&raw.dependency.package.ecosystem, 64),
        manifest_path: sanitize(&raw.dependency.manifest_path, 1024),
        dependency_scope: sanitize_optional(raw.dependency.scope, 64),
        relationship: sanitize_optional(raw.dependency.relationship, 64),
        ghsa_id: sanitize(&raw.security_advisory.ghsa_id, 64),
        cve_id: sanitize_optional(raw.security_advisory.cve_id, 64),
        advisory_summary: sanitize(&raw.security_advisory.summary, 512),
        vulnerable_version_range: sanitize(
            &raw.security_vulnerability.vulnerable_version_range,
            512,
        ),
        first_patched_version: raw
            .security_vulnerability
            .first_patched_version
            .map(|version| sanitize(&version.identifier, 128)),
        html_url: sanitize(&raw.html_url, 1024),
        created_at: sanitize(&raw.created_at, 64),
        updated_at: sanitize(&raw.updated_at, 64),
    }
}

fn normalize_code_scanning(raw: RawCodeScanningAlert) -> CodeScanningAlert {
    let instance = raw.most_recent_instance;
    let (git_ref, commit_sha, message, path, start_line, end_line) = match instance {
        Some(instance) => {
            let (path, start_line, end_line) = match instance.location {
                Some(location) => (
                    Some(sanitize(&location.path, 1024)),
                    location.start_line,
                    location.end_line,
                ),
                None => (None, None, None),
            };
            (
                sanitize_optional(instance.git_ref, 512),
                sanitize_optional(instance.commit_sha, 128),
                instance
                    .message
                    .map(|message| sanitize(&message.text, 1024)),
                path,
                start_line,
                end_line,
            )
        }
        None => (None, None, None, None, None, None),
    };

    CodeScanningAlert {
        number: raw.number,
        state: sanitize(&raw.state, 32),
        rule_id: sanitize(&raw.rule.id, 256),
        rule_name: sanitize_optional(raw.rule.name, 256),
        rule_description: sanitize(&raw.rule.description, 512),
        security_severity: sanitize_optional(raw.rule.security_severity_level, 32),
        severity: sanitize(&raw.rule.severity, 32),
        tool_name: sanitize(&raw.tool.name, 256),
        html_url: sanitize(&raw.html_url, 1024),
        git_ref,
        commit_sha,
        message,
        path,
        start_line,
        end_line,
        created_at: sanitize(&raw.created_at, 64),
        updated_at: sanitize_optional(raw.updated_at, 64),
    }
}

fn latest_analysis(outcome: Result<GhOutcome, GhError>) -> LatestCodeScanningAnalysis {
    let unavailable = |availability| LatestCodeScanningAnalysis {
        availability,
        tool_name: None,
        commit_sha: None,
        git_ref: None,
        created_at: None,
        error: None,
        warning: None,
    };
    let out = match outcome {
        Ok(out) => out,
        Err(_) => return unavailable(AlertAvailability::ClientUnavailable),
    };
    if out.timed_out {
        return unavailable(AlertAvailability::TemporarilyUnavailable);
    }
    if out.exit_code != Some(0) {
        return unavailable(classify_api_failure(&out.stderr));
    }
    if out.stdout_truncated {
        return unavailable(AlertAvailability::MalformedResponse);
    }
    let mut analyses: Vec<RawCodeScanningAnalysis> = match serde_json::from_str(out.stdout.trim()) {
        Ok(analyses) => analyses,
        Err(_) => return unavailable(AlertAvailability::MalformedResponse),
    };
    let Some(raw) = analyses.drain(..).next() else {
        return unavailable(AlertAvailability::Available);
    };
    LatestCodeScanningAnalysis {
        availability: AlertAvailability::Available,
        tool_name: sanitize_optional(Some(raw.tool.name), 256),
        commit_sha: sanitize_optional(raw.commit_sha, 128),
        git_ref: sanitize_optional(raw.git_ref, 512),
        created_at: sanitize_optional(raw.created_at, 64),
        error: sanitize_optional(raw.error, 1024),
        warning: sanitize_optional(raw.warning, 1024),
    }
}

fn sanitize_optional(value: Option<String>, max_chars: usize) -> Option<String> {
    value
        .map(|value| sanitize(&value, max_chars))
        .filter(|value| !value.is_empty())
}

fn sanitize(value: &str, max_chars: usize) -> String {
    let mut output = String::new();
    let mut pending_space = false;
    let mut output_chars = 0;
    for character in value.chars() {
        if character.is_control() || character.is_whitespace() {
            pending_space = !output.is_empty();
            continue;
        }
        if pending_space && output_chars < max_chars {
            output.push(' ');
            output_chars += 1;
            pending_space = false;
        }
        if output_chars == max_chars {
            break;
        }
        output.push(character);
        output_chars += 1;
    }
    output.trim().to_string()
}

fn dependabot_response(
    repository: String,
    collection: Collection<DependabotAlert>,
) -> DependabotAlertsResponse {
    DependabotAlertsResponse {
        repository,
        completeness: collection.completeness,
        availability: collection.availability,
        collected_count: collection.alerts.len(),
        truncation_reason: collection.truncation_reason,
        alerts: collection.alerts,
    }
}

fn code_scanning_response(
    repository: String,
    collection: Collection<CodeScanningAlert>,
    latest_analysis: LatestCodeScanningAnalysis,
) -> CodeScanningAlertsResponse {
    CodeScanningAlertsResponse {
        repository,
        completeness: collection.completeness,
        availability: collection.availability,
        collected_count: collection.alerts.len(),
        truncation_reason: collection.truncation_reason,
        alerts: collection.alerts,
        latest_analysis,
    }
}

pub fn register(iii: &IIIClient, cell: &ConfigCell, emitter: &CalledEmitter) {
    register_dependabot(iii, cell, emitter);
    register_code_scanning(iii, cell, emitter);
}

fn register_dependabot(iii: &IIIClient, cell: &ConfigCell, emitter: &CalledEmitter) {
    let cell = cell.clone();
    let emitter = emitter.clone();
    iii.register_function(
        DEPENDABOT_ALERTS_ID,
        RegisterFunction::new_async(move |request: AlertsRequest| {
            let cell = cell.clone();
            let emitter = emitter.clone();
            async move {
                let limit = alert_limit(request.limit)?;
                let args = dependabot_alerts_args(&request, None)?;
                let args_summary = events::summarize_args(&args);
                let repository = request.repo.clone();
                events::run_and_emit(
                    &emitter,
                    DEPENDABOT_ALERTS_ID,
                    args_summary,
                    Some(repository.clone()),
                    async move {
                        let config = cell.read().await.clone();
                        let collection = fetch_dependabot_alerts(
                            &config,
                            &repository,
                            limit,
                            request.timeout_ms,
                        )
                        .await;
                        Ok::<_, Error>(dependabot_response(repository, collection))
                    },
                )
                .await
            }
        })
        .description(DEPENDABOT_ALERTS_DESC),
    );
}

fn register_code_scanning(iii: &IIIClient, cell: &ConfigCell, emitter: &CalledEmitter) {
    let cell = cell.clone();
    let emitter = emitter.clone();
    iii.register_function(
        CODE_SCANNING_ALERTS_ID,
        RegisterFunction::new_async(move |request: AlertsRequest| {
            let cell = cell.clone();
            let emitter = emitter.clone();
            async move {
                let limit = alert_limit(request.limit)?;
                let args = code_scanning_alerts_args(&request, 1)?;
                let analysis_args = code_scanning_analysis_args(&request)?;
                let args_summary = events::summarize_args(&args);
                let repository = request.repo.clone();
                events::run_and_emit(
                    &emitter,
                    CODE_SCANNING_ALERTS_ID,
                    args_summary,
                    Some(repository.clone()),
                    async move {
                        let config = cell.read().await.clone();
                        let (collection, analysis_outcome) = tokio::join!(
                            fetch_numbered_alerts::<RawCodeScanningAlert, CodeScanningAlert>(
                                &config,
                                &repository,
                                limit,
                                request.timeout_ms,
                                normalize_code_scanning,
                            ),
                            gh::run(&config, &analysis_args, None, request.timeout_ms),
                        );
                        Ok::<_, Error>(code_scanning_response(
                            repository,
                            collection,
                            latest_analysis(analysis_outcome),
                        ))
                    },
                )
                .await
            }
        })
        .description(CODE_SCANNING_ALERTS_DESC),
    );
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn outcome(stdout: String) -> Result<GhOutcome, GhError> {
        Ok(GhOutcome {
            stdout,
            stderr: String::new(),
            exit_code: Some(0),
            duration_ms: 1,
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    fn collect_test_pages<Raw, Normalized>(
        outcomes: Vec<Result<GhOutcome, GhError>>,
        limit: usize,
        normalize: fn(Raw) -> Normalized,
    ) -> Collection<Normalized>
    where
        Raw: DeserializeOwned,
    {
        let mut collected = Vec::new();
        for outcome in outcomes {
            match parse_alert_page(outcome) {
                ParsedPage::Alerts(page) => {
                    match append_alert_page(&mut collected, page, limit, normalize) {
                        PageProgress::Continue => {}
                        PageProgress::Complete => return Collection::complete(collected),
                        PageProgress::RecordLimit => {
                            return Collection::partial(
                                collected,
                                AlertAvailability::Available,
                                Some(TruncationReason::RecordLimit),
                            )
                        }
                    }
                }
                ParsedPage::Unavailable(availability) => {
                    return Collection::partial(collected, availability, None)
                }
                ParsedPage::OutputLimited => {
                    return Collection::partial(
                        collected,
                        AlertAvailability::Available,
                        Some(TruncationReason::OutputLimit),
                    )
                }
            }
        }
        Collection::partial(
            collected,
            AlertAvailability::Available,
            Some(TruncationReason::RecordLimit),
        )
    }

    fn dependabot_raw(number: u64) -> Value {
        json!({
            "number": number,
            "state": "open",
            "dependency": {
                "package": { "ecosystem": "cargo", "name": "demo" },
                "manifest_path": "Cargo.lock",
                "scope": "runtime",
                "relationship": "direct"
            },
            "security_advisory": {
                "ghsa_id": "GHSA-demo",
                "cve_id": "CVE-2026-1",
                "summary": "short summary",
                "description": "large raw description must be dropped",
                "severity": "high",
                "references": [{"url": "https://attacker.invalid"}]
            },
            "security_vulnerability": {
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": { "identifier": "2.0.0" }
            },
            "html_url": format!("https://github.com/o/r/security/dependabot/{number}"),
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "dismissed_by": { "login": "private-user" }
        })
    }

    fn code_scanning_raw(number: u64) -> Value {
        json!({
            "number": number,
            "state": "open",
            "rule": {
                "id": "rust/sql-injection",
                "name": "SQL injection",
                "description": "Untrusted input reaches a query",
                "help": "long help and code snippets must be dropped",
                "security_severity_level": "high",
                "severity": "error"
            },
            "tool": { "name": "CodeQL", "version": "private-noise" },
            "most_recent_instance": {
                "ref": "refs/heads/main",
                "commit_sha": "abc123",
                "message": { "text": "diagnostic\nmessage" },
                "location": { "path": "src/main.rs", "start_line": 10, "end_line": 12 }
            },
            "html_url": format!("https://github.com/o/r/security/code-scanning/{number}"),
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-02T00:00:00Z",
            "dismissed_by": { "login": "private-user" }
        })
    }

    #[test]
    fn endpoint_specific_args_use_cursor_and_numeric_pagination() {
        let request = AlertsRequest {
            repo: "iii-hq/iii".into(),
            limit: None,
            timeout_ms: None,
        };
        assert_eq!(
            dependabot_alerts_args(&request, None).unwrap(),
            vec![
                "api",
                "repos/iii-hq/iii/dependabot/alerts",
                "-X",
                "GET",
                "-f",
                "state=open",
                "-f",
                "per_page=100",
                "--include",
            ]
        );
        let cursor_args = dependabot_alerts_args(&request, Some("Y3Vyc29yPQ==")).unwrap();
        assert_eq!(cursor_args.last().unwrap(), "after=Y3Vyc29yPQ==");
        assert!(!cursor_args.iter().any(|arg| arg.starts_with("page=")));
        assert_eq!(
            code_scanning_alerts_args(&request, 1).unwrap()[1],
            "repos/iii-hq/iii/code-scanning/alerts"
        );
        for page in 1..=max_alert_pages(500) {
            let args = code_scanning_alerts_args(&request, page).unwrap();
            assert!(!args.iter().any(|arg| arg == "--paginate"));
            assert!(!args.iter().any(|arg| arg == "--slurp"));
            assert_eq!(args.last().unwrap(), &format!("page={page}"));
        }
        assert_eq!(max_alert_pages(500), 6);
        assert_eq!(
            code_scanning_analysis_args(&request).unwrap(),
            vec![
                "api",
                "repos/iii-hq/iii/code-scanning/analyses",
                "-X",
                "GET",
                "-f",
                "per_page=1",
            ]
        );
    }

    #[test]
    fn dependabot_include_shape_extracts_and_decodes_only_next_after_cursor() {
        let body = serde_json::to_string(&vec![dependabot_raw(1)]).unwrap();
        let included = format!(
            "HTTP/2.0 200 OK\r\n\
             content-type: application/json\r\n\
             link: <https://api.github.com/repos/o/r/dependabot/alerts?per_page=100&state=open&after=Y3Vyc29yJTJGJTNE%3D>; rel=\"next\", \
             <https://api.github.com/repos/o/r/dependabot/alerts?per_page=100&before=old>; rel=\"prev\"\r\n\
             x-private-header: must-not-escape\r\n\r\n{body}"
        );
        match parse_dependabot_page::<RawDependabotAlert>(outcome(included)) {
            ParsedCursorPage::Page(page) => {
                assert_eq!(page.alerts.len(), 1);
                assert_eq!(page.next_after.as_deref(), Some("Y3Vyc29yJTJGJTNE="));
            }
            _ => panic!("live --include shape should parse"),
        }
    }

    #[test]
    fn malformed_dependabot_next_link_is_not_treated_as_complete() {
        let included = "HTTP/2.0 200 OK\n\
                        link: <https://api.github.com/repos/o/r/dependabot/alerts?after=%ZZ>; rel=\"next\"\n\n[]";
        match parse_dependabot_page::<RawDependabotAlert>(outcome(included.into())) {
            ParsedCursorPage::Unavailable(availability) => {
                assert_eq!(availability, AlertAvailability::MalformedResponse)
            }
            _ => panic!("invalid cursor must not silently end pagination"),
        }
    }

    #[test]
    fn page_boundaries_are_flattened_without_inventing_a_total() {
        let first: Vec<Value> = (1..=100).map(dependabot_raw).collect();
        let second = vec![dependabot_raw(101)];
        let collection = collect_test_pages(
            vec![
                outcome(serde_json::to_string(&first).unwrap()),
                outcome(serde_json::to_string(&second).unwrap()),
            ],
            101,
            normalize_dependabot,
        );
        let response = dependabot_response("o/r".into(), collection);
        assert_eq!(response.completeness, CollectionCompleteness::Complete);
        assert_eq!(response.collected_count, 101);
        assert_eq!(response.alerts.len(), 101);
        assert_eq!(response.truncation_reason, None);
    }

    #[test]
    fn record_limit_marks_the_result_partial() {
        let page = vec![dependabot_raw(1), dependabot_raw(2), dependabot_raw(3)];
        let collection = collect_test_pages(
            vec![outcome(serde_json::to_string(&page).unwrap())],
            2,
            normalize_dependabot,
        );
        let response = dependabot_response("o/r".into(), collection);
        assert_eq!(response.completeness, CollectionCompleteness::Partial);
        assert_eq!(response.availability, AlertAvailability::Available);
        assert_eq!(response.collected_count, 2);
        assert_eq!(
            response.truncation_reason,
            Some(TruncationReason::RecordLimit)
        );
    }

    #[test]
    fn output_limit_is_explicit_and_never_parses_cut_json() {
        let mut out = outcome("[{\"cut\":".into()).unwrap();
        out.stdout_truncated = true;
        let collection = collect_test_pages::<RawDependabotAlert, DependabotAlert>(
            vec![Ok(out)],
            100,
            normalize_dependabot,
        );
        let response = dependabot_response("o/r".into(), collection);
        assert_eq!(response.completeness, CollectionCompleteness::Partial);
        assert_eq!(response.collected_count, 0);
        assert_eq!(
            response.truncation_reason,
            Some(TruncationReason::OutputLimit)
        );
    }

    #[test]
    fn malformed_page_response_is_sanitized_partial_data() {
        let collection = collect_test_pages::<RawDependabotAlert, DependabotAlert>(
            vec![outcome("{\"not\":\"an alert array\"}".into())],
            100,
            normalize_dependabot,
        );
        let response = dependabot_response("o/r".into(), collection);
        assert_eq!(response.completeness, CollectionCompleteness::Partial);
        assert_eq!(response.availability, AlertAvailability::MalformedResponse);
        assert_eq!(response.collected_count, 0);
    }

    #[test]
    fn auth_error_is_classified_without_exposing_stderr() {
        let secret = "gh: HTTP 401: Bad credentials token-secret-value";
        let response = dependabot_response(
            "o/r".into(),
            collect_test_pages::<RawDependabotAlert, DependabotAlert>(
                vec![Ok(GhOutcome {
                    stdout: String::new(),
                    stderr: secret.into(),
                    exit_code: Some(1),
                    duration_ms: 1,
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                })],
                100,
                normalize_dependabot,
            ),
        );
        assert_eq!(
            response.availability,
            AlertAvailability::AuthenticationRequired
        );
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains("token-secret-value"));
        assert!(!encoded.contains("stderr"));
    }

    #[test]
    fn later_page_failure_preserves_already_collected_alerts() {
        let first: Vec<Value> = (1..=100).map(dependabot_raw).collect();
        let collection = collect_test_pages(
            vec![
                outcome(serde_json::to_string(&first).unwrap()),
                Ok(GhOutcome {
                    stdout: String::new(),
                    stderr: "HTTP 403: Resource not accessible".into(),
                    exit_code: Some(1),
                    duration_ms: 1,
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                }),
            ],
            500,
            normalize_dependabot,
        );
        let response = dependabot_response("o/r".into(), collection);
        assert_eq!(response.completeness, CollectionCompleteness::Partial);
        assert_eq!(response.availability, AlertAvailability::PermissionDenied);
        assert_eq!(response.collected_count, 100);
        assert_eq!(response.truncation_reason, None);
    }

    #[test]
    fn disabled_code_scanning_is_distinct_from_permission_denied() {
        assert_eq!(
            classify_api_failure("HTTP 403: GitHub Advanced Security must be enabled"),
            AlertAvailability::FeatureDisabled
        );
        assert_eq!(
            classify_api_failure("HTTP 403: Resource not accessible by integration"),
            AlertAvailability::PermissionDenied
        );
    }

    #[test]
    fn code_scanning_normalization_drops_help_users_and_control_characters() {
        let collection = collect_test_pages(
            vec![outcome(
                serde_json::to_string(&vec![code_scanning_raw(7)]).unwrap(),
            )],
            100,
            normalize_code_scanning,
        );
        let response = code_scanning_response(
            "o/r".into(),
            collection,
            latest_analysis(outcome("[]".into())),
        );
        assert_eq!(response.collected_count, 1);
        assert_eq!(
            response.alerts[0].message.as_deref(),
            Some("diagnostic message")
        );
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains("long help"));
        assert!(!encoded.contains("private-user"));
        assert!(!encoded.contains("private-noise"));
    }

    #[test]
    fn latest_analysis_surfaces_bounded_tool_health_without_result_data() {
        let raw = json!([{
            "tool": { "name": "Trivy", "version": "0.99" },
            "commit_sha": "abc123",
            "ref": "refs/heads/main",
            "created_at": "2026-01-03T00:00:00Z",
            "error": "configuration\nfailed",
            "warning": "partial upload",
            "results_count": 99,
            "sarif_id": "private-sarif"
        }]);
        let health = latest_analysis(outcome(serde_json::to_string(&raw).unwrap()));
        assert_eq!(health.availability, AlertAvailability::Available);
        assert_eq!(health.tool_name.as_deref(), Some("Trivy"));
        assert_eq!(health.error.as_deref(), Some("configuration failed"));
        let encoded = serde_json::to_string(&health).unwrap();
        assert!(!encoded.contains("results_count"));
        assert!(!encoded.contains("private-sarif"));
        assert!(!encoded.contains("0.99"));
    }

    #[test]
    fn repo_and_limit_validation_prevent_unbounded_or_injected_paths() {
        assert!(repository_endpoint("iii-hq/iii", "dependabot/alerts").is_ok());
        assert!(repository_endpoint("iii-hq/iii/extra", "dependabot/alerts").is_err());
        assert!(repository_endpoint("iii-hq/../iii", "dependabot/alerts").is_err());
        assert_eq!(alert_limit(None).unwrap(), usize::from(DEFAULT_ALERT_LIMIT));
        assert!(alert_limit(Some(0)).is_err());
    }
}
