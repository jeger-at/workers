# github

GitHub as iii functions, powered by the GitHub CLI. Typed `github::*`
functions cover pull requests, issues, repos, Actions runs and workflows,
releases, search, and repository security alerts; `github::exec` runs any
other gh command and `github::api` reaches any GitHub REST endpoint. Agents get
schema-discoverable GitHub operations with read-vs-mutate permission gating
instead of raw shell.

## Install

```bash
iii worker add github
```

`iii worker add` fetches the binary, writes a config block into
`~/.iii/config.yaml`, and the engine starts the worker the next time it boots.

The worker shells out to the [GitHub CLI](https://cli.github.com) — install
a current `gh` (the typed field sets are validated against gh 2.94) and give
it credentials: either `gh auth login` on the host, or set `GH_TOKEN` for
the worker (see Configuration).

## Quickstart

```rust
use iii_sdk::{register_worker, InitOptions, TriggerRequest};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let iii = register_worker("ws://localhost:49134", InitOptions::default());

    // Open PRs in a repo, typed and parsed:
    let prs = iii
        .trigger(TriggerRequest {
            function_id: "github::pr::list".into(),
            payload: json!({ "repo": "cli/cli", "state": "open", "limit": 5 }),
            action: None,
            timeout_ms: Some(60_000),
        })
        .await?;
    println!("{prs:#?}"); // { value: [{ number, title, state, url, … }] }

    // Open repository security alerts, normalized and bounded. A partial
    // response never claims an exact total.
    let alerts = iii
        .trigger(TriggerRequest {
            function_id: "github::security::dependabot-alerts".into(),
            payload: json!({ "repo": "cli/cli", "limit": 100 }),
            action: None,
            timeout_ms: Some(60_000),
        })
        .await?;
    println!("{alerts:#?}");

    // Anything else gh can do, verbatim:
    let version = iii
        .trigger(TriggerRequest {
            function_id: "github::exec".into(),
            payload: json!({ "args": ["--version"] }),
            action: None,
            timeout_ms: Some(60_000),
        })
        .await?;
    println!("{version:#?}"); // { stdout, stderr, exit_code, … }

    Ok(())
}
```

## Configuration

```yaml
gh_executable: ""            # path to gh; empty = `gh` on PATH
token: "${GH_TOKEN}"         # env-expanded; empty = ambient `gh auth login`
default_timeout_ms: 30000    # per-call timeout when timeout_ms is omitted
max_timeout_ms: 120000       # upper clamp for any per-call timeout_ms
max_output_bytes: 1048576    # per-stream capture cap (flags *_truncated)
```

Other keys (and their defaults) live in [`src/config.rs`](src/config.rs).

The two `github::security::*` functions request explicit 100-record REST pages
under one deadline. Code scanning uses bounded numeric pages; Dependabot uses
the endpoint's `after` cursor extracted from the next Link header. They make at
most `ceil(limit / 100) + 1` requests (six at the 500-record maximum). Their
response always carries `completeness`, `collected_count`, `availability`, and
`truncation_reason`; partial results do not claim an exact total.
Authentication, disabled-feature, permission, and temporary failures are
returned as sanitized availability classifications, never raw headers or `gh`
stderr.
