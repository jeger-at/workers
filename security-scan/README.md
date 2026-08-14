# security-scan

`security-scan` accepts manual review requests for operator-configured repositories and queues a report-only security analysis of an exact Git commit. It creates an isolated checkout resolved to that commit, constrains Harness to read-only code functions, validates the structured result, and never applies a suggested change.

## Install

```bash
iii worker add security-scan
```

Analysis also requires the Harness stack to be running. It is a runtime prerequisite rather than a registry dependency so the worker install graph stays within the registry depth limit.

```bash
iii worker add harness
```

The worker composes existing iii infrastructure rather than implementing local substitutes: private compare-and-set records live in `state`, durable steps run through `queue`, exact checkouts come from `worktree`, and analysis runs through `harness`.

## Quickstart

Request a scan using a configured repository id and a full commit SHA:

```bash
iii trigger security-scan::request \
  repository=iii-hq/iii \
  target_sha="$(git -C /srv/repos/iii rev-parse HEAD)" \
  mode=scan
```

The request returns immediately:

```json
{
  "run_id": "sec_...",
  "status": "queued",
  "deduplicated": false
}
```

Submitting the same repository, commit, and mode again returns the same run id with `deduplicated: true`. A retryable failed run is restarted as a new attempt under that same id. If the first queue wake fails, the durable queued checkpoint remains available to the recovery sweep. Use `mode=suggest` to include minimal patch suggestions in the report; suggestions remain text and are never applied.

Read the current status or completed report:

```bash
iii trigger security-scan::read run_id=sec_...
```

## Configuration

Repositories are an operator-owned allowlist. Callers choose an id, not an arbitrary filesystem path or URL.

```yaml
repositories:
  - id: iii-hq/iii       # stable id accepted by security-scan::request
    path: /srv/repos/iii # local Git repository owned by the operator
analysis:
  model: provider/model-id # required model from the live router catalog
  provider: provider-id    # optional explicit provider
  max_turns: 4             # maximum Harness generations
  max_output_tokens: 8000  # ceiling for one generation
  max_total_tokens: 50000  # ceiling for the complete review
  max_cost_usd: 2.0        # optional spend ceiling
```

The shipped configuration leaves `analysis.model` empty and `repositories` empty. Set a model and at least one repository before requesting a scan; the empty repository allowlist rejects every request.

Configuration is loaded at worker startup in this MVP. Restart `security-scan` after changing the repository allowlist or analysis settings.

## Safety boundary

The worker accepts only 40-character commit SHAs, verifies the materialized checkout matches the requested commit, and disables ignored-file provisioning for scanner worktrees so local `.env`, dependency, and cache files are not copied into the review scope. The Harness turn can discover function contracts and call only `coder::info`, `coder::tree`, `coder::list-folder`, `coder::read-file`, and `coder::search`. It cannot run repository code, access the network, mutate files, update state, or start another agent.

Dependency sessions use private random identities rather than the public run id. Structured output is rejected if it exposes the internal checkout root or high-confidence credential material. Terminal scanner worktrees are removed through the existing `worktree` worker.

The public MVP exposes `security-scan::request` and `security-scan::read`. `security-scan::execute` and `security-scan::on-turn-completed` are internal worker functions. This phase does not expose apply, commit, push, comment, review, merge, or alert-dismissal functions.

This first phase is the bounded investigation layer. A later phase will feed it deterministic, pinned SAST, dependency, and secret-scanner candidates before Harness analysis, following the same candidate-discovery then evidence-review split used by DeepSec.
