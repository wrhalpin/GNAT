# ADR-0025: Upstream Contribution Pipeline

**Decision:** 7-step gate enforced by `ContributionPipeline`; draft PR is always true and cannot be overridden.

**Why a programmatic gate:**
Contributing a connector to upstream without a compliance check would allow incomplete
or untested connectors to land in the shared codebase. The 7 steps enforce the minimum
bar automatically so contributors don't need to read a checklist.

**The 7 steps:**
1. **Enabled guard** — `contribute.enabled = true` must be set in INI; prevents accidental runs.
2. **Registry check** — connector must exist in `CLIENT_REGISTRY`.
3. **Compliance matrix** — all 8 `ConnectorMixin` methods implemented + test file present.
4. **Test suite** — `pytest tests/unit/` must pass; aborts on any failure.
5. **Branch creation** — `contribute/{platform}-{timestamp}`; `_PROTECTED_BRANCHES` blocks `main`/`master`.
6. **Commit + push** — uses `SubprocessRunner` (injectable for testing).
7. **Draft PR** — GitHub REST API `POST /repos/{owner}/{repo}/pulls` with `draft: true`.

**`draft_pr` hardcoded:**
The PR is always a draft. This is intentional — human review before merge is non-negotiable
for a shared security library. No config knob exposes this.
