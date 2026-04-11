# Changelog

All notable changes to GNAT are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Detailed per-version release notes are available in [`docs/releases/`](docs/releases/).

---

## [1.5.0]

Consolidation release. Bumps the version tag to reflect the full Analyst OS feature set
(Alembic migrations, Plugin System, Policy Engine, TAXII write endpoints, Workflow
orchestration, Data Lineage, Analyst Metrics, AI Intel Review Queue, Discord connector,
STIX Object Validator). Presentation deck rebuilt to v1.5.0 with 5 new slides covering
all v1.4+ modules.

→ Full feature breakdown is in `## [1.4.0]` below; this entry marks the version cut.
## [Unreleased]

### Added — Phase 2 Wave 2: MDR Platforms

Three Managed Detection & Response connectors covering the top-rated
MDR vendors from the 2026 audit. This wave fills the gap between
platform-level EDR (CrowdStrike, SentinelOne, etc., already in GNAT) and
the managed-service delivery layer — the tier where analyst-generated
tickets, investigations, and confirmed detections live. Platform count:
119 → 122.

All three connectors are `trusted_internal` (customer's own MDR
telemetry) and read-only.

**New connectors (`gnat/connectors/`)**
- `huntress/` — `HuntressClient` for Huntress Managed EDR / ITDR.
  HTTP Basic auth with `api_key_id` as username + `api_secret` as
  password (reuses `BaseClient._basic_auth`). Endpoints: `/v1/account`,
  `/v1/organizations`, `/v1/agents`, `/v1/incident_reports`,
  `/v1/reports`, `/v1/signals`. Incident reports map to
  `observed-data` envelopes with refs to the affected `identity`
  (organization), custom `x-huntress-agent` SCO for the deployed
  agent, and any `ipv4-addr` observables from `remote_ip`. Domain
  helpers: `list_organizations`, `list_agents`, `list_incidents`,
  `get_incident`. `_unwrap_huntress` helper strips Huntress's
  single-key envelopes (e.g. `{"organization": {...}}`).
- `arctic_wolf/` — `ArcticWolfClient` for Arctic Wolf MDR. Bearer
  token auth with an optional `X-Arctic-Wolf-Customer` header for
  multi-tenant MSSP deployments. Dispatches across `/v1/tickets`,
  `/v1/tickets/{id}/comments`, `/v1/investigations`, `/v1/customer`.
  Tickets and investigations both map to `observed-data` envelopes
  with `filters["kind"]` selecting the endpoint. Domain helpers:
  `list_tickets`, `list_investigations`, `get_ticket`,
  `get_ticket_comments`, `get_customer`.
- `red_canary/` — `RedCanaryClient` for Red Canary MDR. `X-Api-Key`
  header auth, JSON:API response shape (`{"data": ...}`) unwrapped by
  `_unwrap_rc`. Endpoints: `/openapi/v3/detections`, `/endpoints`,
  `/events`, `/organization`. Detections map to `observed-data`
  envelopes with refs to the affected endpoint as `identity` and any
  source `ipv4-addr`. Attribute nesting (`attributes.severity` etc.)
  is handled inline in `to_stix`. Domain helpers: `list_detections`,
  `get_detection`, `list_endpoints`, `get_endpoint`, `list_events`.

**Tests**
- 43 new tests across `TestHuntressClient` (15),
  `TestArcticWolfClient` (14), `TestRedCanaryClient` (14) plus two
  Phase 2 Wave 2 integrity tests. Full unit suite: 2270 tests
  passing, zero regressions. Ruff clean across all new files.

**Architectural notes**
- All three MDR connectors introduce a custom SCO on the Huntress side
  (`x-huntress-agent`) for the deployed agent record. This mirrors the
  pattern Phase 1 Wave 3b established with `x-cryptocurrency-wallet`
  on TRM Labs — custom STIX observable types are acceptable when the
  platform's native entity doesn't have a natural STIX analog.

### Added — Phase 2 Wave 1: Malware Sandboxes

Five dynamic-malware-analysis connectors closing the single biggest
remaining coverage gap from the 2026 audit. Up to this point GNAT had
zero sandbox connectors — every IOC came from static-analysis / reputation
sources. Phase 2 Wave 1 introduces the full sandbox tier at once so
subsequent workflows (ransomware triage, phishing chain analysis,
malware family attribution) have behavioral telemetry to consume.
Platform count: 114 → 119.

**Shared helper (`gnat/utils/stix_helpers.py`)**
- `sandbox_report_envelope(source_name, analysis_id, …)` — builds a
  STIX 2.1 `observed-data` envelope around a sandbox behavioral report
  with deterministic UUID-5 refs to synthetic `file`/`url`/`process`/
  `ipv4-addr`/`domain-name`/`url` observables. Every Phase 2 Wave 1
  connector consumes this helper so all five produce consistent
  envelope shapes.

**New connectors (`gnat/connectors/`)**
- `joe_sandbox/` — `JoeSandboxClient` for Joe Sandbox Cloud. Joe's
  "apikey as POST form field" convention is wrapped in an
  `_authed_form()` helper. COST_UNIT=5 to reflect submission expense.
  Domain helpers: `submit_file`, `submit_url`, `get_submission`,
  `get_analysis`, `get_iocs`, `iocs_to_indicators`. STIX emits
  `observed-data` (full analysis), `malware` (family attribution from
  detection tags), and `indicator` (extracted IOCs).
- `any_run/` — `AnyRunClient` for ANY.RUN interactive sandbox.
  `Authorization: API-Key <key>` header. Domain helpers: `submit_file`,
  `submit_url`, `get_analysis`, `list_environments`. Maps ANY.RUN's
  nested `mainObject` + `network` structure to sandbox envelopes.
- `hybrid_analysis/` — `HybridAnalysisClient` for Hybrid Analysis /
  Falcon Sandbox. Requires both `api-key` header **and** a non-empty
  `User-Agent` (defaults to `"Falcon Sandbox"`); the connector rejects
  missing User-Agent at construction time. Domain helpers:
  `submit_file`, `submit_url`, `get_report_summary`, `hash_lookup`,
  `search_hash`. Maps `threat_level_human` to STIX `malware_types`.
- `vmray/` — `VMRayClient` for VMRay Cloud. `Authorization: api_key
  <key>` header. Unwraps VMRay's `{"data": ..., "result": "ok"}`
  envelope at the HTTP boundary via `_unwrap_vmray` so downstream
  mappers don't think about it. Domain helpers: `submit_file`,
  `submit_url`, `get_sample`, `get_analysis`, `get_submission`,
  `get_summary_v2` (the rich v2 behavioral summary format).
- `intezer/` — `IntezerClient` for Intezer Analyze. POSTs to
  `/get-access-token` on first request and caches the returned JWT as
  a Bearer token. Unique "binary DNA" code-reuse attribution → STIX
  `malware` with `x_intezer.code_reuse_pct`. Domain helpers:
  `analyze_file`, `analyze_hash`, `get_analysis`, `get_sub_analyses`,
  `get_iocs`, `get_family`, `get_file_analysis`.

**Architectural notes**
- All five sandboxes raise `GNATClientError` from
  `upsert_object`/`delete_object` — submissions are *domain helpers*
  (`submit_file`, `submit_url`, `analyze_file`, `analyze_hash`), not
  STIX CRUD writes. This matches the read-only-CRUD convention
  established in Phase 1.
- COST_UNIT=5 on all five connectors to reflect the relative expense
  of submitting samples vs cheap lookups in other connectors.

**Tests**
- 66 new connector tests across `TestJoeSandboxClient` (14),
  `TestAnyRunClient` (12), `TestHybridAnalysisClient` (13),
  `TestVMRayClient` (13), `TestIntezerClient` (14) plus two Phase 2
  Wave 1 integrity tests.
- 5 new tests for `sandbox_report_envelope` in
  `tests/unit/test_stix_helpers.py` (basic file envelope, URL
  submission, deterministic ids, raw report embedding, empty
  artifacts).
- Full unit suite: 2047 tests passing, zero regressions.
- Ruff clean across all new files.

### Added — Phase 1 Wave 3b: Tier 1 Connector Expansion (Identity / Email / Finance)

Five more Tier 1 connectors completing Wave 3. Per the user's "Both" vote
on the ITDR vendor question, both Silverfort and Semperis ship
simultaneously. Abnormal Security and Cofense Intelligence fill the
advanced email / BEC gap. TRM Labs covers blockchain / cryptocurrency
threat intelligence. Platform count: 109 → 114.

**New connectors (`gnat/connectors/`)**
- `silverfort/` — `SilverfortClient` for the ITDR platform. OAuth2
  client-credentials auth exchanged at ``/api/v1/auth/token``, Bearer
  cached on ``_auth_headers``. `TRUST_LEVEL = "trusted_internal"` (the
  customer's own authentication telemetry). Emits `user-account`
  (humans + service accounts) and `observed-data` (auth events with
  synthetic user-account + ipv4-addr refs). Domain helpers:
  `list_users`, `list_service_accounts`, `list_auth_events`,
  `list_alerts`, `get_user_risk`.
- `semperis/` — `SemperisClient` for Directory Services Protector.
  Bearer-token auth, `TRUST_LEVEL = "trusted_internal"`. Endpoints:
  `/IoEs`, `/IoCs`, `/Security/Evaluators`, `/Tenants/Forest/Domains`,
  `/Security/Events`. IoE records map to STIX `indicator` with
  `anomalous-activity` label + `[x-semperis-ioe:evaluator = ...]`
  pattern; IoC records use `malicious-activity`. Security events map to
  `observed-data` wrapping a user-account ref for the actor. Domain
  helpers: `list_ioes`, `list_iocs`, `list_evaluators`,
  `list_forest_domains`, `list_security_events`.
- `abnormal/` — `AbnormalClient` for Abnormal Security (BEC / credential
  phishing / vendor impersonation). Bearer-token auth,
  `TRUST_LEVEL = "trusted_internal"`. Dispatches across `/threats`,
  `/cases`, `/vendor-cases`, `/abusemailbox/campaigns` via
  `filters["kind"]`. Each record maps to `observed-data` wrapping a
  deterministic `email-message` ref and a sender `identity` ref, with
  full `x_abnormal` context (attack_type, attack_vector, attack_strategy,
  judgement, impersonated_party, vendor_name, case_id, subject).
  Domain helpers: `list_threats`, `get_threat`, `get_threat_message`,
  `list_cases`, `list_vendor_cases`, `list_abusemailbox_campaigns`.
- `cofense_intel/` — `CofenseIntelClient` for Cofense Intelligence /
  ThreatHQ. HTTP Basic auth (reuses `BaseClient._basic_auth`). Dispatches
  across `/threat/search`, `/threat/{id}`, `/threat/updates`,
  `/malware/families`, `/threat/actors`. Emits `indicator` (IPs, domains,
  URLs, SHA-256 hashes — all tagged with `x_cofense.human_verified =
  True`), `malware`, `threat-actor`, and `report` STIX types. Domain
  helpers: `search_threats`, `get_threat`, `recent_threats`,
  `list_malware_families`, `list_actors`.
- `trm_labs/` — `TRMLabsClient` for blockchain / crypto intel. HTTP
  Basic auth with the API key as username (empty password). Endpoints:
  `POST /screening/addresses` (batch risk screen), `GET /entities/{id}`
  (attribution), `GET /addresses/{chain}/{address}` (full profile).
  STIX mapping: screening results → `indicator` with a custom
  `[x-cryptocurrency-wallet:value = ... AND ...:chain = ...]` pattern
  and `malicious-activity` label when risk_score >= 10; entities →
  `threat-actor`; address profiles → `observed-data` wrapping a
  synthetic `x-cryptocurrency-wallet` ref. Domain helpers:
  `screen_address`, `screen_addresses_batch`, `get_entity`,
  `get_address_profile`.

**Tests**
- 68 new tests across `TestSilverfortClient` (13),
  `TestSemperisClient` (14), `TestAbnormalClient` (13),
  `TestCofenseIntelClient` (14), `TestTRMLabsClient` (16) plus two
  Wave 3b integrity tests. Full suite: 1977 tests passing, zero
  regressions.

### Added — Phase 1 Wave 3a: Tier 1 Connector Expansion (Infrastructure Pivoting)

Three infrastructure-pivoting connectors addressing the biggest 2026 audit
gap outside of sandbox telemetry: passive DNS, historical WHOIS, and
pre-weaponization attack infrastructure. Platform count: 106 → 109.

Per the user's "Both" decision on the pDNS vendor question, **both**
SecurityTrails and DomainTools are wired in; Silent Push complements them
with future-attack infrastructure detection.

**New connectors (`gnat/connectors/`)**
- `securitytrails/` — `SecurityTrailsClient` wraps
  `https://api.securitytrails.com/v1/` with custom `APIKEY` header auth.
  Supports current DNS, subdomains, historical DNS by record type
  (a/aaaa/mx/ns/soa/txt), historical WHOIS, DSL domain/IP search, and
  reverse-IP. Emits `domain-name`, `ipv4-addr`, `observed-data` (pDNS
  history). Domain helpers: `domain_info`, `subdomains`,
  `historical_dns`, `historical_whois`, `search_domains`, `reverse_ip`.
- `domaintools/` — `DomainToolsClient` for the Iris API with
  query-parameter `api_username` + `api_key` auth. Endpoints: current
  WHOIS, WHOIS history, Iris pivoting, hosting history, reverse-IP,
  reputation. Emits `domain-name`, `ipv4-addr`, `observed-data`. Domain
  helpers: `whois`, `whois_history`, `iris_investigate`, `reverse_ip`,
  `hosting_history`, `reputation`.
- `silent_push/` — `SilentPushClient` with `X-API-KEY` header auth.
  Endpoints: domain/IPv4 enrich, passive DNS, IOC search, asset scan.
  Emits `indicator` (future-attack signals) and `observed-data` (pDNS).
  Domain helpers: `ipv4_enrich`, `domain_enrich`, `padns`, `search_iocs`,
  `scan_asset`. Risk scores ≥50 flagged with `malicious-activity` label.

**Tests**
- 43 new tests across three new `TestXxxClient` classes +
  `test_phase1_wave3a_registry_contains_new_connectors` and
  `test_phase1_wave3a_config_sections_exist`. Full suite: 1909 tests
  passing, zero regressions.

### Added — Phase 1 Wave 2: Tier 1 Connector Expansion

Three more Tier 1 connectors targeting the 2026 audit's "unique enterprise
telemetry" slot: Cloudflare edge intel, GitGuardian secret incidents, and
runZero CAASM inventory. All three have published OpenAPI specs and were
originally slated as codegen candidates; in practice hand-writing the
STIX mapping was faster than post-processing auto-generated stubs.
Platform count: 103 → 106.

**New connectors (`gnat/connectors/`)**
- `cloudflare_intel/` — `CloudflareIntelClient` wraps the
  `/client/v4/accounts/{account_id}/intel/` endpoints (domain, IP, ASN,
  WHOIS, passive DNS, domain history). Bearer-token + `account_id`
  required. Emits STIX `indicator` (domain / ipv4), `infrastructure`
  (ASN), and `observed-data` (WHOIS / pDNS / history). Deterministic
  UUID-5 ids keyed on the queried observable. Domain helpers:
  `get_domain_intel`, `get_ip_intel`, `get_asn_intel`, `get_whois`,
  `get_passive_dns`, `get_domain_history`. Registered as
  `"cloudflare_intel"`.
- `gitguardian/` — `GitGuardianClient` for the v1 REST API. Lists and
  fetches secret incidents (`/v1/incidents/secrets`), sources, and
  members. Ad-hoc scanning exposed via `scan_content` (POST `/v1/scan`)
  and `scan_content_batch` (POST `/v1/multiscan`). Incidents map to
  STIX `observed-data` envelopes wrapping file + identity observables
  via `make_observed_data_envelope`, with full `x_gitguardian` context
  (incident id, secret type + family, status, severity, validity,
  assignee, repository, occurrences). Registered as `"gitguardian"`.
- `runzero/` — `RunZeroClient` for the CAASM platform. `TRUST_LEVEL =
  "trusted_internal"` since runZero data is the customer's own asset
  inventory. Bulk exports via `/api/v1.0/export/org/{assets,services,
  software,vulnerabilities}.json`, single-asset lookup via
  `/api/v1.0/org/assets/{id}`, plus `list_sites` and `list_tasks`
  domain helpers. STIX mapping: assets → `observed-data` with
  `ipv4-addr` / `mac-addr` / `software` refs; software records →
  `software` SCO; vulnerability records → `vulnerability` SDO with
  CVSS external refs. Registered as `"runzero"`.

**Config (`config/config.ini.example`)**
- New sections `[cloudflare_intel]`, `[gitguardian]`, `[runzero]` under
  a "Phase 1 Wave 2" banner.

**Registry (`gnat/clients/__init__.py`)**
- Added imports + `CLIENT_REGISTRY` entries + `__all__` entries for
  `CloudflareIntelClient`, `GitGuardianClient`, `RunZeroClient`.

**Tests**
- `tests/unit/connectors/test_connectors.py` — 49 new tests across
  three new `TestXxxClient` classes + two Wave 2 integrity tests
  (`test_phase1_wave2_registry_contains_new_connectors`,
  `test_phase1_wave2_config_sections_exist`). Full suite: 1866 tests
  passing, zero regressions.

### Added — Phase 1 Wave 1: Tier 1 Connector Expansion

Four new connectors closing the biggest gaps in GNAT's 2026 coverage audit
(malware-family attribution, MITRE ATT&CK framework, open-source supply chain,
exploit intelligence). All four are read-only feeds and bring the platform
count from 99 → 103. Built on the existing `BaseClient` + `ConnectorMixin`
pattern with shared STIX-mapping helpers extracted to
`gnat/utils/stix_helpers.py`.

**New connectors (`gnat/connectors/`)**
- `mitre_attack/` — `MitreAttackClient` wraps the public MITRE ATT&CK TAXII 2.1
  server at `https://attack-taxii.mitre.org/api/v21/`. Supports all three
  matrices (`enterprise-attack`, `mobile-attack`, `ics-attack`). Registered
  as `"mitre_attack"`. Domain helpers: `get_technique`, `get_group`,
  `get_software`, `list_tactics`, `list_techniques`, `list_groups`.
- `abusech/` — `AbuseChClient` unified feed connector covering URLhaus,
  MalwareBazaar, ThreatFox, Feodo Tracker, and SSL Blacklist. Single
  registry entry (`"abusech"`) with per-feed dispatch via
  `filters["feed"]` in `list_objects`, plus domain helpers
  `query_urlhaus_url`, `query_urlhaus_host`, `query_mb_hash`,
  `query_threatfox_ioc`, `get_feodo_blocklist`, `get_sslbl_blocklist`.
  Optional `Auth-Key` header for higher rate-limit tier. Emits STIX
  `indicator` objects with deterministic UUID-5 ids and per-feed
  `x_urlhaus`/`x_malwarebazaar`/`x_threatfox`/`x_feodotracker`/`x_sslbl`
  extensions.
- `osv/` — `OSVClient` for the open-source vulnerability database at
  `https://api.osv.dev`. Endpoints: `/v1/query`, `/v1/querybatch`,
  `/v1/vulns/{id}`. Domain helpers: `query_package`, `query_batch`,
  `get_vuln`. Emits STIX `vulnerability` objects via the shared
  `osv_to_stix_vulnerability()` helper.
- `vulncheck/` — `VulnCheckClient` for exploit intelligence at
  `https://api.vulncheck.com/v3/`. Supports all six indices
  (`vulncheck-kev`, `initial-access`, `exploits`, `canary-intelligence`,
  `mitre-cve`, `nist-nvd2`). Domain helpers: `get_kev`, `get_exploits`,
  `get_initial_access`, `list_indices`. Bearer-token auth.

**New TAXII reader (`gnat/ingest/sources/`)**
- `mitre_taxii_reader.py`: `MitreAttackTAXIIReader(TAXIICollectionReader)`
  auto-discovers the enterprise/mobile/ICS matrix collections and wraps
  every poll with a thread-safe token-bucket rate limiter matching
  MITRE's published 10 requests / 10 minutes / source IP limit. Module
  constants: `MITRE_TAXII_ROOT`, `MITRE_COLLECTION_IDS`.

**Shared STIX helpers (`gnat/utils/stix_helpers.py`)**
- `make_observed_data_envelope(first_observed, last_observed, …)` —
  builds STIX 2.1 `observed-data` SDOs with deterministic UUID-5 ids
  derived from source + observation window + object_refs. Consumed by
  all upcoming sandbox/identity/secret-scanning connectors.
- `osv_to_stix_vulnerability(osv_dict)` — converts OSV-schema vulnerability
  dicts to STIX 2.1 `vulnerability` objects. Handles CVE/GHSA/OSV id
  aliasing, CVSS severity → external references, affected package ranges
  → `x_osv_affected`, CWE IDs → `x_cwe_ids`.
- `cvss_to_external_reference(vector, score, version)` — builds STIX
  `external_references` entries for CVSS v2/v3/v4 vectors.
- `make_indicator_pattern(observable_type, value)` — centralized STIX
  pattern builder for ipv4-addr, ipv6-addr, domain-name, url, email-addr,
  file hashes (MD5/SHA-1/SHA-256/SHA-512), and x-cryptocurrency-wallet.
  Escapes single quotes.
- `x509_fingerprint_pattern(sha1, sha256, ja3, ja3s)` — STIX patterns for
  x509 fingerprints and TLS JA3/JA3S values; multiple fingerprints joined
  with `OR`.

**Config (`config/config.ini.example`)**
- New sections `[mitre_attack]`, `[abusech]`, `[osv]`, `[vulncheck]` at
  the end of the file under a "Phase 1 Wave 1" banner.

**Registry (`gnat/clients/__init__.py`)**
- Added imports + `CLIENT_REGISTRY` entries + `__all__` entries for
  `MitreAttackClient`, `AbuseChClient`, `OSVClient`, `VulnCheckClient`.

**Tests**
- `tests/unit/test_stix_helpers.py` — new file, 29 tests covering all
  core and Phase 1 Wave 1 helpers (deterministic ids, CVSS encoding,
  indicator pattern escaping, OSV → STIX conversion, JA3 patterns).
- `tests/unit/connectors/test_connectors.py` — 58 new tests across four
  new `TestXxxClient` classes + two Phase 1 Wave 1 integrity tests
  (`test_phase1_wave1_registry_contains_new_connectors`,
  `test_phase1_wave1_config_sections_exist`). Full suite: 1482 tests
  passing, zero regressions.

### Added — Phase 4: Control, Reasoning, Safety

**4A — Execution Context & Domain Boundaries**
- `gnat/core/context.py`: `ExecutionContext` dataclass carrying `context_id` (UUID), `initiated_by`, `domain`, `trust_level`, `policy_set`, `workspace_id`, `created_at`, `parent_context_id`, `is_replay`; factory methods `create()`, `from_connector()`, `child()`
- `gnat/core/context.py`: `QueryBudget` dataclass — finite query budget for connector calls; `consume()` raises `BudgetExceeded` when exhausted; attached to `ExecutionContext` via `max_budget_units` param on `create()`
- `gnat/core/domains.py`: `Domain` enum (ingestion/analysis/investigation/reporting/execution); `DOMAIN_CALL_RULES` permission graph; `@domain_boundary(target_domain)` decorator with thread-local stack enforcement; `DomainBoundaryViolation` and `TrustLevelViolation` exceptions; `@require_trust_level(minimum)` decorator
- `alembic/versions/0004_add_execution_log.py`: `execution_log` table (context_id PK, initiated_by, domain, trust_level, policy_set, workspace_id, created_at, parent_context_id, is_replay, event_type, notes)

**P-1 — Connector Trust & Versioning**
- `BaseClient`: added `TRUST_LEVEL: str = "semi_trusted"`, `API_VERSION: str = ""`, `API_PREFIX: str = ""`, `COST_UNIT: int = 1` class variables; added `_context: Any = None` attribute for budget tracking
- `BaseClient._request()`: deducts `COST_UNIT` from `ExecutionContext.budget` when a context is attached; raises `BudgetExceeded` when exhausted
- `BudgetExceeded(GNATClientError)`: new exception with `connector`, `cost`, `remaining` attributes
- 16 connectors updated with explicit `TRUST_LEVEL`, `API_VERSION`, `API_PREFIX`: Splunk, XSOAR, Graylog, Security Onion, Sentinel, QRadar, Elastic, Wazuh (trusted_internal); ThreatQ, CrowdStrike, Feedly, VirusTotal, MISP, Recorded Future (semi_trusted); AlienVault, Shadowserver (untrusted_external)

**4B — Idempotency & Schema Evolution**
- `alembic/versions/0005_add_idempotency.py`: `idempotency_key VARCHAR(255)` column with partial unique index on `workspace_objects`
- `WorkspaceObjectModel`: `idempotency_key` column added; `WorkspaceStore.make_idempotency_key()` static method computing `{connector_id}:{stix_type}:{external_id}:{sha1[:12]}`
- `STIXBase`: `schema_version: int = 1` class variable for ORM versioning
- `alembic/versions/0006_add_agent_tables.py`: `agent_sessions` and `agent_actions` tables

**4C — Hypothesis Engine, Negative Evidence, Reasoning**
- `gnat/stix/sdos/hypothesis.py`: `STIXHypothesis` custom SDO (`x-gnat-hypothesis`); fields: statement, confidence [0-1], status (pending/confirmed/refuted/inconclusive), supporting_evidence[], refuting_evidence[]; methods: `add_supporting_evidence()`, `add_refuting_evidence()`, `update_confidence()`, `close(verdict)`; full `to_dict()`/`from_dict()` serialization
- `gnat/stix/sdos/negative_evidence.py`: `NegativeEvidenceRecord` custom SDO (`x-gnat-negative-evidence`); fields: target_ref, queried_connector, ttl_seconds, query_timestamp; methods: `is_expired()`, `seconds_remaining()`
- `gnat/reasoning/hypothesis.py`: `HypothesisEngine` — `propose()`, `evaluate()` (Solr corroboration + weighted confidence), `close()`, `get()`, `list_all()`; confidence scoring: trusted_internal→0.9, semi_trusted→0.6, untrusted_external→0.3; auto-classify ≥0.75→confirmed, ≤0.15+refutation→refuted
- `gnat/reasoning/engine.py`: `ReasoningEngine` — `prioritize(observables, context, store_notes)` returning `[(observable, score, explanation)]` sorted descending; composite score: trust_weight×0.4 + age_factor×0.3 + corroboration_bonus×0.3 − neg_penalty×0.5; structured machine-readable explanation dicts; STIX `note` objects stored per scored observable

**4D — Agent Governance & HITL**
- `gnat/policy/models.py`: `AgentActionType` enum (read_stix/write_stix/delete_stix/enrich/ingest/export/trigger_playbook/manage_workspace/escalate/hypothesize); `agent_can_act(trust_level, action_type)` matrix; `_TRUST_ACTION_PERMISSIONS` per trust level
- `gnat/agents/governor.py`: `AgentGovernor` — `can_act()`, `require_can_act()`, `record_action()`, `rate_limit_check()` (sliding-window counter), `get_action_log()`, `set_policy_override()`; `AgentAction` dataclass with `to_dict()`; `RateLimitExceeded` and `AgentPermissionDenied` exceptions
- `gnat/agents/hitl.py`: `HITLGateway` bridging `AgentGovernor` to existing `gnat/review/service.py`; four-tier impact model: low/medium auto-approve, high→ReviewItem PENDING, critical→PENDING + XSOAR notification via `XSOARClient.upsert_object()`; timeout auto-rejection; `evaluate()`, `submit_for_approval()`, `check_approval_status()`, `auto_approve_pending()`

**4E — Isolation, Performance, Testing**
- `alembic/versions/0007_workspace_trust_boundary.py`: `trust_boundary VARCHAR(50)` and `allowed_connector_refs TEXT` columns on `workspaces`
- `alembic/versions/0008_query_cost_log.py`: `query_cost_log` table for per-connector cost tracking
- `WorkspaceModel`: `trust_boundary` and `allowed_connector_refs` columns added
- `Workspace`: `trust_boundary` and `allowed_connector_refs` attributes loaded from DB; `check_connector_trust(connector)` enforces trust rank and allowlist at connector instantiation
- `gnat/testing/__init__.py` + `gnat/testing/simulation.py`: `SimulationConnector(BaseClient)` — canned STIX fixtures, no network; `ReplayRunner` — replays `execution_log` sequences through pipeline with assertion support; `AgentTestHarness` — mock-approves all HITL submissions for deterministic agent tests

### Added — AI & Connector Improvements

**Google Gemini provider (`gnat/agents/gemini.py`)**
- `GeminiProvider(LLMProvider, BaseClient)`: full Gemini 2.0/1.5 support via `POST /v1beta/models/{model}:generateContent`; auth via `x-goog-api-key` header; system messages mapped to `systemInstruction`; "assistant" → "model" role translation; `chat()` returns OpenAI-compatible `choices[0].message.content` envelope; `structured()` uses `response_mime_type: application/json` for reliable JSON output; default model `gemini-2.0-flash`
- `LLMClient` now accepts `backend="gemini"` — previously raised `NotImplementedError`; error message updated to list `gemini` as supported
- `ClaudeProvider` default model updated from `claude-3-5-sonnet-20241022` to `claude-sonnet-4-6`

**ResearchLibrary Solr integration**
- `ResearchLibrary.__init__` accepts optional `search_index` parameter (defaults to `NullSearchIndex`)
- `search()` dispatches to Solr when a `SolrSearchIndex` is attached, otherwise uses the existing in-memory scan
- `_memory_search()`: extracted from former `search()` implementation
- `_solr_search()`: Solr path — fetches STIX IDs from index, resolves to `ResearchEntry` objects via `_entry_by_stix_id()`
- `_entry_by_stix_id()`: reverse-lookup scan from STIX object ID → containing `ResearchEntry`
- `_index_entry_objects()`: indexes all STIX objects in an entry into the search sidecar; called from `promote()` after staging write; failures logged, never raised
- `default()` and `from_manager()` factories call `_build_search_index_from_config()` to auto-configure the index from `[search]` INI section

**Recorded Future v3 connector hardening**
- `list_alerts()` and `list_playbook_alerts()`: support both `data.results` and `data.alerts` response envelope keys; support both `data.nextPageToken` and `data.pagination.nextPageToken` cursor paths
- `update_playbook_alert()`: tries PATCH first, falls back to PUT on failure (handles older RF API versions)
- `list_playbook_alert_categories()` and `list_fusion_files()`: defensive fallback key paths
- `get_fusion_file()`: handles raw-bytes, JSON-envelope, and embedded content responses

### Added — Federated Multi-GNAT Deployment

**Federation layer (`gnat/federation/`)**
- `FederationPeer` dataclass: models a remote GNAT peer with `peer_id`, `taxii_url`, `api_key`, `direction` (pull/push/both), `max_tlp` ceiling, optional `parent_peer_id` for hierarchical topologies, `workspace_filter` (explicit opt-in required — empty list = nothing shared), and sync state tracking (`last_sync_at`, `last_sync_status`)
- `PeerRegistry`: JSON-backed CRUD store for peer configuration (`~/.gnat/federation_peers.json`); `from_config()` parses `[federation.peer.*]` INI sections; `update_sync_status()` persists last sync result for incremental resumption
- `PeerSyncService`: pull and push orchestration with TLP gate (`_tlp_allowed`) enforced on every object before transmission; last-write-wins conflict resolution on STIX `modified` timestamp; `sync_from_peer()` and `push_to_peer()` with `FederationError` for unrecoverable failures; `PullResult` and `PushResult` summary classes
- `FederationScheduler`: creates one `FeedJob` per enabled peer; `start()` / `stop()` lifecycle; `trigger(peer_id)` for immediate one-off sync; `status()` returns per-peer sync state; persists `last_sync_at` to `PeerRegistry` via `on_success` callback for incremental resumption across restarts
- `FederationTopology`: `ancestors()`, `descendants()`, `parent()`, `children()`, `is_leaf()`, `is_root()`, cycle detection; `effective_max_tlp()` applies hierarchy defaults (AMBER up child→parent, GREEN down parent→child); `hierarchy_graph()` returns JSON topology for REST API

**GNATRemoteConnector (`gnat/connectors/gnat_remote/`)**
- `GNATRemoteConnector(BaseClient, ConnectorMixin)`: TAXII 2.1 client for remote GNAT instances; `authenticate()` sets Bearer token; `health_check()` pings discovery endpoint; `list_collections()`, `fetch_objects()`, `push_bundle()`, `list_objects()`, `get_object()`, `upsert_object()`, `delete_object()`; `to_stix()` / `from_stix()` are pass-throughs (both sides speak STIX 2.1 natively)
- Registered as `"gnat_remote"` in `CLIENT_REGISTRY`

**REST API (`gnat/serve/routers/federation.py`)**
- `GET /api/federation/peers` — list all peers with current sync status
- `POST /api/federation/peers` — register a new peer
- `DELETE /api/federation/peers/{peer_id}` — remove a peer and cancel its sync job
- `GET /api/federation/peers/{peer_id}/health` — ping remote TAXII discovery endpoint, return latency
- `POST /api/federation/peers/{peer_id}/sync` — trigger immediate sync (uses scheduler if running, falls back to direct sync)
- `GET /api/federation/topology` — mesh/hierarchy graph JSON (nodes, edges, hierarchy_edges)
- `create_app()` accepts `federation_registry`, `federation_scheduler`, `federation_sync_service` parameters

**Export (`gnat/export/delivery/targets.py`)**
- `TAXIIPushDelivery`: pushes STIX 2.1 bundles to a remote TAXII collection; wraps `HTTPDelivery` with TAXII media type headers

**Configuration**
- `config/config.ini.example`: added `[federation]`, `[federation.peer.acme-east]` (mesh), `[federation.peer.hospital-a]` and `[federation.peer.health-system-parent]` (hierarchical healthcare example)

**Tests**
- `tests/unit/federation/test_federation.py`: 60 tests covering `FederationPeer`, `PeerRegistry`, `PeerSyncService` TLP gate + conflict resolution, `FederationTopology` traversal + hierarchy graph, `FederationScheduler` lifecycle
- `tests/unit/connectors/test_gnat_remote.py`: 19 tests covering authenticate, health_check, list_collections, fetch_objects, push_bundle, CRUD operations

---

## [1.4.0]

### Added — Analyst OS Layer (Phase 3)

**Database Migrations (`alembic/`)**
- `alembic.ini` + `alembic/env.py`: Alembic 1.13 setup; URL resolved from `GNAT_DB_URL` env var → `[database]` INI section → `alembic.ini` default; unified metadata via `gnat.migrations.get_combined_metadata()`
- `alembic/versions/0001_init_all_tables.py`: initial schema (investigations, reports, workspaces, workspace_objects, enrichment_log, context_globals)
- `alembic/versions/0002_add_lineage_events.py`: `lineage_events` table with composite index on (object_id, timestamp)
- `alembic/versions/0003_add_metrics_events.py`: `metrics_events` table with index on (metric_type, timestamp)
- `gnat/migrations/__init__.py`: `get_combined_metadata()` aggregates all `_Base` objects for Alembic auto-detection
- `gnat/migrations/cli.py`: `gnat-db` CLI entry point with upgrade/downgrade/current/history/check/revision/stamp subcommands
- New extras: `[migrations]` (alembic + sqlalchemy); `[orchestration]` (sqlalchemy)
- New script: `gnat-db = "gnat.migrations.cli:main"` in pyproject.toml

**Plugin System (`gnat/plugins/`)**
- `GNATPlugin` ABC: `name`, `version`, `capabilities`, `description`; requires `register(registry)` implementation
- `PluginCapability` enum: CONNECTOR | READER | MAPPER | AGENT | REPORTER | HOOK
- `HookBus` singleton: thread-safe pub/sub with `on()` decorator, `register/unregister/emit/clear/handlers()`; 14 built-in `KNOWN_EVENTS`; async handler support; exceptions in handlers are caught and logged, never propagated
- `PluginRegistry`: load/unload/get/list/list_by_capability; entry_points discovery (`gnat.plugins` group); filesystem discovery via `GNAT_PLUGIN_DIRS`; `register_connector/reader/mapper()` wraps existing registries
- `load_plugins()`: reads `[plugins]` INI section + `GNAT_PLUGIN_DIRS` env var
- `[project.entry-points."gnat.plugins"]` section in pyproject.toml for third-party plugin declaration
- ADR-0036: Plugin Architecture — entry_points + filesystem discovery; HookBus pub/sub; backward-compatible connector/reader/mapper registration

**Policy Engine (`gnat/policy/`)**
- `Role` enum (VIEWER → ADMIN) + `Permission` enum (10 permissions) + static `ROLE_PERMISSIONS` matrix
- `PolicyEngine`: `evaluate(subject, permission)`, `evaluate_role(role, permission)`, `require(permission, key_store)` FastAPI `Depends` factory, `audit()` emits `policy_decision` HookBus event
- `build_audit_middleware(key_store)`: Starlette `BaseHTTPMiddleware` that times requests, resolves actor, emits structured log + `api_request` HookBus event
- `APIKey.role: str = "viewer"` field added; `APIKeyStore.add_key/generate_key()` gain `role=` kwarg
- `APIKey.to_dict()` now includes `role` field
- `build_gateway_router()` gains optional `policy_engine=` parameter; admin endpoints use `engine.require(Permission.MANAGE_KEYS)` instead of raw TLP check; old `_require_admin()` removed
- ADR-0037: Policy Engine — RBAC orthogonal to TLP, static permission matrix, FastAPI-native Depends integration

**TAXII 2.1 Write Endpoints**
- `TAXIICollection.can_write = True` for TLP:AMBER and TLP:RED collections
- POST `/taxii2/{api-root}/collections/{id}/objects/`: push STIX 2.1 bundle; requires `WRITE_TAXII` permission; validates `type=bundle`; routes `report` objects to `store.ingest_stix()`; returns TAXII 2.1 status record (202)
- DELETE `/taxii2/{api-root}/collections/{id}/objects/{stix-id}`: soft-delete by STIX ID; tries `store.delete_by_stix_id()` first, falls back to scan+delete; returns 404 on not found
- `build_taxii_router()` gains optional `policy_engine=` parameter
- `_ingest_stix_objects()` and `_soft_delete_object()` helpers (testable independently)
- Updated module docstring to document all 8 endpoints (6 read + 2 write)

**Investigation Query DSL (`gnat/analysis/query.py`)**
- `InvestigationQuery` dataclass: `status` list, `created_by`, `assigned_to`, `tags` list (ANY match), `classification` list, `date_from`/`date_to`, `text` (title substring), `has_hypothesis`, `has_linked_report`, `page`, `page_size`, `sort_by`, `sort_desc`
- `InvestigationStore.list()` now accepts `query: InvestigationQuery` with full filter → SQLAlchemy WHERE chain; `has_hypothesis`/`has_linked_report` post-filtered from JSON blob; legacy kwargs preserved for backward compatibility
- `InvestigationService.list()` accepts `InvestigationQuery` and passes it through
- SQL injection protection: `safe_sort_by` property validates against allowlist

**Serve Routers (`gnat/serve/routers/`)**
- `gnat/serve/routers/investigations.py`: 11 REST endpoints — list (full `InvestigationQuery` filter params), create, get, update, transition, add note, add task, update task, add hypothesis, link artifacts, summary
- `gnat/serve/routers/analysis.py`: 7 REST endpoints — graph/pivot, graph/filter, graph/shortest-path, copilot/gaps, copilot/draft, reports/{id}/export/stix, metrics/investigations, metrics/enrichment
- `gnat/serve/app.py`: `create_app()` and `run()` gain `investigation_service`, `graph_query`, `gap_detector`, `report_drafting_assistant`, `export_service`, `metrics_aggregator` parameters; new routers registered with `_api_deps`

**Agent Orchestration (`gnat/agents/`)**
- `gnat/agents/workflow.py`: `Workflow`, `WorkflowContext`, `WorkflowStep`, `WorkflowResult` — sequential DAG executor with `on_success`/`on_failure` routing, cycle detection, elapsed timing
- `gnat/agents/steps.py`: built-in step factories — `enrich_step`, `correlate_step`, `gap_detect_step`, `draft_report_step`, `transition_step`, `fn_step`; all accept `None` components for no-op/test mode
- `gnat/agents/workflows/phishing_triage.py`: 5-step pre-built phishing triage workflow (enrich → correlate → gap_detect → draft_report → transition IN_PROGRESS)
- `gnat/agents/workflows/incident_response.py`: 5-step incident response workflow (enrich → correlate → gap_detect → draft_report → transition REVIEW)

**Data Lineage (`gnat/lineage/`)**
- `LineageEventType` enum: INGESTED | ENRICHED | NORMALIZED | LINKED | EXPORTED | REPORTED | DELETED
- `LineageEvent` dataclass: immutable append-only record with UUID4 id, timestamp, object_id, actor, source, metadata dict
- `LineageStore` (SQLAlchemy): `lineage_events` table; `append()`, `query(object_id)`, `query_by_type()`, `query_by_actor()`, `count()`; composite index on (object_id, timestamp)
- `LineageTracker`: convenience wrapper with one `record_*` method per event type; `store=None` → silent no-op; exceptions never propagate to callers
- ADR-0038: Data Lineage Tracking — append-only event log; zero new runtime dependencies; optional deployment

**Analyst Metrics (`gnat/metrics/`)**
- `MetricType` enum: 9 types covering investigation lifecycle, enrichment effectiveness, report publishing, gap detection, false positives
- `MetricEvent` dataclass with metric_type, value, labels dict, timestamp
- `MetricsCollector`: thread-safe ring-buffer (configurable max_size); `record()`, `snapshot()`, `since(cutoff)`, `clear()`
- `MetricsAggregator`: `investigation_summary(days)`, `enrichment_effectiveness(platform, days)`, `gap_frequency(days)`, `false_positive_rate(days)` — all return structured dicts

**Architecture Decision Records**
- ADR-0036: Plugin Architecture
- ADR-0037: Policy Engine (RBAC)
- ADR-0038: Data Lineage Tracking

**Tests**
- `tests/unit/test_plugins.py`: 13 tests covering capabilities, ABC enforcement, registry lifecycle, HookBus events/routing/error-swallowing, connector registration
- `tests/unit/test_policy.py`: 13 tests covering role/permission matrix, engine evaluation (by role, subject, fallback), audit hook emission, APIKey role field, init exports
- `tests/unit/test_taxii_write.py`: 12 tests covering collection write flags, ingest helper, soft-delete helper (direct API + fallback scan), router construction
- `tests/unit/agents/test_workflow.py`: 18 tests covering context/step/workflow construction, success/failure/routing runs, all step factories, pre-built workflows
- `tests/unit/test_lineage.py`: 16 tests covering event model, store append/query/count, tracker convenience methods, no-op mode
- `tests/unit/test_metrics.py`: 17 tests covering model, collector (ring buffer, thread safety, snapshot filtering, since), aggregator (investigation summary, enrichment effectiveness, gap frequency, false positive rate)
- `tests/unit/analysis/test_investigation_query.py`: 13 tests covering dataclass helpers (offset/limit/safe_sort_by), full InvestigationStore.list() integration (all filters, pagination, legacy kwargs)

### Added — Discord Bot Connector

**`gnat/connectors/discord/connector.py`** — full `ConnectorMixin` implementation
- `DiscordClient(BaseClient, ConnectorMixin)` targeting Discord REST API v10
- `authenticate()`: sets `Authorization: Bot <token>` + `Content-Type: application/json`; normalises bare token (adds `Bot ` prefix)
- `health_check()`: `GET /api/v10/gateway/bot`
- `get_object("note"|"indicator", "<channel_id>:<message_id>")` → fetches message → STIX `note`
- `get_object("observed-data", channel_id)` → fetches channel → STIX `observed-data`
- `get_object("identity", user_id)` → fetches user → STIX `identity`
- `list_objects("note"|"indicator", filters={"channel_id": ...})` → messages → list of STIX `note`
- `list_objects("observed-data", filters={"thread_id": ...})` → thread messages → STIX `note` list
- `list_objects("identity", filters={"guild_id": ...})` → guild members → STIX `identity` list
- `upsert_object("note", {channel_id, content})` → posts message → STIX `note`
- `delete_object("note"|"indicator", "<channel_id>:<message_id>")` → deletes message
- Domain helpers: `post_message()`, `list_messages()`, `delete_message()`, `start_thread()`, `list_archived_threads()`, `get_channel()`, `get_message()`, `get_user()`, `list_members()`
- STIX translation: messages → `note` (with `x_discord` extension); channels → `observed-data`; users → `identity`
- `from_stix("note")` → Discord message payload `{content, channel_id}`
- `guild_id` constructor param for default member listing
- Registered as `"discord"` in `gnat.clients.CLIENT_REGISTRY`
- `config/config.ini.example`: added `[discord]` section with `host`, `bot_token`, `guild_id`
- 52 unit tests in `TestDiscordClient` covering all methods, STIX translation, registry registration, capability reflection, and snowflake helper

---

### Added — AI Intel Review Queue

**Review Package (`gnat/review/`)**
- `ReviewStatus` enum: PENDING | APPROVED | REJECTED | MODIFIED
- `ReviewItem` dataclass: full review lifecycle record with stix_id, stix_type, stix_data, source/target workspace, submitted_by/at, reviewer fields, confidence_override, modified_properties, promoted_at
- `ReviewItem.to_dict()` / `from_dict()` serialization round-trip
- `ReviewQueueStore`: SQLAlchemy-backed `review_queue` table; `save()`, `get()`, `delete()`, `list()` (status + stix_type + submitted_by filters + pagination), `count()`, `stats()` returning per-status breakdown
- `ReviewService`: `submit()` validates STIX id/type; `approve()` validates confidence override 0-100; `reject()` records reason; `modify()` captures analyst property overrides (MODIFIED state); `promote()` merges modified_properties + confidence + x_source_type="analyst_verified" + removes x_ai_ceiling, optionally writes to target workspace via workspace_manager; `bulk_approve()`, `bulk_reject()`; `stats()` adds `total` key; `list()` with pagination
- `ReviewError` for invalid operations (wrong status, duplicate promote, missing item)

**REST Router (`gnat/serve/routers/review.py`)**
- 8 endpoints: GET/POST `/api/review`, GET `/api/review/stats`, GET `/api/review/{id}`, POST `/api/review/{id}/approve`, POST `/api/review/{id}/reject`, POST `/api/review/{id}/modify`, POST `/api/review/{id}/promote`
- Service resolved via `app.state.review_service`; workspace_manager via `app.state.workspace_manager`
- Registered in `gnat/serve/app.py`

**TUI Review Screen (`gnat/tui/screens/review.py`)**
- `ReviewScreen(Screen)` with F6 / Ctrl+R / Ctrl+A / Ctrl+D bindings
- Toolbar: search Input + status Select + stix_type Select + Refresh button
- Stats bar showing pending/approved/rejected/modified counts
- DataTable with id/stix_id/type/status/submitted_by/workspace columns
- Detail pane: labels + reviewer notes Input + confidence Input + Approve/Reject buttons
- `_init_service()`: resolves `GNAT_DB_URL`, graceful ImportError + DB error handling
- `GNATApp` gains F6 binding and Review TabPane (sixth tab); `gnat tui review` screen choice added

**CLI (`gnat review`)**
- `gnat review list` (--status, --type, --page, --page-size)
- `gnat review approve <id>` (--by, --notes, --confidence)
- `gnat review reject <id>` (--by, --reason)
- `gnat review stats`

**STIX Object Validation (`gnat/stix/object_validator.py`)**
- `STIXObjectValidator`: validates required props per SDO/SCO/SRO/meta type (19+16+2+4 types), ID format, timestamps, booleans, integers, confidence 0-100, open/closed vocabularies, `_ref`/`_refs` reference formats
- `STIXBundleValidator`: validates bundle structure + all objects; deduplicates IDs; aggregates errors/warnings
- `validate_object()` / `validate_bundle()` module-level convenience functions
- `ObjectValidationResult` / `BundleValidationResult` dataclasses with valid/errors/warnings fields
- `ObjectValidationError` exception (raised when `raise_on_error=True`)
- Strict mode: open vocab violations become errors; custom types/extensions disallowed
- All exported from `gnat.stix`

**Tests**
- `tests/unit/review/test_review.py`: 40 tests — ReviewStatus values, ReviewItem defaults/roundtrip/optional-fields, ReviewQueueStore CRUD/filters/stats, ReviewService submit/approve/reject/modify/promote/bulk ops/stats/pagination, package exports
- `tests/unit/test_stix_object_validator.py`: 89 tests covering all validation paths, SDO/SCO/SRO types, vocabularies, bundle validation, strict mode, custom types, init exports
- `tests/unit/test_tui.py` extended: ReviewScreen import, F6 binding, 6-tab assertion, `review` screen CLI choice

---

### Added — Integration & CLI Hardening (Phase 4)

**CLI Subcommands (`gnat/cli/main.py`)**
- `gnat investigation` subcommand group: `list` (--status, --created-by, --tag, --text, --page, --page-size), `create` (--title, --created-by, --description, --tlp, --tags), `get <id>`, `transition <id> <status>` (--note, --author), `note <id>` (--content, --author), `link <id>` (--indicators, --reports)
- `gnat plugins` subcommand group: `list` (loads entry_points + env dirs, tabulates all registered plugins), `load <directory>` (on-demand directory scan)
- `gnat db` subcommand group: `upgrade`, `downgrade` (-1), `current`, `history`, `revision` (-m, --autogenerate), `stamp <revision>` — all delegated to `gnat.migrations.cli.run_db_command()`
- `gnat tui` now accepts `investigations` as a screen choice
- DB URL resolved from `GNAT_DB_URL` env var (default `sqlite:///gnat.db`) for investigation subcommand
- Graceful ImportError handling: missing SQLAlchemy → exit 1 with install hint; missing Alembic → exit 1 with install hint

**Data Lineage Wiring**
- `IngestPipeline.with_lineage(tracker)`: fluent builder that sets `_lineage`; after each `obj.save()` emits `tracker.record_ingest()` — exceptions never propagate
- `ExportPipeline.with_lineage(tracker)`: fluent builder on `gnat.export.base.ExportPipeline`; after successful delivery emits `tracker.record_export()` for each delivered object
- `ReportService.__init__` gains optional `lineage=` parameter; `publish()` emits `tracker.record_report()` after STIX bundle generation

**MetricsCollector HookBus Bridge (`gnat/metrics/hooks.py`)**
- `register_metrics_hooks(collector)`: registers closures on `HookBus.instance()` for `investigation_opened`, `investigation_closed` (+ INVESTIGATION_DURATION from `duration_seconds`), `report_published`, `gap_detected`
- `unregister_metrics_hooks()`: removes all previously registered closures for clean test teardown
- Exported from `gnat.metrics.__init__`

**TUI Investigations Panel (`gnat/tui/screens/investigations.py`)**
- `InvestigationsScreen(Screen)` with F5 / Ctrl+R / Ctrl+N bindings
- `compose()`: Header, search Input, status Select, Refresh/New buttons, DataTable (id/title/status/tlp/created_by/updated), detail pane with transition Select
- `_init_service()`: creates `InvestigationStore` + `InvestigationService` from `GNAT_DB_URL`; graceful ImportError + DB error handling with status message
- `_load_investigations(status_filter, text)`: builds `InvestigationQuery`, populates DataTable
- `on_data_table_row_selected()`: shows detail pane with full investigation metadata
- `_apply_transition()`: calls `service.transition()`, refreshes table
- `GNATApp` gains `db_url=` parameter; F5 binding added; Investigations TabPane wired into `compose()`; `run()` and `_cmd_tui()` updated

**Tests**
- `tests/unit/test_cli_phase4.py`: 25 tests — parser registration (investigation/plugins/db), investigation list/create/transition (success + error paths, missing SQLAlchemy), plugins list/load (empty + populated + error), db subcommand (upgrade/downgrade/-1/current/revision with message and autogenerate/stamp/missing alembic/runtime error)
- `tests/unit/test_lineage.py` (extended): `with_lineage()` fluent API, IngestPipeline + ExportPipeline + ReportService lineage emission
- `tests/unit/test_metrics.py` (extended): `register_metrics_hooks` / `unregister_metrics_hooks` — investigation_opened, investigation_closed + duration, report_published, gap_detected, unregister stops capture
- `tests/unit/test_tui.py` (extended): InvestigationsScreen import, `db_url=` param, F5 binding, 5-tab assertion, `investigations` screen CLI choice

---

### Added — Analysis Layer (Phase 0 + 1 + 2)

**`gnat.analysis` — Analyst-facing foundation**
- `gnat/analysis/tlp.py`: `TLPLevel` enum implementing TLP 2.0 (WHITE/CLEAR/GREEN/AMBER/AMBER+STRICT/RED) with STIX marking definition IDs, hex colours, rank ordering, and human-readable labels
- `gnat/analysis/confidence.py`: `ConfidenceScore` dataclass combining the NATO Admiralty Scale (source reliability A–F, information credibility 1–6) with a STIX 2.1 numeric confidence value (0–100); `ConfidenceLevel` convenience bands (HIGH/MEDIUM/LOW); convenience factories `ConfidenceScore.high/medium/low()`

**`gnat.analysis.investigations` — Investigation lifecycle**
- `Investigation` dataclass: top-level analyst workspace with status state machine (OPEN → IN_PROGRESS → REVIEW → CLOSED), TLP classification, scope constraints, hypothesis tracking, analyst notes, tasks, and artifact linking
- `Hypothesis`, `AnalystNote`, `InvestigationTask`, `InvestigationScope` dataclasses
- `InvestigationStore`: SQLAlchemy-backed persistence (`sqlite:///:memory:` for tests, shared engine support); follows existing `WorkspaceStore` JSON-serialization pattern; zero-migration `create_all()` schema init
- `InvestigationService`: enforces state machine transitions, owns all mutation operations (create/get/list/delete/transition, add_note/task/hypothesis, link_indicators/observables/threat_actors, add_tags, summary)
- `InvestigationError` for invalid operations

**`gnat.reporting` — Intelligence product lifecycle**
- `Report` dataclass: structured intelligence product with five-state lifecycle (DRAFT → REVIEW → APPROVED → PUBLISHED → ARCHIVED), versioning with `parent_report_id` linkage, TLP classification, evidence binding, attribution, STIX export
- `Finding`, `EvidenceLink`, `Attribution`, `ReportSection`, `ChangelogEntry` dataclasses
- `ReportType` enum: INCIDENT_REPORT / THREAT_ACTOR_PROFILE / CAMPAIGN_ANALYSIS / DAILY_BRIEF / VULNERABILITY_ADVISORY / FINISHED_INTELLIGENCE
- `ReportStore`: SQLAlchemy-backed persistence with same zero-migration pattern as `InvestigationStore`
- `ReportService`: enforces lifecycle transitions; `publish()` auto-generates STIX bundle and sets `stix_report_ref`; `create_revision()` creates new draft from published version with incremented version
- `report_to_stix_bundle()`: serialises a `Report` to a STIX 2.1 bundle (report SDO + identity SDO + threat-actor SDO if attribution set + attributed-to relationship); TLP `object_marking_refs`; `x_gnat_*` extension fields
- Three report templates (YAML): `incident_report.yaml`, `threat_actor_profile.yaml`, `campaign_analysis.yaml`
- `[analysis]` and `[reporting]` optional dependency extras (both require `sqlalchemy>=2.0`)

**Architecture Decision Records**
- ADR-0031: Analysis Layer Architecture — layered consumer model; `WorkspaceStore` pattern for new tables; no new storage backend
- ADR-0032: STIX Custom Objects — `x-gnat-investigation` SDO schema; `investigates` custom relationship verb; standard `report` SDO for finished intelligence
- ADR-0033: Confidence Scoring Model — rationale for Admiralty Scale; STIX numeric confidence for interoperability; HIGH/MEDIUM/LOW bands aligned with ATT&CK convention
- ADR-0034: Report Lifecycle — five-state machine with reject path; immutability on PUBLISHED; versioning model; STIX bundle triggered on publish

**Tests**
- `tests/unit/analysis/test_confidence.py`: 16 tests covering TLP ordering, STIX marking IDs, confidence bands, Admiralty Scale, serialization roundtrips, bounds validation
- `tests/unit/analysis/test_investigations.py`: 24 tests covering model roundtrips, state machine valid/invalid transitions, full service lifecycle (create/get/transition/note/task/hypothesis/link/delete/list/summary)
- `tests/unit/reporting/test_reports.py`: 30 tests covering report model, evidence links, attribution, full DRAFT→PUBLISHED lifecycle, immutability enforcement, STIX bundle structure and field correctness, revision creation

**Bug fixes**
- `gnat/investigations/builder.py`: CASE_ID seed expansion passed a list to `normalize()` instead of iterating it (fixed in previous session)
- `gnat/investigations/normalizer.py`: Missing `("threatq", "incident")` dispatch alias — ThreatQ Events are the investigation container but the builder calls `normalize(platform, "incident", ...)` for all CASE_ID seeds
- `gnat/investigations/workspace.py`: `_node_to_stix_base` and Relationship tagging used `obj["key"] = value` item assignment; `STIXBase` only supports `obj.key = value` attribute access — fixed, workspace now materialises all nodes correctly (was 0 nodes materialised)

**Example**
- `docs/tutorials/investigation_xsoar_tq_gm_powerbi.py`: End-to-end cross-platform investigation script (XSOAR + ThreatQ + GreyMatter → EvidenceGraph → workspace → Power BI xlsx); `--mock` flag for dry runs without live credentials; completeness check verifying 14 investigation methods across 3 platforms

### Added — Analysis Layer (Phase 3: Correlation Engine + Analyst Assistance)

**`gnat.analysis.correlation` — Cross-platform indicator correlation**
- `EntityResolver`: deduplicates indicators across platforms by canonical value; normalises IPv4 (strips /32), IPv6 (compressed), domain (lowercase, trailing dot stripped), URL (scheme+host lowercase), email, MD5/SHA1/SHA256 hashes, hostname, and ASN; groups cross-platform aliases into `EntityGroup` objects
- `IndicatorRecord`: lightweight dataclass for platform-sourced IOC records with platform, ioc_type, value, confidence, tags, and first/last seen timestamps
- `EntityGroup`: aggregated view of cross-platform aliases; exposes `platforms`, `is_cross_platform`, `max_confidence`, `all_tags` properties
- `RelationshipScorer`: scores entity-to-entity relationships using co-occurrence (0/0/15/30/45 pts for 1–4+ platforms), recency (≤7d=25pts, ≤30d=15pts, ≤90d=5pts), and source-reliability bonus (+10 if all ≥ B_USUALLY_RELIABLE); output is a `ConfidenceScore`
- `ClusterDetector`: rule-based heuristic clustering of `EntityGroup` objects via shared /24 subnet, shared tags, platform co-occurrence, and timing proximity (72-hour window); BFS connected-component grouping; `Cluster` dataclass with member IDs, signals list, and confidence score
- `EnrichmentDispatcher`: fan-out enrichment across registered connectors; tries `search_indicators_by_value` → `search_observables_by_value` → `list_objects` in priority order; fully best-effort (errors logged, never raised); returns `EnrichmentResult` dict per platform

**`gnat.analysis.timeline` — Chronological event reconstruction**
- `TimelineBuilder`: reconstructs investigation timelines from `Investigation` objects (opened/notes/tasks/closed), `EvidenceGraph` nodes (via `time_window` and `stix` metadata), and raw records (arbitrary timestamp + title fields)
- `TimelineEvent`: dataclass with timestamp, event_type, title, source, description, and linked_artifacts
- `TimelineEventType` enum: 14 event types covering incident/investigation lifecycle, analyst actions, and observables

**`gnat.analysis.graph` — Evidence graph querying**
- `GraphQuery`: adjacency-index BFS pivot/expand/filter over `EvidenceGraph` objects; supports N-hop pivoting, cross-node expansion, and multi-dimensional filtering (confidence, platform set, date range, node types)
- `GraphContext`: results container with nodes dict, edges list, seed_ids; `platforms()`, `node_count`, `edge_count` properties; `to_dict()` for API serialisation
- `GraphQuery.shortest_path()`: BFS shortest-path between any two nodes

**`gnat.analysis.copilot` — Analyst assistance**
- `GapDetector`: 8 rule-based evidence gap detection rules (no-evidence/CRITICAL, lateral-movement-no-host/HIGH, exfiltration-no-network/HIGH, attribution-no-ttp/HIGH, ransomware-no-hash/MEDIUM, phishing-no-email-or-domain/MEDIUM, c2-no-network-ioc/HIGH, no-campaign-linkage/LOW); `detect()` per hypothesis, `detect_all()` across all hypotheses, `summary()` counts by severity
- `GapRecommendation`: dataclass with rule_id, severity, description, suggested_action
- `ReportDraftingAssistant`: LLM-backed executive summary and key-findings narrative drafting; graceful fallback (placeholder text + warning) when no LLM configured; two-call `draft_full()` for merged results; configurable prompt templates; evidence capped at 20 links to avoid token explosion
- `DraftResult`: output dataclass with executive_summary, key_findings_narrative, model, prompt/completion token counts, and warnings

### Added — Dissemination Layer (Phase 4)

**`gnat.dissemination.export` — Report export**
- `ExportService`: exports published intelligence reports to STIX 2.1 bundle, GNAT JSON, or PDF; uses cached `stix_bundle_json` when available; SHA-256 checksum on all outputs
- `ExportFormat` enum: STIX / JSON / PDF
- `ExportResult`: dataclass with report_id, format, path, size_bytes, checksum (SHA-256 hex), exported_at
- `export_stix_bundle()`: in-memory STIX bundle retrieval without disk write
- PDF export via `gnat.reports.renderers.PDFRenderer`; falls back to plain-text if reportlab not installed

**`gnat.dissemination.taxii` — TAXII 2.1 server**
- `TAXIICollection`: TAXII 2.1 collection backed by GNAT report store; deterministic UUIDs (uuid5); TLP rank-based `is_accessible()` access control
- `COLLECTIONS`: four built-in collections (tlp-white/green/amber/red) with cumulative TLP filtering
- `build_taxii_router()`: FastAPI router implementing all six TAXII 2.1 read-only endpoints (Discovery, API Root, Collections list/metadata, Objects, Manifest); offset-based pagination with base64 cursor; `application/taxii+json;version=2.1` content type
- ADR-0035: FastAPI over dedicated TAXII library; TLP-based collection model; single-process TAXII+API mount

**`gnat.dissemination.notify` — Webhook notifications**
- `WebhookNotifier`: fan-out HTTP POST notifications to registered subscribers; TLP-level access control per subscriber; HMAC-SHA256 `X-GNAT-Signature` header when secret configured; best-effort delivery (errors logged, never raised)
- `WebhookSubscription`: dataclass with id, url, min_tlp, secret, events list, timeout
- `DeliveryReceipt`: per-delivery outcome with status_code, success flag, error message, attempted_at

**`gnat.dissemination.api` — REST gateway and API key management**
- `APIKey`: API key dataclass with TLP access level, label, expiry, enabled flag, SHA-256 token hash property
- `APIKeyStore`: in-memory bearer token store with add/generate/revoke/delete/list operations; `generate_key()` produces cryptographically random 32-byte tokens
- `build_gateway_router()`: FastAPI router for report listing/metadata/export (STIX/JSON/PDF) and admin key management; TLP-filtered report responses; PDF via `FileResponse` with background cleanup

**Optional extras**
- `gnat[taxii-server]`: FastAPI + uvicorn for TAXII 2.1 server
- `gnat[dissemination]`: FastAPI + uvicorn + SQLAlchemy for full dissemination layer

**Tests**: 142 new unit tests across `tests/unit/analysis/test_correlation.py`, `test_timeline.py`, `test_graph.py`, `test_copilot.py`, `tests/unit/dissemination/test_export.py`, `test_taxii.py`, `test_notify.py`

---

## [v1.3.0] — Unreleased

9 new platform connectors (AWS Security Hub/GuardDuty, Cribl Stream, Datadog, Dragos, HIBP, SecurityScorecard, Synapse, Tanium, Trend Micro Vision One). Unified multi-LLM client (`LLMClient`) with Claude, OpenAI, and Grok backends and automatic fallback. Deprecated `PENDING_ITEMS.md` — release notes, ADRs, and the architecture implementation plan now supersede it.

→ [Full release notes](docs/releases/v1.3.0.md)

---

## [v1.2.0] — 2026-03-30

25 new platform connectors across three batches (Censys, ServiceNow SecOps, Darktrace, ExtraHop, Lansweeper, Vectra, Sophos, Trellix, BitSight, Flashpoint, HudsonRock, Intel 471, UpGuard, Carbon Black, CortexXDR, Dragos, FortiEDR, FortiSIEM, FortiSOAR, Google Chronicle, GreyNoise, LogRhythm, Nozomi, Prisma Cloud, Shodan). CISA KEV connector. 89 new unit tests for previously untested connectors. Mass lint cleanup (4,647 auto-fixed issues + 141 manual fixes).

→ [Full release notes](docs/releases/v1.2.0.md)

---

## [v1.1.0] — 2026-03-30

13 new connectors (Armis, Axonius, Cortex Xpanse, CyCognito, DefectDojo, Greenbone, Group-IB, Orca, Qualys, SentinelOne, Tenable One, Wiz, ZeroFox). Optional Rust-accelerated IOC processing (`gnat-core`). Web dashboard, Textual TUI, TAXII 2.1 server, NLP query engine, STIX pattern validator, multi-tenant workspace isolation, XSOAR content pack generator, upstream contribution pipeline, connector health monitor, Solr/Grafana observability, Docker integration test harness, Jira connector, and numerous connector additions and fixes.

→ [Full release notes](docs/releases/v1.1.0.md)

---

## [v1.0.0] — 2026-03-28

First stable release. 29 platform connectors including SIEM/IDS/IPS platforms (Elastic, Graylog, MISP, OpenCTI, OSSIM, QRadar, Security Onion, Sentinel, Snort, Suricata, Wazuh, Zeek, ControlUp DEX, AlienVault OTX). Solr search sidecar. Report generation pipeline (PDF, HTML, DOCX, Markdown) with AI narration. AI agents (ResearchAgent, ParsingAgent, CopilotReader). Research Library with curation workflow.

→ [Full release notes](docs/releases/v1.0.0.md)

---

## [v0.9.0] — 2025-09-15

Research Library three-tier knowledge base (personal / staging / library workspaces) with TTL-based curation and INI configuration.

→ [Full release notes](docs/releases/v0.9.0.md)

---

## [v0.8.0] — 2025-07-01

AI agent integration: ResearchAgent (Claude-powered threat synthesis), ParsingAgent (unstructured text → STIX), and CopilotReader (Microsoft Copilot DirectLine). Config via `[claude]` INI section.

→ [Full release notes](docs/releases/v0.8.0.md)

---

## [v0.7.0] — 2025-05-15

Export pipeline with fluent builder API. 11 filter types (TypeFilter, ConfidenceFilter, TLPFilter, SectorFilter, etc.), EDL and Netskope CE transforms, and multiple delivery targets including EDLServer (FastAPI).

→ [Full release notes](docs/releases/v0.7.0.md)

---

## [v0.6.0] — 2025-04-01

Feed scheduling layer: `FeedScheduler`, `FeedJob`, `IngestJob`, cron expression support via croniter, and `gnat schedule` CLI subcommands.

→ [Full release notes](docs/releases/v0.6.0.md)

---

## [v0.3.0] — 2025-03-20

Async client (`AsyncGNATClient` on httpx). Full CLI (`gnat ping`, `query`, `list`, `ingest`, `codegen`, `config`). Visualization layer (TabularView, GraphView with sigma.js WebGL for 1000+ nodes, GrafanaServer, PowerBIExporter). Context system (GlobalContext, Workspace, WorkspaceManager, FlatFileStore/WorkspaceStore). Sphinx documentation. GitHub Actions CI/CD.

→ [Full release notes](docs/releases/v0.3.0.md)

---

## [v0.1.0] — 2025-03-19

Initial release. Core client layer (`GNATClient`, `BaseClient`, `CLIENT_REGISTRY`). STIX 2.1 ORM (`STIXBase` + 12 domain/observable types). 6 platform connectors (ThreatQ, CrowdStrike, Proofpoint, Netskope, XSOAR, Recorded Future). Ingestion framework with 14 source readers and 12 record mappers. OpenAPI code generator. Full unit and integration test scaffold.

→ [Full release notes](docs/releases/v0.1.0.md)

---

[Unreleased]: https://github.com/your-org/gnat/compare/v1.2.0...HEAD
[v1.3.0]: https://github.com/your-org/gnat/compare/v1.2.0...v1.3.0
[v1.2.0]: https://github.com/your-org/gnat/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/your-org/gnat/compare/v1.0.0...v1.1.0
[v1.0.0]: https://github.com/your-org/gnat/compare/v0.9.0...v1.0.0
[v0.9.0]: https://github.com/your-org/gnat/compare/v0.8.0...v0.9.0
[v0.8.0]: https://github.com/your-org/gnat/compare/v0.7.0...v0.8.0
[v0.7.0]: https://github.com/your-org/gnat/compare/v0.6.0...v0.7.0
[v0.6.0]: https://github.com/your-org/gnat/compare/v0.3.0...v0.6.0
[v0.3.0]: https://github.com/your-org/gnat/compare/v0.1.0...v0.3.0
[v0.1.0]: https://github.com/your-org/gnat/releases/tag/v0.1.0

---

*Licensed under the Apache License, Version 2.0*
