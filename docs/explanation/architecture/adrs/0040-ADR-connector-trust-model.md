# ADR-0040 — Connector Trust Level Classification

**Date:** 2026-04-09  
**Status:** Accepted  
**Deciders:** GNAT Platform Team

---

## Context

GNAT integrates with 99 distinct security and threat intelligence platforms.
These connectors span a wide spectrum of data reliability and authority:

- An internal SIEM (Splunk, Microsoft Sentinel, IBM QRadar) is operated by the
  organisation itself; its indicators are authoritative by definition.
- Commercial threat intelligence feeds (ThreatQ, Recorded Future, CrowdStrike)
  are curated by professional analysts and carry strong but not absolute
  reliability.
- Community or public feeds (AlienVault OTX, Shadowserver, CISA KEV) are
  maintained by volunteers or government bodies; data quality varies widely and
  indicators may be stale or incorrectly attributed.

Prior to this ADR every connector carried **equal implicit trust**.  The
enrichment dispatcher treated a hit from AlienVault OTX identically to a hit
from the organisation's own Splunk deployment.  The `ReasoningEngine`
introduced in Phase 4C (see ADR-0044) needed a **stable, declarative source of
trust authority** to compute trust-weighted scores without requiring each call
site to re-derive trust from the connector's identity.

Three requirements drove the design:

1. **Declarative, not runtime-computed:** trust level must be a class-level
   constant that static analysis tools and policy agents can inspect without
   instantiating a connector.
2. **Propagatable:** trust must flow automatically from connector declaration
   into `ExecutionContext` (ADR-0039) and from there into `ReasoningEngine`
   scoring (ADR-0044).
3. **Auditable:** attempts to escalate trust above what a connector class
   declares must be detected and logged.

---

## Decision

### Class Variable on `BaseClient`

Add a single class variable to `gnat/clients/base.py`:

```python
class BaseClient:
    """Base HTTP client for all GNAT connectors."""

    # Trust level for data produced by this connector.
    # Subclasses MUST override this if they are not semi-trusted.
    TRUST_LEVEL: str = "semi_trusted"
```

Every concrete connector subclass overrides `TRUST_LEVEL` to one of three
enumerated string constants defined in `gnat/core/trust.py`:

```python
TRUSTED_INTERNAL    = "trusted_internal"
SEMI_TRUSTED        = "semi_trusted"
UNTRUSTED_EXTERNAL  = "untrusted_external"
```

### Classification Assignments

The following table shows the trust assignment for all 99 connectors.
Connectors not listed below carry the default `semi_trusted` level.

#### `trusted_internal`

These connectors represent data that is operated, controlled, and
authoritative within the customer's own environment.

| Connector | Module | Rationale |
|-----------|--------|-----------|
| Splunk | `gnat/connectors/splunk/` | Internal SIEM; customer-operated |
| Microsoft Sentinel | `gnat/connectors/sentinel/` | Internal cloud SIEM |
| IBM QRadar | `gnat/connectors/qradar/` | Internal SIEM |
| Elastic SIEM | `gnat/connectors/elastic/` | Internal SIEM/XDR |
| Graylog | `gnat/connectors/graylog/` | Internal log aggregation |
| Security Onion | `gnat/connectors/security_onion/` | Internal NSM/SIEM |
| Wazuh | `gnat/connectors/wazuh/` | Internal SIEM/XDR |
| Palo Alto XSOAR | `gnat/connectors/xsoar/` | Internal SOAR orchestrator |

#### `semi_trusted`

Professional, commercially-operated or well-established open-source platforms
whose data quality is high but not self-certified.

| Connector | Module | Rationale |
|-----------|--------|-----------|
| ThreatQ | `gnat/connectors/threatq/` | Commercial TIP with curation |
| CrowdStrike Falcon | `gnat/connectors/crowdstrike/` | Commercial EDR/TI |
| Recorded Future | `gnat/connectors/recordedfuture/` | Commercial TI |
| Feedly | `gnat/connectors/feedly/` | Curated commercial feed |
| VirusTotal | `gnat/connectors/virustotal/` | Commercial multi-scanner |
| MISP | `gnat/connectors/misp/` | Open-source TIP, community-vetted |
| Mandiant Advantage | `gnat/connectors/mandiant/` | Commercial TI |
| Flashpoint | `gnat/connectors/flashpoint/` | Commercial dark-web TI |
| Intel 471 | `gnat/connectors/intel471/` | Commercial cybercrime TI |
| Group-IB | `gnat/connectors/group_ib/` | Commercial TI |
| Anomali ThreatStream | `gnat/connectors/threatstream/` | Commercial TIP |
| ThreatConnect | `gnat/connectors/threatconnect/` | Commercial TIP |

All remaining connectors not listed in the trusted_internal or
untrusted_external sections default to `semi_trusted` at the `BaseClient`
level.

#### `untrusted_external`

Community-contributed, public, or government feeds where quality control is
limited or the submission model is open.

| Connector | Module | Rationale |
|-----------|--------|-----------|
| AlienVault OTX | `gnat/connectors/alienvault/` | Open community submissions |
| Shadowserver Foundation | `gnat/connectors/shadowserver/` | Public; quality varies by dataset |
| CISA KEV | `gnat/connectors/cisa/` | Government advisory; no auth; coverage gaps |
| PulseDive | `gnat/connectors/pulsedive/` | Community-aggregated |
| GreyNoise | `gnat/connectors/greynoise/` | Mass-scanner data; noisy by design |
| Have I Been Pwned | `gnat/connectors/hibp/` | Breach aggregate; no attribution |
| Hudson Rock | `gnat/connectors/hudsonrock/` | Breach intelligence; community-sourced |

### Example Overrides

```python
# gnat/connectors/splunk/client.py
class SplunkClient(BaseClient):
    TRUST_LEVEL = "trusted_internal"

# gnat/connectors/alienvault/client.py
class AlienVaultClient(BaseClient):
    TRUST_LEVEL = "untrusted_external"

# gnat/connectors/threatq/client.py
class ThreatQClient(BaseClient):
    TRUST_LEVEL = "semi_trusted"  # explicit; same as default but self-documenting
```

### Integration with `ExecutionContext`

`ExecutionContext.from_connector()` (ADR-0039) reads `TRUST_LEVEL` via the
class, not the instance, so it is available before authentication:

```python
@classmethod
def from_connector(
    cls,
    connector: BaseClient,
    domain: str,
    workspace_id: str,
    policy_set: str | None = None,
    budget: QueryBudget | None = None,
) -> "ExecutionContext":
    declared_trust = type(connector).TRUST_LEVEL
    return cls(
        context_id=uuid4(),
        initiated_by=type(connector).__module__.split(".")[-2],
        domain=domain,
        trust_level=declared_trust,
        policy_set=policy_set,
        workspace_id=workspace_id,
        created_at=datetime.utcnow(),
        parent_context_id=None,
        is_replay=False,
        budget=budget,
    )
```

### Trust Escalation Detection

If a caller constructs an `ExecutionContext` manually and supplies a
`trust_level` higher than the connector class declares, the mismatch is
detected in `ExecutionContext.from_connector()` and written as a
`security_event` row to `execution_log`:

```python
if requested_trust != declared_trust:
    _log_security_event(
        event="trust_escalation_attempt",
        connector=type(connector).__name__,
        declared=declared_trust,
        requested=requested_trust,
        workspace_id=workspace_id,
    )
    # requested_trust is ignored; declared_trust is used
```

### Trust Weight Mapping

The trust level string maps to a numeric weight used by `ReasoningEngine`
(ADR-0044):

| Trust Level | Weight |
|-------------|--------|
| `trusted_internal` | 0.9 |
| `semi_trusted` | 0.6 |
| `untrusted_external` | 0.3 |

The mapping is defined in `gnat/core/trust.py` as `TRUST_WEIGHTS: dict[str, float]`
and shared between `ExecutionContext`, `HypothesisEngine`, and `ReasoningEngine`
to ensure a single source of truth.

---

## Consequences

### Positive

- **Declarative and inspectable:** `TRUST_LEVEL` is a class constant that can
  be read by policy agents, linters, and documentation generators without
  instantiating a connector or making any network call.
- **Zero runtime cost:** reading a class variable adds no overhead compared to
  the HTTP call that follows.
- **Automatic propagation:** once set on the class, trust flows into
  `ExecutionContext`, `HypothesisEngine`, and `ReasoningEngine` without any
  additional caller configuration.
- **Auditable escalation:** any attempt to override the declared trust level is
  logged before being silently rejected; the declared level always wins.
- **No breaking changes:** the default (`semi_trusted`) means existing
  connectors that have not yet been classified behave identically to the
  pre-ADR behaviour.

### Negative / Trade-offs

- **Static classification:** trust level is a class constant, not a
  runtime-configurable value.  An operator who has additional context (e.g.
  "our OTX subscription is curated by an analyst") cannot elevate a connector's
  trust without modifying source code or subclassing.
- **Binary per connector:** trust is assigned at the connector level, not at
  the dataset or indicator level.  A connector that mixes high- and low-quality
  data (e.g. VirusTotal community vs. premium API hits) cannot express that
  distinction through `TRUST_LEVEL` alone; per-object tagging (deferred) is
  needed for that.
- **Classification maintenance:** as new connectors are added, the platform
  team must consciously assign a trust level; the default `semi_trusted` acts
  as a safe backstop but may be too conservative or too permissive depending on
  context.

### Deferred

- **Operator-configurable trust override:** allow operators to raise or lower a
  connector's effective trust via the INI config file (e.g.
  `[alienvault] trust_override = semi_trusted`) without modifying source code.
- **Per-object trust tags:** complement connector-level trust with
  indicator-level confidence tags derived from raw connector metadata (e.g.
  VirusTotal detection ratio, MISP event distribution level).
- **Dynamic trust scoring:** a future `TrustCalibrationAgent` could observe
  long-term accuracy of indicators per connector and automatically adjust trust
  weights; this is deferred pending training data collection.

---

## Alternatives Considered

### Per-object trust tags at ingest time

Rather than a connector-level class constant, each mapper could attach a trust
tag to every `STIXBase` object it produces.  Rejected because:

1. Every mapper author would need to decide on trust independently, leading to
   inconsistency.
2. Mappers do not always have access to the connector identity at call time.
3. The per-object approach does not express *source authority* — the question of
   "how much do I trust this platform in general?" is separate from "how
   confident is this individual indicator?" and both are needed.

### Dynamic trust scoring based on historical accuracy

A scoring model that adjusts trust weights based on observed true-positive rates
per connector was considered.  Deferred (not rejected) because it requires
several months of labelled ground-truth data that does not yet exist.  The
static classification in this ADR will serve as the training baseline once
collection begins.

### INI-file trust assignment

Defining trust levels in `config.ini` rather than as class constants was
considered.  Rejected for the initial implementation because:

1. It would require a running config loader before any connector can be
   classified, making static analysis and documentation generation more complex.
2. Class constants are self-documenting in the source tree and version-controlled
   alongside the connector code.
3. Operator overrides via INI are deferred work and can be layered on top of the
   class-constant baseline without replacing it.

---

*Licensed under the Apache License, Version 2.0*
