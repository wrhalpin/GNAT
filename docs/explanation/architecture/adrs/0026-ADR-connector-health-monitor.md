# ADR-0026: Connector Health Monitor

**Decision:** `ConnectorHealthJob` — a `FeedJob` subclass that runs in the shared `FeedScheduler`; schema drift tracked via JSON fingerprint comparison.

**Why FeedJob subclass:**
Health checks are just another scheduled job. Reusing `FeedScheduler` means health monitoring
gets retry logic, overlap protection, and on-success/on-failure callbacks for free.

**Drift detection algorithm:**
1. Sample `list_objects(limit=1)` from each connector.
2. Extract field names from the response (recursive key extraction).
3. Compute a frozenset fingerprint and serialize to `SchemaSnapshot` JSON.
4. On each run, compare current fingerprint against the stored baseline.
5. If changed fields exceed `drift_threshold` (default 20%), emit a `DriftReport`.

**Slack alerts:**
`_post_slack_webhook()` is called when drift is detected. The webhook URL is read from
`[health]` INI section. This provides zero-dependency alerting without requiring a
monitoring framework.

**Baseline command:**
`gnat health baseline` runs one sampling pass and writes the initial `SchemaSnapshot`
files. Production deployments should run baseline after initial connector setup and
after planned API migrations.

---

*Licensed under the Apache License, Version 2.0*
