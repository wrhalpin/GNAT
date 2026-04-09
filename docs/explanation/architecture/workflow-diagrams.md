# GNAT Workflow Diagrams

This page explains the major data and control flows in GNAT through a set of workflow
diagrams. Each diagram uses [Mermaid](https://mermaid.js.org/) syntax, which renders
natively on GitHub and can be imported directly into [Grafly](https://grafly.io/) for
interactive editing.

---

## 1. Ingestion Pipeline Workflow

The following sequence diagram shows the full lifecycle of a piece of threat intelligence
as it flows through the ingestion pipeline from raw source data to a normalized STIX object
stored in a workspace.

```mermaid
sequenceDiagram
    autonumber
    actor Operator
    participant Scheduler as FeedScheduler<br/>(gnat/schedule)
    participant Reader as SourceReader<br/>(gnat/ingest/sources)
    participant Mapper as RecordMapper<br/>(gnat/ingest/mappers)
    participant Classifier as IOCClassifier<br/>(gnat/ingest)
    participant ORM as STIX ORM<br/>(gnat/orm)
    participant Connector as Connector<br/>(gnat/connectors)
    participant Solr as Search Sidecar<br/>(gnat/search)

    Operator->>Scheduler: schedule(feed_job)
    Scheduler->>Reader: trigger read()
    Reader-->>Reader: fetch source (TAXII / CSV / RSS / …)
    Reader->>Mapper: yield raw record dict
    Mapper->>Mapper: map(record) → intermediate dict
    Mapper->>Classifier: classify IOC type
    Classifier-->>Mapper: ioc_type, defanged value
    Mapper->>ORM: STIXBase.from_dict(normalized)
    ORM-->>ORM: validate fields, set _properties
    ORM->>Connector: upsert_object(stix_obj)
    Connector-->>ORM: confirmation / updated id
    ORM->>Solr: index(stix_obj.to_dict())
    Solr-->>Operator: search-ready
```

---

## 2. Intelligence Analysis Workflow

This flow diagram shows how a SOC analyst moves from an initial threat indicator through
correlation, investigation building, and report generation to final dissemination.

```mermaid
flowchart TD
    A([Threat Indicator / Alert]) --> B[Ingest & Normalise\ngnat/ingest]
    B --> C{Already known?}
    C -- Yes --> D[Merge / Enrich\nEntityResolver]
    C -- No  --> E[Create new STIX object\nSTIXBase]
    D --> F
    E --> F[STIX ORM\ngnat/orm]

    F --> G[Open Investigation\nInvestigationService]
    G --> H[InvestigationBuilder\n5-step pipeline]
    H --> H1[1. Seed expansion]
    H --> H2[2. Incident expansion]
    H --> H3[3. Normalisation]
    H --> H4[4. Correlation\nClusterDetector]
    H --> H5[5. Materialise EvidenceGraph]

    H5 --> I[Confidence Scoring\nConfidenceScore + TLP]
    I --> J[Gap Detection\nGapDetector]
    J --> K{Gaps found?}
    K -- Yes --> L[AI Drafting Assist\nReportDraftingAssistant]
    K -- No  --> M

    L --> M[Create Report Draft\nReportService DRAFT]
    M --> N[Review → Approve\nReportService lifecycle]
    N --> O[Publish Report\nSTIX SDO bundle]
    O --> P[Disseminate\nExportService / WebhookNotifier]
    P --> Q([Downstream consumers])
```

---

## 3. Export & Dissemination Workflow

```mermaid
flowchart LR
    A[Published Report\ngnat/reporting] --> B[ExportService\ngnat/dissemination]

    B --> C{Export Format?}
    C -- STIX 2.1 Bundle --> D[JSON / Bundle]
    C -- PDF            --> E[ReportLab PDF]
    C -- DOCX           --> F[python-docx DOCX]

    D --> G[WebhookNotifier]
    E --> G
    F --> G

    G --> H{TLP Filter}
    H -- CLEAR / GREEN  --> I[All subscribers]
    H -- AMBER          --> J[Need-to-know only]
    H -- RED            --> K[Named recipients]

    I --> L([TAXII 2.1 Server\ngnat/serve])
    I --> M([REST API endpoint])
    J --> L
    K --> M

    B --> N[EDL Delivery\ngnat/export]
    N --> O([Netskope CE\nFirewall / Proxy])

    style A fill:#4ea8de,color:#fff
    style L fill:#2d7a2d,color:#fff
    style O fill:#2d7a2d,color:#fff
```

---

## 4. Report Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> DRAFT : create_report()

    DRAFT --> REVIEW    : submit_for_review()
    DRAFT --> DRAFT     : save_draft()

    REVIEW --> APPROVED : approve()
    REVIEW --> DRAFT    : reject() — analyst revises

    APPROVED --> PUBLISHED : publish()\ncreates STIX SDO bundle

    PUBLISHED --> ARCHIVED : archive()
    PUBLISHED --> DRAFT    : revise()\nnew draft linked via parent_report_id

    ARCHIVED --> [*]

    note right of PUBLISHED
        Immutable after publish.
        Revisions create a new draft.
    end note
```

---

## 5. AI Agent Request Flow

```mermaid
sequenceDiagram
    autonumber
    participant Caller as GNATClient / Agent Code
    participant LLM as LLMClient<br/>(gnat/agents/llm.py)
    participant Claude as ClaudeProvider
    participant OAI as OpenAIProvider
    participant Grok as GrokProvider
    participant ORM as STIX ORM

    Caller->>LLM: complete(prompt, context)
    LLM->>Claude: attempt request
    alt Claude available
        Claude-->>LLM: response text
    else fallback
        LLM->>OAI: attempt request
        alt OpenAI available
            OAI-->>LLM: response text
        else fallback
            LLM->>Grok: attempt request
            Grok-->>LLM: response text
        end
    end
    LLM-->>Caller: LLMResponse(text, provider, tokens)

    Note over Caller,ORM: ParsingAgent path
    Caller->>LLM: extract_stix(raw_text)
    LLM-->>Caller: structured STIX JSON
    Caller->>ORM: STIXBase.from_dict(stix_json)
    ORM-->>Caller: stix_object
```

---

## 6. Connector Authentication Flow

```mermaid
flowchart TD
    A([GNATClient.get_connector]) --> B[Read gnat.ini section]
    B --> C{auth_type?}

    C -- api_key  --> D[X-Api-Key header]
    C -- oauth2   --> E[POST /oauth/token]
    C -- basic    --> F[Base64 Basic auth]
    C -- bearer   --> G[Authorization: Bearer]
    C -- hmac     --> H[Compute HMAC-SHA256\nsignature per request]
    C -- sigv4    --> I[AWS SigV4 signing\naws_security connector]

    D --> J[BaseClient.request]
    E --> J
    F --> J
    G --> J
    H --> J
    I --> J

    J --> K{HTTP response}
    K -- 2xx --> L[Return data]
    K -- 4xx/5xx --> M[Raise GNATClientError\nstatus + body]
    M --> N{Retry policy}
    N -- retries left --> J
    N -- exhausted    --> O([Propagate error to caller])
```

---

## 7. Feed Scheduling Workflow

```mermaid
flowchart LR
    A([Operator: schedule_feed]) --> B[FeedJob\ngnat/schedule]
    B --> C[croniter\ncron expression]
    C --> D[FeedScheduler.run_pending]

    D --> E{Due now?}
    E -- Yes --> F[Execute FeedJob.run]
    E -- No  --> G[Sleep until next tick]

    F --> H[IngestPipeline.run\nfor this feed]
    H --> I[Metrics: last_run,\nnext_run, record_count]
    I --> J{Error?}
    J -- No  --> K[Update last_success]
    J -- Yes --> L[Log error\nincrement failure_count]
    L --> M{max_failures exceeded?}
    M -- Yes --> N[Disable feed\nalert operator]
    M -- No  --> G

    K --> G
    G --> D
```

---

## 8. ExecutionContext Propagation (Phase 4A)

This diagram shows how an `ExecutionContext` is created at pipeline entry and propagated
through all downstream operations, providing end-to-end traceability.

```mermaid
sequenceDiagram
    autonumber
    actor Operator
    participant Pipeline as IngestPipeline<br/>(gnat/ingest)
    participant Ctx as ExecutionContext<br/>(gnat/core/context.py)
    participant Log as execution_log<br/>(Postgres)
    participant Client as BaseClient<br/>(gnat/clients/base.py)
    participant Budget as QueryBudget

    Operator->>Pipeline: run(source, workspace_id)
    Pipeline->>Ctx: ExecutionContext.create(initiated_by, domain, workspace_id)
    Ctx-->>Pipeline: ctx (context_id=UUID, trust_level, is_replay=False)
    Pipeline->>Log: INSERT INTO execution_log (ctx.to_dict())
    Log-->>Pipeline: ack

    Pipeline->>Client: connector._context = ctx
    loop Per observable
        Client->>Budget: budget.consume(COST_UNIT, connector_name)
        alt Budget exhausted
            Budget-->>Client: raise BudgetExceeded
        else OK
            Client-->>Pipeline: HTTP response data
        end
    end

    Note over Pipeline,Ctx: Child context for sub-operation
    Pipeline->>Ctx: ctx.child(initiated_by="enrichment-agent", domain="analysis")
    Ctx-->>Pipeline: child_ctx (parent_context_id=ctx.context_id)
    Pipeline->>Log: INSERT INTO execution_log (child_ctx.to_dict())
```

---

## 9. Hypothesis Engine Lifecycle (Phase 4C)

The full propose → evaluate → close lifecycle for `STIXHypothesis` objects, showing
how Solr corroboration and trust-weighted evidence feed into confidence updates.

```mermaid
sequenceDiagram
    autonumber
    actor Analyst
    participant Engine as HypothesisEngine<br/>(gnat/reasoning/hypothesis.py)
    participant WS as Workspace<br/>(gnat/context/workspace.py)
    participant Solr as SolrSearchIndex<br/>(gnat/search/index.py)
    participant H as STIXHypothesis<br/>(x-gnat-hypothesis SDO)

    Analyst->>Engine: propose("APT29 behind Q1 campaign", evidence=["rel--1"], confidence=0.2)
    Engine->>H: STIXHypothesis(statement, confidence=0.2, status="pending")
    H->>H: add_supporting_evidence("rel--1")
    Engine->>WS: _add_object(h.to_dict(), mark_dirty=True)
    WS-->>Analyst: STIXHypothesis (id, confidence=0.2, status="pending")

    Analyst->>Engine: evaluate(hypothesis_id)
    Engine->>WS: load hypothesis object
    Engine->>Solr: search(statement, limit=20)
    Solr-->>Engine: [corroborating_stix_ids]
    Engine->>Engine: corroboration_boost = min(len(ids) × 0.05, 0.3)
    Engine->>Engine: raw = (support_count / total) + corroboration_boost
    Engine->>H: update_confidence(clamped_raw)
    alt confidence ≥ 0.75
        H->>H: status = "confirmed"
    else confidence ≤ 0.15 and refute_count > 0
        H->>H: status = "refuted"
    end
    Engine->>WS: _add_object(h.to_dict(), mark_dirty=True)
    Engine-->>Analyst: STIXHypothesis (updated confidence + status)

    Analyst->>Engine: close(hypothesis_id, verdict="confirmed")
    Engine->>H: close("confirmed")
    Engine->>WS: _add_object(h.to_dict(), mark_dirty=True)
    Engine-->>Analyst: STIXHypothesis (status="confirmed")
```

---

## 10. ReasoningEngine Observable Scoring (Phase 4C)

How `ReasoningEngine.prioritize()` scores a set of observables using five weighted signals.

```mermaid
flowchart TD
    A([observable_set, context]) --> B[ReasoningEngine.prioritize]

    B --> C[Gather NegativeEvidenceRecords\nfrom workspace]
    C --> D[For each observable...]

    D --> E1[trust_weight\nfrom ExecutionContext.trust_level]
    D --> E2[age_factor\n1.0 − 5%×age_days]
    D --> E3[neg_penalty\n0.3 × fresh_neg_count]
    D --> E4[corroboration_bonus\nSolr hits × 0.05]

    E1 --> F[Composite Score\nscore = trust×0.4 + age×0.3\n+ corroboration×0.3 − neg×0.5]
    E2 --> F
    E3 --> F
    E4 --> F

    F --> G[Clamp to 0.0–1.0]
    G --> H[Build explanation dict\nmachine-readable components]
    H --> I{store_notes?}
    I -- Yes --> J[Write STIX note object\nlinked to observable]
    I -- No  --> K

    J --> K[Collect results]
    K --> L[Sort by score DESC]
    L --> M([return list of tuple: observable, score, explanation])

    style F fill:#4ea8de,color:#fff
    style M fill:#2d7a2d,color:#fff
```

---

## 11. Agent Governance & HITL Flow (Phase 4D)

How every agent action passes through `AgentGovernor` and `HITLGateway` before execution.

```mermaid
flowchart TD
    A([Agent requests action]) --> B[AgentGovernor.can_act\nagent_id, action_type, trust_level]

    B --> C{Policy override\nexists?}
    C -- Yes --> D{Override allows?}
    C -- No  --> E{Trust-level matrix\nallows?}

    D -- No  --> F([raise AgentPermissionDenied])
    D -- Yes --> G

    E -- No  --> F
    E -- Yes --> G[Rate limit check\nsliding window]

    G --> H{Within limit?}
    H -- No  --> I([raise RateLimitExceeded])
    H -- Yes --> J[Create AgentAction\nimpact_level assigned]

    J --> K[HITLGateway.evaluate]

    K --> L{impact_level?}
    L -- low/medium --> M[Auto-approve\napproved_by = auto-policy]
    L -- high       --> N[ReviewService.submit\nstatus = PENDING]
    L -- critical   --> O[ReviewService.submit\n+ XSOARClient notification]

    N --> P{Human reviews...}
    O --> P
    P -- Approved --> Q[action.status = approved\nExecute action]
    P -- Rejected --> R([Action cancelled])
    P -- Timeout  --> S[Auto-reject\nreviewer = system-timeout]

    M --> Q
    Q --> T[AgentGovernor.record_action\nAudit log + HookBus emit]
    T --> U([Action complete])

    style F fill:#c0392b,color:#fff
    style I fill:#c0392b,color:#fff
    style R fill:#c0392b,color:#fff
    style U fill:#2d7a2d,color:#fff
```

---

## 12. Workspace Trust Boundary Enforcement (Phase 4E)

How `check_connector_trust()` enforces isolation boundaries before allowing connector access.

```mermaid
flowchart TD
    A([Connector attempts workspace access]) --> B[workspace.check_connector_trust\nconnector]

    B --> C[Read type connector .TRUST_LEVEL]
    C --> D[Read workspace.trust_boundary]

    D --> E{connector_rank ≥\nrequired_rank?}
    E -- No  --> F([raise PermissionError\nConnector trust too low])

    E -- Yes --> G{allowed_connector_refs\nnon-empty?}
    G -- No  --> H[Access granted]
    G -- Yes --> I{connector class name\nin allowlist?}

    I -- No  --> J([raise PermissionError\nConnector not in allowlist])
    I -- Yes --> H

    H --> K[Proceed with read/write]

    style F fill:#c0392b,color:#fff
    style J fill:#c0392b,color:#fff
    style H fill:#2d7a2d,color:#fff

    subgraph Trust Rank Order
        TR1[trusted_internal = 2]
        TR2[semi_trusted = 1]
        TR3[untrusted_external = 0]
    end
```

---



All Mermaid diagrams in this file can be:

- **Rendered directly on GitHub** — GitHub renders Mermaid in Markdown automatically.
- **Imported into [Grafly](https://grafly.io/)** — copy the Mermaid code block and use
  *File → Import → Mermaid* in the Grafly editor.
- **Embedded in Sphinx docs** — add `sphinxcontrib-mermaid` to `docs/sphinx-html/requirements.txt`
  and the extension to `conf.py`, then use the `.. mermaid::` directive.

---

*Licensed under the Apache License, Version 2.0*
