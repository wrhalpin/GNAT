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

## Using These Diagrams

All Mermaid diagrams in this file can be:

- **Rendered directly on GitHub** — GitHub renders Mermaid in Markdown automatically.
- **Imported into [Grafly](https://grafly.io/)** — copy the Mermaid code block and use
  *File → Import → Mermaid* in the Grafly editor.
- **Embedded in Sphinx docs** — add `sphinxcontrib-mermaid` to `docs/sphinx-html/requirements.txt`
  and the extension to `conf.py`, then use the `.. mermaid::` directive.

---

*Licensed under the Apache License, Version 2.0*
