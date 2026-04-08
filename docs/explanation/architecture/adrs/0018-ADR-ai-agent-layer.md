# ADR-0018: AI Agent Layer

**Decision:** Agents implement the existing `SourceReader` / `RecordMapper`
interfaces so they drop directly into `IngestPipeline` and `FeedJob` without
any special casing.

### Two agent types, one interface

`ResearchAgent` is a `SourceReader` — it yields `RawRecord` dicts.
`ParsingAgent` is a `RecordMapper` — it consumes `RawRecord` dicts and yields
`STIXBase` objects. `CopilotReader` is a `SourceReader` — it yields `RawRecord`
dicts from M365 sources. The pipeline chain is:

```
ResearchAgent / CopilotReader (SourceReader)
    → ParsingAgent (RecordMapper)
    → existing mappers (optional)
    → connectors / EDLs
```

This means scheduling, deduplication, error handling, and delivery all reuse
the existing `FeedJob` / `IngestPipeline` infrastructure with zero new code.

### Claude API key in INI, not environment

```ini
[claude]
api_key               = sk-ant-...
model                 = claude-sonnet-4-6
max_tokens            = 4096
timeout               = 120
ai_confidence_ceiling = 60
```

The `ClaudeClient` uses stdlib `urllib` only — no `anthropic` SDK dependency.
This keeps the `agents` extra dependency-free (no new pip installs required).

### Confidence ceiling — the most important design decision

Every STIX object produced by `ParsingAgent` is capped at
`AgentConfig.ai_confidence_ceiling` (default 60) and tagged
`x_source_type: "ai_extracted"`. This means:

- AI-extracted intel can never reach EDLs at high confidence without analyst review
- Filters like `ConfidenceFilter(min_confidence=70)` in export pipelines
  will exclude AI intel by default unless explicitly lowered
- The tag allows analysts to find and review all AI-extracted objects:
  `ws.objects` filtered by `x_source_type == "ai_extracted"`

**Never raise the ceiling to 100.** Claude can hallucinate slightly wrong IPs
or malformed hashes. The ceiling exists to require human review before high-stakes
propagation.

### Reader factory pattern for incremental research

The feed-driven `ResearchAgent` and `CopilotReader` both support `newer_than`
via the `JobRunContext` pattern:

```python
FeedJob(
    reader_factory=lambda ctx: ResearchAgent(
        config=cfg,
        monitored_sources=[...],
        newer_than=ctx.last_success_iso,  # None on first run (full backfill)
    ),
    ...
)
```

On the first run `newer_than` is `None` and Claude fetches everything relevant.
On subsequent runs it's the ISO timestamp of the last successful completion.

### Topic-driven vs. feed-driven — when to use each

| Mode | Use when | Output |
|---|---|---|
| Topic-driven | Targeted research ("what do we know about APT29?") | One synthesis per topic |
| Feed-driven | Monitoring sources on schedule | One record per new article found |
| CopilotReader | M365 content (emails, SharePoint, Teams) | One record per content item |

Topic-driven is better for on-demand analyst queries. Feed-driven is better for
recurring monitoring jobs. Both can be combined in the same `IngestPipeline`.

### max_calls_per_run prevents runaway cost

Topic-driven mode makes one Claude API call per topic. Feed-driven makes one
call per batch of 10 sources. `max_calls_per_run` (default 20) caps total calls
per `_iter_records` invocation. For a feed with 100 monitored sources:
`100 / 10 = 10 batches < 20 limit` — fine. For a topic list of 50 topics, set
`max_calls_per_run=50` explicitly or the last 30 will be silently skipped with
a warning log.

### Prompts are centralised in prompts.py

All Claude system and user prompt templates live in `gnat/agents/prompts.py`.
This is intentional — prompt engineering is iterative and keeping prompts
separate from logic means they can be reviewed, versioned, and tuned without
touching agent code. The JSON schema embedded in `PARSING_SYSTEM` is the
contract between Claude and `ParsingAgent._to_stix_objects`. Field names must
match exactly.

### CopilotReader uses DirectLine v3 (sync urllib)

Copilot is accessed via Bot Framework DirectLine v3 API. The reader uses
stdlib `urllib` (not the async `httpx` client from `async_client.base`) because
`SourceReader._iter_records` is synchronous. The polling pattern (2s interval,
30 attempts max) handles Copilot's variable response time when querying M365 Graph.

The prose fallback in `_parse_reply` handles cases where Copilot returns a
natural-language "no results" message instead of JSON — this is common when
the M365 source has no new content matching the query.

---

*Licensed under the Apache License, Version 2.0*
