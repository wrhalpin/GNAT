# ADR-0019: Shared Research Library

**Decision:** Three-tier model (personal → staging → library) with all access
through `ResearchLibrary`. No direct workspace manipulation by analysts.

### Why three tiers, not two

A flat shared workspace has two failure modes: analysts write garbage directly
to the shared space, or concurrent writes from multiple analysts corrupt entries.
The staging tier absorbs both. Analysts write to staging freely — it's an inbox,
not a source of truth. The curation job is the only thing that writes to the
library, so the library is never in an inconsistent state from concurrent analyst
activity.

### Deduplication: most recent wins

When multiple analysts research the same topic and promote to staging, the
curation job keeps the entry with the latest `promoted_at` timestamp and
archives the rest. Archived entries remain in storage — nothing is deleted —
so the history of who researched what is preserved for audit. The `entry_id`
is a SHA-256 fingerprint of `(topic_key, promoted_at)` so it's deterministic
and collision-resistant.

### TTL categories

| Category | Default | Rationale |
|---|---|---|
| `indicator` | 24h | IOCs rotate or get sinkholed quickly |
| `vulnerability` | 72h | Exploitability status changes within days |
| `campaign` | 14d | Campaign activity evolves over weeks |
| `threat_actor` | 30d | Actor TTPs and infrastructure change slowly |
| `other` | 7d | Conservative fallback |

All overridable in `[research_library]` INI section. The TTL is set at
*curation time*, not promotion time — so the clock starts when the entry
enters the library, not when the analyst finished their research.

### check-before-research pattern

```python
lib = ResearchLibrary.default()

if lib.is_fresh("APT29"):
    # Use cached research — load into workspace, save API costs
    lib.load_into_workspace("APT29", my_workspace)
else:
    # Run agents, review, then promote
    # ... research ...
    lib.promote(my_workspace, topic="APT29", researcher="analyst1",
                note="New C2 infra confirmed by Unit42 and Mandiant.")
```

`is_fresh` returns `True` only for curated (library) entries within their TTL.
Pending staging entries are invisible to `is_fresh` and `get`. This means
analysts always see curator-reviewed data, never raw staging entries.

### The optional note field

`lib.promote(..., note="...")` is deliberately optional. Making it required
adds friction that reduces promotion rates. Making it optional means analysts
who want to share context can do so; those in a hurry can skip it. The note
appears in `list_entries()` and `search()` output, so a descriptive note
increases discoverability by colleagues.

### CurationJob scheduling

```python
from gnat.research import ResearchLibrary, CurationJob
from gnat.schedule import FeedScheduler

lib  = ResearchLibrary.default()
job  = CurationJob(lib, interval_seconds=4 * 3600)   # every 4 hours

with FeedScheduler() as sched:
    sched.add(job)
```

Four hours is a reasonable default — staging entries don't sit unreviewed for
long, but the curation job doesn't run so frequently that it becomes noisy in
the scheduler status output. For teams that need faster promotion, `cron="0 * * * *"`
(hourly) works equally well.
