# How-to: Use the Research Library

Cache, curate, and reuse threat research across multiple analysis cycles.

---

## Check before researching

Avoid redundant AI calls by checking the library first:

```python
from gnat.research import ResearchLibrary

lib = ResearchLibrary.default()

topic = "APT29"
if lib.is_fresh(topic):
    # Use cached research
    entry = lib.get(topic)
    print(f"Using research by {entry.researcher}: {entry.note}")
    lib.load_into_workspace(topic, my_workspace)
else:
    # Run agents, then promote result
    # ... research pipeline ...
    lib.promote(
        workspace  = my_workspace,
        topic      = topic,
        researcher = "analyst1",
        note       = "New C2 infra confirmed by Unit42 and Mandiant.",
    )
```

---

## Browse the library

```python
lib = ResearchLibrary.default()

# List all fresh entries
for entry in lib.list_entries():
    print(f"{entry['topic']:30s} {entry['age_hours']:5.1f}h  "
          f"{'✓' if entry['is_fresh'] else 'STALE':6s}  "
          f"{entry['researcher']}")

# Search
results = lib.search("phishing")
for e in results:
    print(e.topic, e.note[:80])
```

---

## Scheduled curation

Automatically promote staged research into the library on a recurring schedule:

```python
from gnat.research import ResearchLibrary, CurationJob
from gnat.schedule import FeedScheduler

lib     = ResearchLibrary.default()
curator = CurationJob(lib, interval_seconds=4 * 3600)

with FeedScheduler() as sched:
    sched.add(curator)
```

---

## See Also

- [How-to: Use AI Agents](use-ai-agents.md)
- [How-to: Generate Reports](generate-reports.md)
- [Explanation: Shared Research Library](../explanation/architecture/adrs/0019-shared-research-library.md)
