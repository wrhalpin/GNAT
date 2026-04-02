# How-to: Run the Ingest Pipeline

Recipes for pulling data from various sources and writing it to a platform or workspace.

---

## Blocklist → ThreatQ

```python
from gnat.ingest import IngestPipeline
from gnat.ingest.sources.readers import PlainTextReader
from gnat.ingest.mappers.mappers import FlatIOCMapper

result = (
    IngestPipeline("blocklist-daily")
    .read_from(PlainTextReader("https://blocklist.example.com/ips.txt"))
    .map_with(FlatIOCMapper(confidence=70, tlp_marking="white"))
    .deduplicate(key_fields=["name"])
    .write_to(threatq_client)
).run()

print(result)  # IngestResult: 1247 records → 1247 mapped → 1201 written
```

---

## TAXII feed → ThreatQ (incremental)

```python
from gnat.ingest.sources.readers import TAXIICollectionReader

result = (
    IngestPipeline("taxii-daily")
    .read_from(TAXIICollectionReader(
        collection,
        added_after="2024-03-20T00:00:00Z",
    ))
    .map_with(STIXPassthroughMapper(client=threatq_client))
    .write_to(threatq_client)
).run()
```

---

## CSV file → workspace

```python
from gnat.ingest.sources.readers import CSVReader
from gnat.ingest.mappers.mappers import CSVIndicatorMapper

result = (
    IngestPipeline("csv-import")
    .read_from(CSVReader("threat_intel.csv"))
    .map_with(CSVIndicatorMapper(
        value_field    = "ioc_value",
        type_field     = "ioc_type",
        confidence_field = "score",
    ))
    .write_to(threatq_client)
).run()
```

---

## Splunk alerts → indicators (incremental)

```python
from gnat.ingest.sources.readers import SplunkReader

result = (
    IngestPipeline("splunk-alerts")
    .read_from(SplunkReader(
        splunk_client,
        search='search index=security sourcetype=alerts earliest=-24h',
    ))
    .map_with(SplunkResultMapper(
        indicator_field = "dest_ip",
        indicator_type  = "ipv4",
        confidence      = 65,
    ))
    .write_to(threatq_client)
).run()
```

---

## See Also

- [How-to: Schedule Feeds](schedule-feeds.md)
- [How-to: Use AI Agents](use-ai-agents.md)
- [Explanation: Ingestion Framework](../explanation/architecture/adrs/0004-ingestion-framework.md)
