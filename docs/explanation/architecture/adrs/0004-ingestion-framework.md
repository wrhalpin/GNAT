# ADR-0004: Ingestion Framework

**Decision:** Three composable abstractions — `SourceReader`, `RecordMapper`,
`IngestPipeline`.

**`SourceReader` contract:**
- Implement `_iter_records(self) -> Iterator[RawRecord]`
- Override `open()` / `close()` for resources with connection lifecycle
- Support context manager (`with reader:`) — auto-calls `open`/`close`
- `batch_size` param for paginated sources (SQL, Elasticsearch)

**`RecordMapper` contract:**
- Implement `map(self, record: RawRecord) -> Iterator[STIXBase]`
- May yield 0 objects (filtered), 1 (normal), or N (MISP events with many attrs)
- Use `self._client`, `self.tlp_marking`, `self.confidence`

**Critical dedup bug fixed in v0.1:**
`DeduplicationCache.__len__` returning `0` on empty cache made
`if self._dedup and ...` evaluate to `False` before the first item was
seen — the entire dedup was silently skipped. Fix: always use
`if self._dedup is not None and ...`. This applies everywhere you guard
on an object with a `__len__` that can be zero.

**IOC auto-classification in `PlainTextReader`:**
Pattern order matters — SHA-256 checked before SHA-1 before MD5 (by
hash length). IPv4 checked before domain to avoid misclassifying IPs
as domains.

**Defang handling:**
`PlainTextReader` strips `[.]`, `hxxp://`, `hxxps://` before
classification. Connectors receiving IOC values from the ingestion
pipeline will see clean values.

---

*Licensed under the Apache License, Version 2.0*
