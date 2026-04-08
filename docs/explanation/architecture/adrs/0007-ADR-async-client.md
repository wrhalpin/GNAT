# ADR-0007: Async Client

**Decision:** `AsyncBaseClient` on `httpx`, not a wrapper around the sync client.

**Why a separate implementation:**
Wrapping sync calls with `asyncio.run_in_executor` would work but defeats
the purpose — you'd be running sync urllib3 on a thread pool rather than
truly async I/O. The platforms that benefit most from async (ThreatQ,
CrowdStrike) support proper HTTP/2 keep-alive which httpx uses natively.

**`authenticate()` is async:**
Means token refresh can be non-blocking. Proofpoint and Netskope auth is
header injection (synchronous in effect) but declared async for
interface consistency.

**`translation methods stay synchronous:**
`to_stix()` and `from_stix()` are CPU-bound JSON manipulation — there is
no benefit to making them async, and it would complicate callers.

**Concurrent multi-platform queries:**
```python
async with AsyncGNATClient() as tq, AsyncGNATClient() as rf:
    await asyncio.gather(tq.connect("threatq"), rf.connect("recordedfuture"))
    tq_res, rf_res = await asyncio.gather(
        tq.client.get_object("indicator", ioc_id),
        rf.client.get_object("indicator", ioc_id),
    )
```
This is the primary reason to use the async client — fan-out enrichment
across 5 platforms takes the same wall-clock time as the slowest single
platform.

---

*Licensed under the Apache License, Version 2.0*
