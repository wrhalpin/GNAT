# ADR-0001: HTTP Client Layer

**Decision:** `urllib3.PoolManager` as the sync base, `httpx.AsyncClient` for async.

**Why urllib3 over requests:**
- `requests` wraps `urllib3` but adds overhead and its own abstraction.
  Since we need connection pooling, retry logic, and raw control over
  headers/encoding, going to `urllib3` directly is cleaner and has zero
  additional dependencies.
- `requests` sessions do not compose well with async; urllib3 does not
  create this problem.

**Why httpx for async:**
- `httpx` provides the same API surface as `requests`-style but is
  natively async with `AsyncClient`.
- It has built-in retry transport (`AsyncHTTPTransport(retries=N)`).
- Alternative considered: `aiohttp`. Rejected because its API is more
  divergent from the sync path, making connector mirroring harder.

**Retry configuration:**
```python
Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist={429, 500, 502, 503, 504},
    allowed_methods={"GET", "POST", "PUT", "PATCH", "DELETE"},
)
```
Note: `allowed_methods` (not `method_whitelist`) — urllib3 ≥ 2.0 API.

**`GNATClientError` carries `status` and `body`:**
Always check `exc.status` in connector tests — 401 vs 403 vs 429 all
need different handling.
