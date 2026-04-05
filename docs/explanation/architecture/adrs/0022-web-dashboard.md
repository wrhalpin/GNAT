# ADR-0022: Web Dashboard (`gnat/serve/`)

**Decision:** Minimal FastAPI application with vanilla-JS single-page frontend; no frontend build step.

**Why no JS framework:**
- The dashboard is an operational tool, not a product UI. Complexity must stay low.
- A self-contained HTML string returned by a FastAPI route requires zero build infrastructure
  and no npm. The dark-theme vanilla-JS dashboard loads in < 50 ms.

**Security model:**
- `X-Api-Key` header validated via `hmac.compare_digest` (constant-time, no timing oracle).
- `APIKeyAuth` is a FastAPI callable dependency injected on every authenticated route.
- `RateLimiter` uses a sliding-window in-memory counter (thread-safe `threading.Lock`) —
  100 req/min per key. Prevents brute-force key guessing without requiring Redis.
- Binds to `127.0.0.1` by default (not `0.0.0.0`) — requires explicit override for
  external exposure.
- Auto-generates an API key if `--api-key` is omitted; prints it to `stderr` with a warning.

**Why not the existing EDL FastAPI app:**
The EDL server (`gnat/export/`) serves static IOC lists and must stay lightweight and
independent. The dashboard needs auth, rate limiting, and multiple routers — mixing them
would create a dependency between the export pipeline and the UI.
