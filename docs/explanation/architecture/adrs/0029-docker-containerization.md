# ADR-0029: Docker Containerization

**Decision:** Three slim Python 3.11 containers (scheduler, EDL server, health monitor) sharing a named `gnat-workspace` volume; Compose profiles for optional services.

**Why three containers:**
Each service has a different availability requirement:
- The EDL server must be highly available (firewalls poll it every 5–15 min).
- The scheduler can restart without data loss (jobs re-run on schedule).
- The health monitor can tolerate brief outages.

Running them in separate containers means an EDL outage doesn't affect scheduling
and a scheduler crash doesn't take down the EDL server.

**Named volume:**
`gnat-workspace` is the shared persistence layer. All three containers mount it read-write.
The `WorkspaceManager` handles concurrent access safely (SQLite WAL mode; FlatFileStore
uses atomic writes).

**Compose profiles:**
- `search` — adds Solr for full-text indexing
- `monitoring` — adds Grafana for dashboards
- `full` — all services

This keeps the base deployment minimal while allowing operators to opt into observability
components.

**`.devcontainer` integration:**
The devcontainer config includes the Rust toolchain and Docker-in-Docker so that Rust
extension development and Docker testing both work in VS Code / Codespaces without
local tool installation.
