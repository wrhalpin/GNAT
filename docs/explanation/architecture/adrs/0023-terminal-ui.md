# ADR-0023: Terminal UI — Textual

**Decision:** Textual 8.x TUI with four screens; NLP query bar delegates to `NLPQueryEngine`.

**Why Textual over curses / urwid:**
- Textual provides a CSS-like layout engine, reactive data binding, and a rich widget
  library — features that would require thousands of lines in raw curses.
- Works over SSH without X11 forwarding — critical for server deployments.
- Textual's async event loop integrates cleanly with GNAT's async client layer.

**Screen architecture:**
Each screen is a self-contained `textual.Screen` subclass that owns its data fetching.
The `GNATApp` root composes them into a `TabbedContent` layout with F1–F4 hot keys.
Screens do not share state directly — they communicate via `app.post_message()`.

**`STIXTable` / `JobTable` widgets:**
Thin `DataTable` subclasses that define standard column layouts. This avoids repeating
column definitions across screens and provides a typed `selected_job_id()` helper.

**Graceful degradation:**
The Query screen works without a Claude API key (falls back to builtin NLP parser).
The Library and Scheduler screens work without a Research Library or active scheduler
(they render empty tables with a status bar message).
