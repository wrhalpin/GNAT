# ADR-0020: NLP Query Layer

**Decision:** Two-backend NLP engine: a regex/keyword `BuiltinParser` (zero deps) with an optional `ClaudeParser` upgrade.

**Why two backends:**
- Security environments often prohibit sending query text to external AI APIs.
- The builtin parser covers the 80% case (STIX type filters, date ranges, confidence
  bounds, actor/CVE name matching) without any dependencies.
- The Claude backend handles the long tail — ambiguous phrasing, multi-hop references,
  compound temporal expressions — using structured extraction via the Claude API with
  strict JSON schema validation.

**`QuerySpec` design:**
All parsed queries materialise as a `QuerySpec` dataclass: `stix_type`, `filters`
(dict), `time_range` (start/end ISO), `confidence_min`, `limit`, `sources`. This
decouples query parsing from query execution and makes both backends swappable.

**Fallback behaviour:**
`NLPQueryEngine` prefers the configured backend and silently falls back to builtin if
Claude API is unavailable. This ensures the TUI query bar always works even without
a Claude API key.

**TUI integration:**
The Textual Query screen passes user input directly to `NLPQueryEngine.parse()` and
dispatches the resulting `QuerySpec` to `GNATClient.natural_language_query()`. No
intermediate serialisation.
