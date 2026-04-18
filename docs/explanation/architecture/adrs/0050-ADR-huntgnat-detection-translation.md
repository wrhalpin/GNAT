# ADR-0050: HuntGNAT — Detection Rule Translation

**Decision:** Implement STIX indicator pattern to detection rule
translation as a plugin at `gnat/plugins/huntgnat/`, with a custom
recursive descent parser, four language-specific translators, and an
explicit `UntranslatableError` contract that forbids silent semantic drops.

**Problem statement:**
STIX 2.1 indicator patterns express *what* to detect but not *how*.
Analysts must manually rewrite each pattern into platform-native rules
(Sigma, YARA, Suricata, Snort) — a tedious, error-prone process that
breaks the detect-validate loop. GNAT needed an automated translation
layer that produces deployable rules from STIX patterns while clearly
surfacing what *cannot* be translated.

## Plugin vs core extension

HuntGNAT is placed in `gnat/plugins/huntgnat/` rather than
`gnat/analysis/` because it consumes STIX patterns and ORM Indicators
but does not extend core internals (no subclassing of STIXBase, no
new SQLAlchemy tables, no deep coupling to the investigation or
correlation engines). Contrast with Attribution & Campaign Tracking
(ADR-0051) which required core extension placement due to tight
coupling with the ORM, EvidenceGraph, and correlation layers.

## Recursive descent parser over stix2-patterns

The `stix2-patterns` library (an optional GNAT extra for validation)
uses an ANTLR grammar that can validate pattern syntax but does not
expose a usable AST for code generation. Translators need to walk
typed nodes (ObjectPath, Comparison, Observation, CompoundObservation)
to emit platform-native syntax.

**Alternatives considered:**
- Use `stix2-patterns` ANTLR parse tree → rejected because the tree
  is validation-oriented, not generation-oriented. Extracting field
  names and values requires fragile tree-walking over generic nodes.
- Regex extraction of common patterns → rejected because it cannot
  handle compound observations, nested boolean logic, or the full
  STIX pattern grammar.

**Tradeoff:** Maintaining our own parser is a maintenance burden, but
it gives translators typed, documented input. The parser is ~300 lines
and covers the STIX pattern subset that maps to detection rules
(comparisons, boolean logic, compound observations). Exotic features
(WITHIN, REPEATS, START/STOP qualifiers) raise `UntranslatableError`.

## UntranslatableError contract

If a translator cannot semantically express a STIX pattern in its
target language, it must raise `UntranslatableError(reason, pattern,
target_language)`. Silent drops are forbidden.

**Rationale:** An analyst who runs `translate_all()` on 50 indicators
and gets 48 rules must know which 2 failed and why. A silent drop
creates false confidence in ATT&CK coverage — the analyst believes
they have detection when they don't. The caller decides policy: skip,
log, or abort.

## Hunt package as STIX Grouping

Hunt packages use the standard STIX `grouping` SDO type with
`context="x-huntgnat-hunt-package"` rather than a custom SDO.

**Rationale:** STIX Grouping is designed for exactly this use case —
bundling related objects (hypotheses, evidence, indicators, rules)
under a shared analytical context. A custom SDO would lose
interoperability with STIX tooling (TAXII servers, OpenCTI, MISP
import/export). Custom properties (`x_gnat_*`) carry HuntGNAT-specific
metadata within the standard envelope.

## Lifecycle state machine

```
DRAFT → PEER_REVIEWED → ACTIVE → RETIRED (terminal)
                ↓                    ↑
              DRAFT ────────────────→ (via ACTIVE)
```

Mirrors the Report lifecycle pattern from ADR-0034. Key constraint:
RETIRED is terminal — no reactivation. A retired package should be
cloned if the underlying threat resurfaces, preserving the audit trail
of the original retirement decision.

## Drift detection is observe-only

`DriftDetector.check()` compares SHA-256 hashes of canonical and
on-platform rule bodies. When they diverge, it records a `DriftEvent`
and marks the deployment as DRIFTED. It never auto-corrects.

**Rationale:** Platform-side rule modifications may be intentional
tuning by SOC analysts (added exceptions, adjusted thresholds).
Auto-reverting would discard legitimate work and could break
production detections. The drift event surfaces the divergence;
the human decides whether to reconcile.

## Translators implemented

| Translator | Target | Scope |
|-----------|--------|-------|
| `SigmaTranslator` | Sigma YAML | Log-source aware; field-name resolution from STIX object paths |
| `YaraHashTranslator` | YARA | Hash-only (MD5/SHA-1/SHA-256); Phase 1 scope |
| `SuricataTranslator` | Suricata | Network patterns; rejects host-only via UntranslatableError |
| `SnortTranslator` | Snort 3 | Network IPS rules |

New translators (KQL, SPL, EQL) can be added by subclassing
`RuleTranslator` and implementing `translate(ast) -> TranslationResult`.

→ See: `gnat/plugins/huntgnat/translators/base.py`
→ Related: ADR-0034 (Report Lifecycle — lifecycle pattern reuse)
→ Related: ADR-0032 (STIX Custom Objects — `x_gnat_*` property convention)
