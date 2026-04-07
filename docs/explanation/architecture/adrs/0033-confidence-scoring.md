# ADR-0033: Confidence Scoring Model

**Decision:** Adopt the NATO Admiralty Scale (source reliability A–F,
information credibility 1–6) combined with the STIX 2.1 numeric
confidence field (0–100) as the unified confidence model.

**Why Admiralty Scale:**
The Admiralty Scale is the dominant confidence framework in professional
and government CTI. It explicitly separates source reliability from
information credibility — a distinction that is frequently collapsed in
ad-hoc approaches and is a common source of analytical error. It is
taught in analytic tradecraft training (e.g., UK CPNI, US IC standards)
and is immediately familiar to professional analysts.

**Why not structured analytic techniques (SATs) alone:**
SATs (ACH, red teaming, etc.) are processes, not data model fields.
They are analyst workflows, not attributes of an intelligence object.
A confidence *field* on a Finding or Hypothesis needs a fixed schema that
can be stored, queried, and compared. The Admiralty Scale provides this.

**STIX 2.1 numeric confidence — required for interoperability:**
The STIX 2.1 `confidence` property is a mandatory integer 0–100.
Admiralty codes (e.g., "B2") have no direct STIX mapping. We store both:
the Admiralty pair for analytic rigour, the numeric value for STIX
compliance and programmatic filtering. The numeric value is set explicitly
by the analyst (not auto-derived from Admiralty codes) because the mapping
from Admiralty pair to numeric is not standardised and varies by
organisation.

**Convenience bands (HIGH/MEDIUM/LOW):**
UI display and filtering benefit from three-level bands. Bands map to
STIX numeric ranges: HIGH ≥ 70, MEDIUM 40–69, LOW < 40. These align with
the MITRE ATT&CK confidence convention.

**Propagation rule:**
When the CorrelationEngine (Phase 3) assembles a Finding from multiple
EvidenceLinks, the composite confidence should not exceed the minimum
credibility of any contributing source. Implementation: take the
minimum `stix_confidence` across all supporting EvidenceLinks and apply
a small uplift for corroboration (+5 per additional independent source,
capped at the minimum source's maximum band ceiling).

**`ConfidenceScore` model location:**
`gnat.analysis.confidence` — shared dependency imported by
`gnat.analysis.investigations`, `gnat.reporting`, and
`gnat.investigations` (the existing EvidenceGraph module).
