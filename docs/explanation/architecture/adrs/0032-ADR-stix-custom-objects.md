# ADR-0032: STIX Custom Objects for Analysis Layer

**Decision:** Use `x-gnat-investigation` as a STIX 2.1 custom SDO for
Investigation export. Use standard STIX `report` SDO for Report export.
Introduce `investigates` as a custom STIX relationship verb.

**STIX 2.1 has no Investigation SDO:**
The STIX 2.1 specification defines `report` (finished intelligence) but
has no equivalent for the *in-progress* analyst workspace. Custom objects
(`x-` prefix) are the correct mechanism per §10.9 of the specification.

**`x-gnat-investigation` schema:**
```json
{
  "type": "x-gnat-investigation",
  "spec_version": "2.1",
  "id": "x-gnat-investigation--<uuid>",
  "created": "<timestamp>",
  "modified": "<timestamp>",
  "name": "<title>",
  "description": "<description>",
  "status": "open|in_progress|review|closed",
  "x_tlp": "white|green|amber|amber+strict|red",
  "x_created_by": "<analyst id>",
  "x_assigned_to": ["<analyst id>"],
  "x_scope": { ... },
  "x_hypothesis_count": 0,
  "x_linked_indicators": ["indicator--<uuid>", ...],
  "x_linked_threat_actors": ["threat-actor--<uuid>", ...],
  "x_linked_campaigns": ["campaign--<uuid>", ...]
}
```

**Standard STIX `report` SDO for finished intelligence:**
When a GNAT Report reaches `PUBLISHED` status it serializes as a STIX
`report` SDO. `object_refs` is populated with all linked indicators,
observables, threat actors, campaigns, and the parent
`x-gnat-investigation` (if any). `published` maps to `published_at`.

**Custom relationship verb `investigates`:**
The standard STIX verbs do not capture the analyst action of
investigating an artifact. Add `investigates` as a custom relationship
type linking `x-gnat-investigation` → linked artifacts. The
`relationship_type` field accepts free-form strings per STIX 2.1 §7.4.

**Why not reuse `report` for Investigation:**
A STIX `report` is a *finished intelligence product* with a `published`
timestamp. An in-progress Investigation has lifecycle states (OPEN,
IN_PROGRESS, REVIEW) that have no mapping to the report SDO. Forcing a
mapping would either lose state information or require awkward label
encoding. The custom SDO is semantically cleaner and unambiguous.

**Interoperability note:**
STIX consumers that do not recognise `x-gnat-investigation` will ignore
the custom objects (per STIX 2.1 §3.2 ignore-unknown-properties guidance)
but still process all standard SDOs and SROs in the same bundle. Export
bundles always include both the custom investigation object and all
standard STIX objects it references, so partial consumers still receive
full indicator/threat-actor data.

---

*Licensed under the Apache License, Version 2.0*
