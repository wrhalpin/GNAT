# How-to: Work with STIX Objects

Create, relate, and serialize STIX 2.1 objects using the GNAT ORM.

---

## Create STIX objects

```python
from gnat.orm import Indicator, ThreatActor, Vulnerability, AttackPattern, Relationship

# Indicator
ind = Indicator(
    name           = "evil.com",
    pattern        = "[domain-name:value = 'evil.com']",
    pattern_type   = "stix",
    confidence     = 75,
    indicator_types= ["malicious-activity"],
    x_tlp          = "green",
    x_target_sectors = ["Healthcare", "Opportunistic"],
)

# Threat actor
actor = ThreatActor(
    name               = "APT29",
    threat_actor_types = ["espionage"],
    aliases            = ["Cozy Bear", "The Dukes"],
    x_target_sectors   = ["Healthcare", "Government"],
)

# Vulnerability
vuln = Vulnerability(
    name                = "CVE-2024-3400",
    x_cve_id            = "CVE-2024-3400",
    x_cvss_score        = 10.0,
    x_actively_exploited= True,
    description         = "PAN-OS command injection",
)

# Relationship
rel = Relationship(
    relationship_type = "indicates",
    source_ref        = ind.id,
    target_ref        = actor.id,
)
```

---

## Serialize objects

```python
# As a plain dict
print(ind.to_dict())

# As a STIX 2.1 bundle
print(ind.to_stix_bundle())
```

---

## TLP classification

Assign TLP 2.0 levels to objects using `TLPLevel` from `gnat.analysis`:

```python
from gnat.analysis.tlp import TLPLevel

# Set TLP on any ORM object via the x_tlp extension field
ind.x_tlp = TLPLevel.AMBER.value   # "amber"

# Compare levels (higher rank = more restrictive)
assert TLPLevel.RED > TLPLevel.AMBER > TLPLevel.GREEN

# Human-readable label
print(TLPLevel.AMBER.label)   # "TLP:AMBER"

# All TLP 2.0 levels: WHITE (legacy) / CLEAR / GREEN / AMBER / AMBER_STRICT / RED
```

---

## Confidence scoring (NATO Admiralty Scale)

Attach a structured confidence assessment to any intelligence object:

```python
from gnat.analysis.confidence import (
    ConfidenceScore,
    SourceReliability,
    InformationCredibility,
)

# Full Admiralty Scale assessment
score = ConfidenceScore(
    source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
    information_credibility = InformationCredibility.PROBABLY_TRUE,
    stix_confidence         = 75,
    rationale               = "Cross-corroborated by two independent sources.",
)

print(score.label)          # "B2 (HIGH)"
print(score.stix_confidence) # 75 — maps directly to STIX confidence field

# Use the numeric score in the ORM object
ind.confidence = score.stix_confidence

# Convenience factories
high   = ConfidenceScore.high()
medium = ConfidenceScore.medium()
low    = ConfidenceScore.low(rationale="Single unverified source.")
```

See [How-to: Use the Analysis Layer](use-analysis-layer.md) for the full
confidence and TLP reference.

---

## See Also

- [How-to: Run the Ingest Pipeline](run-ingest-pipeline.md)
- [How-to: Use Workspaces](use-workspaces.md)
- [How-to: Use the Analysis Layer](use-analysis-layer.md)
- [Explanation: ORM and STIX Compatibility](../explanation/architecture/adrs/0002-orm-stix-compatibility.md)
- [Explanation: Confidence Scoring Model](../explanation/architecture/adrs/0033-ADR-confidence-scoring.md)

---

*Licensed under the Apache License, Version 2.0*
