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

## See Also

- [How-to: Run the Ingest Pipeline](run-ingest-pipeline.md)
- [How-to: Use Workspaces](use-workspaces.md)
- [Explanation: ORM and STIX Compatibility](../explanation/architecture/adrs/0002-orm-stix-compatibility.md)
