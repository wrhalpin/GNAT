# How-to: Connect to Platforms

Code snippets for authenticating and interacting with supported GNAT platform connectors.
All examples assume `gnat` is installed and your `config.ini` is configured.

---

## Connect via GNATClient (config-driven)

The recommended approach — reads credentials from your `config.ini` automatically:

```python
from gnat.client import GNATClient

client = GNATClient.from_config("threatq")   # reads [threatq] from config.ini
client.connect()
client.ping()
```

---

## ThreatQ

```python
from gnat.connectors.threatq.client import ThreatQClient

client = ThreatQClient(
    host          = "https://threatq.example.com",
    client_id     = "my-id",
    client_secret = "my-secret",
)
client.authenticate()
client.health_check()

# List indicators
indicators = client.list_objects("indicator", page_size=50)

# Get one object
ind = client.get_object("indicator", "12345")

# Upsert
new_ind = client.upsert_object("indicator", {
    "value": "evil.com", "class": "Domain"
})
```

---

## VirusTotal

```python
from gnat.connectors.virustotal.client import VirusTotalClient

vt = VirusTotalClient(
    host    = "https://www.virustotal.com",
    api_key = "your-vt-api-key",
)
vt.authenticate()

# Look up a domain
domain_data = vt.get_object("indicator", "evil.com")

# Search for ransomware files (VT Intelligence required)
results = vt.list_objects("indicator",
    filters={"query": "type:peexe tag:ransomware"})

# Convert to STIX
for item in results:
    stix = vt.to_stix(item)
    print(stix["name"], stix["confidence"])
```

---

## ShadowServer

```python
from gnat.connectors.shadowserver.client import ShadowServerClient

ss = ShadowServerClient(
    api_key    = "your-ss-key",
    api_secret = "your-ss-secret",
)
ss.authenticate()

# Get open RDP exposures
records = ss.list_objects("indicator",
    filters={"report": "scan/rdp", "country": "US"})

# Get sinkholed IPs
sinkholes = ss.list_objects("indicator",
    filters={"report": "sinkhole", "date": "2024-03-21"})

for rec in records[:5]:
    print(ss.to_stix(rec))
```

---

## Rapid7 InsightVM

```python
from gnat.connectors.rapid7.client import Rapid7Client

r7 = Rapid7Client(
    host    = "https://us.api.insight.rapid7.com",
    api_key = "your-r7-key",
    product = "insightvm",
)
r7.authenticate()

# List critical vulnerabilities
vulns = r7.list_objects("vulnerability",
    filters={"severity": "critical", "status": "open"})

for v in vulns:
    stix = r7.to_stix(v)
    print(stix["name"], stix["x_cvss_score"], stix["x_actively_exploited"])
```

---

## Nucleus Security

```python
from gnat.connectors.nucleus.client import NucleusClient

ns = NucleusClient(
    api_key = "your-nucleus-key",
    project = "your-project-id",
)
ns.authenticate()

# List CISA KEV vulnerabilities
kev_vulns = ns.list_objects("vulnerability",
    filters={"kev": True, "status": "open"})

# High EPSS score vulnerabilities (>10% exploitation probability)
risky = ns.list_objects("vulnerability",
    filters={"epss_min": 0.10, "severity": "high"})

for v in risky:
    stix = ns.to_stix(v)
    print(stix["name"], stix["x_nucleus_epss"], stix["x_nucleus_kev"])
```

---

## See Also

- [Reference: Configuration](../reference/configuration.md)
- [How-to: Run the Ingest Pipeline](run-ingest-pipeline.md)
- [How-to: Use the Async Client](use-async-client.md)
