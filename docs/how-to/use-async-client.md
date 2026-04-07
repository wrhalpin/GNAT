# How-to: Use the Async Client

Gather data from multiple platforms concurrently with `AsyncGNATClient`.

---

## Gather from multiple platforms concurrently

```python
import asyncio
from gnat.async_client import AsyncGNATClient

async def gather_all():
    async with AsyncGNATClient() as client:
        results = await client.gather(
            platforms  = ["threatq", "crowdstrike", "splunk"],
            stix_type  = "indicator",
            filters    = {"confidence_min": 70},
        )
    return results

indicators = asyncio.run(gather_all())
print(f"Gathered {len(indicators)} indicators from 3 platforms")
```

---

## See Also

- [How-to: Connect to Platforms](connect-to-platforms.md)
- [Explanation: Async Client](../explanation/architecture/adrs/0007-async-client.md)

---

*Licensed under the Apache License, Version 2.0*
