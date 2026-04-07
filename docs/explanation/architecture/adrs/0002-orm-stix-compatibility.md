# ADR-0002: ORM / STIX Compatibility

**Decision:** `STIXBase` is a pure Python class. It is **not** a SQLAlchemy
model, not a Pydantic model, not a dataclass.

**Why not SQLAlchemy inheritance:**
Coupling the STIX domain model to a DB session lifecycle would mean:
- Objects carry DB session state everywhere
- `async def` methods would require async sessions throughout
- Tests need a DB to instantiate any object
- STIX serialisation becomes entangled with ORM session expiry

The chosen pattern — serialize to JSON via `to_dict()`, store in DB,
deserialize via `from_dict()` — keeps the two layers fully decoupled.

**`__getattr__` / `__setattr__` property bag:**
- Core STIX fields (`id`, `spec_version`, `created`, `modified`) are
  stored as real instance attributes.
- All other properties land in `self._properties` dict.
- `__getattr__` reads from `_properties` on attribute miss.
- This means `obj.confidence = 80` and `obj._properties["confidence"] = 80`
  are equivalent. **Always access via attribute syntax in application code.**

**`x_` prefix convention:**
All non-standard extension fields use `x_` prefix per STIX 2.1 spec
(e.g. `x_rf_risk_score`, `x_tlp`, `x_enrichment_source`). This keeps
the wire format valid.

**`from_dict` class method:**
Returns the most specific ORM class based on `type` field. Unknown types
return bare `STIXBase`. The `_from_dict` helper in `workspace.py` uses
a hardcoded map — update it when adding new ORM types.

---

*Licensed under the Apache License, Version 2.0*
