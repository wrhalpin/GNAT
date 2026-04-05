"""
gnat.orm — STIX 2.1 ORM classes with search mixin applied.

This module shows the recommended pattern for applying
:class:`~gnat.search.mixin.STIXSearchMixin` to each SDO/SCO subclass.

Rules of thumb
--------------
* ``STIXSearchMixin`` comes **before** ``STIXBase`` in the MRO so its
  ``to_search_doc()`` method is found first.
* ``_search_text_fields`` is explicit for every class — no relying on
  the fallback scrape of ``_properties``.  Explicit > implicit for a
  v1 schema you control.
* SCOs (IPv4Address, DomainName, URL, FileObject, EmailAddress) are
  **not** given the mixin.  Their ``value`` fields are exact-match
  structured data — they belong in Postgres filter predicates, not a
  full-text index.  Add the mixin only if you later decide to index
  file names, email subjects, or URL paths for FT purposes.
"""

from gnat.orm.base import STIXBase
from gnat.search.mixin import STIXSearchMixin

# ---------------------------------------------------------------------------
# Indicator SDO
# ---------------------------------------------------------------------------


class Indicator(STIXSearchMixin, STIXBase):
    """
    STIX 2.1 Indicator SDO.

    Indexed fields
    --------------
    ``name``, ``description``, ``pattern``

    ``pattern_type`` is intentionally excluded — it's a short vocab
    token ("stix", "snort", "yara") that adds noise to FT results.
    """

    stix_type = "indicator"

    _search_text_fields = ["name", "description", "pattern"]
    _search_display_priority = ["name", "pattern", "description"]

    def __init__(self, client=None, **kwargs):
        kwargs.setdefault("pattern_type", "stix")
        kwargs.setdefault("indicator_types", [])
        super().__init__(client=client, **kwargs)


# ---------------------------------------------------------------------------
# Threat Actor SDO
# ---------------------------------------------------------------------------


class ThreatActor(STIXSearchMixin, STIXBase):
    """
    STIX 2.1 Threat Actor SDO.

    Indexed fields
    --------------
    ``name``, ``description``, ``aliases``, ``goals``,
    ``resource_level``, ``sophistication``, ``roles``

    These are the fields most useful for analyst FT queries:
    "find everything related to Scattered Spider" or
    "show me groups with nation-state resource_level".
    """

    stix_type = "threat-actor"

    _search_text_fields = [
        "name",
        "description",
        "aliases",
        "goals",
        "resource_level",
        "sophistication",
        "roles",
    ]
    _search_display_priority = ["name", "aliases", "description"]

    def __init__(self, client=None, **kwargs):
        kwargs.setdefault("threat_actor_types", [])
        super().__init__(client=client, **kwargs)


# ---------------------------------------------------------------------------
# Malware SDO
# ---------------------------------------------------------------------------


class Malware(STIXSearchMixin, STIXBase):
    """
    STIX 2.1 Malware SDO.

    Indexed fields
    --------------
    ``name``, ``description``, ``aliases``, ``malware_types``
    """

    stix_type = "malware"

    _search_text_fields = ["name", "description", "aliases", "malware_types"]
    _search_display_priority = ["name", "aliases", "description"]

    def __init__(self, client=None, **kwargs):
        kwargs.setdefault("malware_types", [])
        kwargs.setdefault("is_family", False)
        super().__init__(client=client, **kwargs)


# ---------------------------------------------------------------------------
# AttackPattern SDO
# ---------------------------------------------------------------------------


class AttackPattern(STIXSearchMixin, STIXBase):
    """
    STIX 2.1 Attack Pattern SDO (maps to MITRE ATT&CK techniques).

    Indexed fields
    --------------
    ``name``, ``description``

    ATT&CK IDs (T1059, etc.) live in ``external_references`` which is
    structural — not indexed.  Analyst searches like "PowerShell" will
    still match via ``name`` and ``description``.
    """

    stix_type = "attack-pattern"

    _search_text_fields = ["name", "description"]
    _search_display_priority = ["name", "description"]


# ---------------------------------------------------------------------------
# Vulnerability SDO
# ---------------------------------------------------------------------------


class Vulnerability(STIXSearchMixin, STIXBase):
    """
    STIX 2.1 Vulnerability SDO.

    Indexed fields
    --------------
    ``name``, ``description``

    CVE IDs live in ``external_references`` (structural).  The ``name``
    field typically *is* the CVE ID (e.g. "CVE-2024-1234"), so searches
    for CVE IDs by string will still work via ``name``.
    """

    stix_type = "vulnerability"

    _search_text_fields = ["name", "description"]
    _search_display_priority = ["name", "description"]


# ---------------------------------------------------------------------------
# Campaign SDO
# ---------------------------------------------------------------------------


class Campaign(STIXSearchMixin, STIXBase):
    """
    STIX 2.1 Campaign SDO.

    Indexed fields
    --------------
    ``name``, ``description``, ``aliases``, ``objective``
    """

    stix_type = "campaign"

    _search_text_fields = ["name", "description", "aliases", "objective"]
    _search_display_priority = ["name", "aliases", "description"]

    def __init__(self, client=None, **kwargs):
        super().__init__(client=client, **kwargs)


# ---------------------------------------------------------------------------
# SCOs — exact-match; no search mixin
# ---------------------------------------------------------------------------


class Observable(STIXBase):
    """Generic STIX 2.1 Cyber Observable (base)."""

    stix_type = "observed-data"


class IPv4Address(STIXBase):
    """STIX 2.1 IPv4 Address SCO.  Exact-match only — not indexed for FT."""

    stix_type = "ipv4-addr"


class DomainName(STIXBase):
    """STIX 2.1 Domain Name SCO.  Exact-match only — not indexed for FT."""

    stix_type = "domain-name"


class URL(STIXBase):
    """STIX 2.1 URL SCO.  Exact-match only — not indexed for FT."""

    stix_type = "url"


class FileObject(STIXBase):
    """STIX 2.1 File SCO.  Exact-match only — not indexed for FT."""

    stix_type = "file"


class EmailAddress(STIXBase):
    """STIX 2.1 Email Address SCO.  Exact-match only — not indexed for FT."""

    stix_type = "email-addr"


# ---------------------------------------------------------------------------
# Relationship SRO — structural, not indexed
# ---------------------------------------------------------------------------


class Relationship(STIXBase):
    """
    STIX 2.1 Relationship SRO.

    Not indexed for FT — relationships are traversed via structured
    queries (source_ref / target_ref predicates), not keyword search.
    """

    stix_type = "relationship"
