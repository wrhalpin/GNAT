"""
gnat.stix.object_validator
===========================
STIX 2.1 object-level validator.

Validates STIX 2.1 objects (SDOs, SCOs, SROs, Meta-objects) against the
official specification: required properties, property types, timestamp format,
identifier format, and open/closed vocabulary values.

Two validation modes
---------------------

**Standard** (default)
    Checks required properties and basic type constraints.  Open-vocabulary
    fields accept any string; a warning is added if the value is not in the
    OASIS-defined default vocabulary.

**Strict** (``strict=True``)
    Treats open-vocabulary violations as errors.  Useful for enforcing
    internal data quality standards.

Usage::

    from gnat.stix.object_validator import validate_object, ObjectValidationError

    result = validate_object({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--1d8d7c3e-abc1-4a7e-9f15-0123456789ab",
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Evil IP",
        "pattern": "[ipv4-addr:value = '1.2.3.4']",
        "pattern_type": "stix",
        "valid_from": "2026-01-01T00:00:00.000Z",
    })
    assert result.valid

    result = validate_object({"type": "indicator"})  # missing required fields
    assert not result.valid
    print(result.errors)

    # Raise on failure:
    validate_object(obj, raise_on_error=True)  # raises ObjectValidationError

    # Validate a full STIX bundle:
    from gnat.stix.object_validator import validate_bundle
    result = validate_bundle({"type": "bundle", "id": "bundle--...", "objects": [...]})
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from gnat.stix.version import SUPPORTED_SPEC_VERSIONS

# ---------------------------------------------------------------------------
# Timestamp / identifier regexes
# ---------------------------------------------------------------------------

# STIX 2.1 §3.3: timestamps must be RFC 3339 with millisecond precision
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")

# STIX 2.1 §2.9: identifiers are <type>--<UUID4>
_ID_RE = re.compile(
    r"^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

# ---------------------------------------------------------------------------
# Common required properties for all STIX objects (§3.2)
# ---------------------------------------------------------------------------

_COMMON_REQUIRED: frozenset[str] = frozenset({"type", "spec_version", "id", "created", "modified"})

# Properties that must be valid timestamps
_TIMESTAMP_PROPS: frozenset[str] = frozenset(
    {
        "created",
        "modified",
        "valid_from",
        "valid_until",
        "first_seen",
        "last_seen",
        "published",
        "first_observed",
        "last_observed",
        "start_time",
        "stop_time",
    }
)

# ---------------------------------------------------------------------------
# Per-type required properties (beyond the common set)
# ---------------------------------------------------------------------------

_TYPE_REQUIRED: dict[str, frozenset[str]] = {
    # SDOs
    "attack-pattern": frozenset({"name"}),
    "campaign": frozenset({"name"}),
    "course-of-action": frozenset({"name"}),
    "grouping": frozenset({"context", "object_refs"}),
    "identity": frozenset({"name"}),
    "incident": frozenset({"name"}),
    "indicator": frozenset({"pattern", "pattern_type", "valid_from"}),
    "infrastructure": frozenset({"name", "infrastructure_types"}),
    "intrusion-set": frozenset({"name"}),
    "location": frozenset(),  # name or at least one geo property recommended but not required
    "malware": frozenset({"name", "is_family"}),
    "malware-analysis": frozenset({"product", "result"}),
    "note": frozenset({"content", "object_refs"}),
    "observed-data": frozenset(
        {"first_observed", "last_observed", "number_observed", "object_refs"}
    ),
    "opinion": frozenset({"opinion", "object_refs"}),
    "report": frozenset({"name", "published", "object_refs"}),
    "threat-actor": frozenset({"name", "threat_actor_types"}),
    "tool": frozenset({"name", "tool_types"}),
    "vulnerability": frozenset({"name"}),
    # SROs
    "relationship": frozenset({"relationship_type", "source_ref", "target_ref"}),
    "sighting": frozenset({"sighting_of_ref"}),
    # SCOs (spec_version, id are still required per §10.1)
    "artifact": frozenset(),
    "autonomous-system": frozenset({"number"}),
    "directory": frozenset({"path"}),
    "domain-name": frozenset({"value"}),
    "email-addr": frozenset({"value"}),
    "email-message": frozenset({"is_multipart"}),
    "file": frozenset(),
    "ipv4-addr": frozenset({"value"}),
    "ipv6-addr": frozenset({"value"}),
    "mac-addr": frozenset({"value"}),
    "mutex": frozenset({"name"}),
    "network-traffic": frozenset({"dst_ref", "protocols"}),
    "process": frozenset(),
    "software": frozenset({"name"}),
    "url": frozenset({"value"}),
    "user-account": frozenset(),
    "windows-registry-key": frozenset(),
    "x509-certificate": frozenset(),
    # Meta-objects
    "bundle": frozenset({"id"}),  # type + id; spec_version not required on bundle
    "marking-definition": frozenset({"definition_type", "created"}),
    "language-content": frozenset({"object_ref", "object_modified", "contents"}),
    "extension-definition": frozenset({"name", "schema", "version", "extension_types"}),
}

# ---------------------------------------------------------------------------
# Open vocabularies (§7) — warnings only unless strict=True
# ---------------------------------------------------------------------------

_OPEN_VOCAB: dict[str, frozenset[str]] = {
    "indicator_types": frozenset(
        {
            "anomalous-activity",
            "anonymization",
            "benign",
            "compromised",
            "malicious-activity",
            "attribution",
            "unknown",
        }
    ),
    "malware_types": frozenset(
        {
            "adware",
            "backdoor",
            "bot",
            "bootkit",
            "ddos",
            "downloader",
            "dropper",
            "exploit-kit",
            "keylogger",
            "ransomware",
            "remote-access-trojan",
            "resource-exploitation",
            "rogue-security-software",
            "rootkit",
            "screen-capture",
            "spyware",
            "trojan",
            "unknown",
            "virus",
            "webshell",
            "wiper",
            "worm",
        }
    ),
    "threat_actor_types": frozenset(
        {
            "activist",
            "competitor",
            "crime-syndicate",
            "criminal",
            "hacker",
            "insider-accidental",
            "insider-disgruntled",
            "nation-state",
            "sensationalist",
            "spy",
            "terrorist",
            "unknown",
        }
    ),
    "tool_types": frozenset(
        {
            "denial-of-service",
            "exploitation",
            "information-gathering",
            "network-capture",
            "credential-exploitation",
            "remote-access",
            "vulnerability-scanning",
            "unknown",
        }
    ),
    "attack_motivation": frozenset(
        {
            "accidental",
            "coercion",
            "dominance",
            "ideology",
            "notoriety",
            "organizational-gain",
            "personal-gain",
            "personal-satisfaction",
            "revenge",
            "unpredictable",
        }
    ),
    "infrastructure_types": frozenset(
        {
            "amplification",
            "anonymization",
            "botnet",
            "command-and-control",
            "exfiltration",
            "hosting-malware",
            "hosting-victim-websites",
            "phishing",
            "reconnaissance",
            "rooting",
            "staging",
            "unknown",
        }
    ),
    "report_types": frozenset(
        {
            "attack-pattern",
            "campaign",
            "identity",
            "indicator",
            "intrusion-set",
            "malware",
            "observed-data",
            "threat-actor",
            "threat-report",
            "tool",
            "vulnerability",
        }
    ),
    "opinion": frozenset(
        {
            "strongly-disagree",
            "disagree",
            "neutral",
            "agree",
            "strongly-agree",
        }
    ),
    "grouping_context": frozenset(
        {
            "suspicious-activity",
            "malware-analysis",
            "unspecified",
        }
    ),
    "malware_result": frozenset(
        {
            "malicious",
            "suspicious",
            "benign",
            "unknown",
        }
    ),
    "pattern_type": frozenset(
        {
            "stix",
            "pcre",
            "sigma",
            "snort",
            "suricata",
            "yara",
        }
    ),
    "relationship_type": frozenset(
        {
            "attributed-to",
            "based-on",
            "beacons-to",
            "communicates-with",
            "compromises",
            "consists-of",
            "controls",
            "delivers",
            "derived-from",
            "downloads",
            "drops",
            "duplicate-of",
            "dynamic-analysis-of",
            "exfiltrates-to",
            "exploits",
            "has",
            "hosts",
            "impersonates",
            "indicates",
            "investigated-by",
            "located-at",
            "mitigates",
            "originates-from",
            "owns",
            "related-to",
            "remediates",
            "resolves-to",
            "revoked-by",
            "static-analysis-of",
            "subtechnique-of",
            "targets",
            "uses",
            "variant-of",
        }
    ),
}

# ---------------------------------------------------------------------------
# Closed vocabularies (§7) — always errors
# ---------------------------------------------------------------------------

_CLOSED_VOCAB: dict[str, frozenset[str]] = {
    "spec_version": SUPPORTED_SPEC_VERSIONS,
    "definition_type": frozenset({"tlp", "statement"}),
}

# ---------------------------------------------------------------------------
# Boolean properties — must be bool
# ---------------------------------------------------------------------------

_BOOL_PROPS: frozenset[str] = frozenset(
    {
        "is_family",
        "is_multipart",
        "is_hidden",
        "is_self_signed",
        "revoked",
        "defanged",
        "can_escalate_privs",
        "is_disabled",
        "is_privileged",
        "is_service_account",
        "is_aslr_enabled",
        "is_dep_enabled",
    }
)

# ---------------------------------------------------------------------------
# Integer properties — must be int (or castable)
# ---------------------------------------------------------------------------

_INT_PROPS: frozenset[str] = frozenset(
    {
        "number_observed",
        "confidence",
        "number",
        "pid",
        "uid",
        "gid",
        "src_port",
        "dst_port",
        "x_priority",
    }
)

# Confidence range per STIX 2.1 §3.2.7
_CONFIDENCE_RANGE = (0, 100)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ObjectValidationResult:
    """
    Result of validating a single STIX 2.1 object.

    Attributes
    ----------
    valid : bool
        ``True`` if the object passes all checks (errors list is empty).
    errors : list of str
        Critical violations — required fields missing, wrong types, bad format.
    warnings : list of str
        Non-critical issues — open-vocabulary values not in default set,
        unknown extension properties, etc.
    object_type : str
        The ``type`` value of the validated object, or ``"<unknown>"`` if
        the type field is missing.
    object_id : str
        The ``id`` value, or ``"<unknown>"``.
    """

    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    object_type: str = "<unknown>"
    object_id: str = "<unknown>"

    def _add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.valid = False

    def _add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def __bool__(self) -> bool:  # noqa: D105
        return self.valid


@dataclass
class BundleValidationResult:
    """
    Aggregated result of validating all objects in a STIX bundle.

    Attributes
    ----------
    valid : bool
        ``True`` only if every object in the bundle passes validation.
    object_results : list of ObjectValidationResult
        Per-object results in the same order as ``bundle["objects"]``.
    bundle_errors : list of str
        Errors on the bundle wrapper itself (missing ``id``, bad ``type``).
    """

    valid: bool = True
    object_results: list[ObjectValidationResult] = field(default_factory=list)
    bundle_errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:  # noqa: D105
        return self.valid

    @property
    def all_errors(self) -> list[str]:
        """Flat list of every error across bundle and all contained objects."""
        errs = list(self.bundle_errors)
        for r in self.object_results:
            errs.extend(r.errors)
        return errs

    @property
    def all_warnings(self) -> list[str]:
        """Flat list of every warning across all contained objects."""
        warns: list[str] = []
        for r in self.object_results:
            warns.extend(r.warnings)
        return warns


class ObjectValidationError(Exception):
    """
    Raised by :func:`validate_object` when ``raise_on_error=True`` and the
    object has validation errors.

    Attributes
    ----------
    result : ObjectValidationResult
        The full result including error messages.
    """

    def __init__(self, result: ObjectValidationResult) -> None:
        super().__init__(
            f"STIX object validation failed ({result.object_type} {result.object_id}): "
            + "; ".join(result.errors)
        )
        self.result = result


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------


class STIXObjectValidator:
    """
    Validates STIX 2.1 objects against the official specification.

    Parameters
    ----------
    strict : bool
        When ``True``, open-vocabulary violations are treated as errors
        rather than warnings.
    allow_custom : bool
        When ``True``, objects with ``type`` values not in the known STIX 2.1
        type set are accepted without an error (custom objects are allowed by
        the STIX 2.1 spec as long as the ``type`` starts with ``x-``).
    raise_on_error : bool
        When ``True``, :meth:`validate` raises :exc:`ObjectValidationError`
        on any validation error.
    """

    def __init__(
        self,
        strict: bool = False,
        allow_custom: bool = True,
        raise_on_error: bool = False,
    ) -> None:
        self._strict = strict
        self._allow_custom = allow_custom
        self._raise = raise_on_error

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(self, obj: dict[str, Any]) -> ObjectValidationResult:
        """
        Validate a single STIX 2.1 object dict.

        Parameters
        ----------
        obj : dict
            A STIX 2.1 object as a plain Python dict.

        Returns
        -------
        ObjectValidationResult
        """
        result = ObjectValidationResult()

        if not isinstance(obj, dict):
            result._add_error("Object must be a dict")
            if self._raise:
                raise ObjectValidationError(result)
            return result

        obj_type = obj.get("type", "")
        obj_id = obj.get("id", "<unknown>")
        result.object_type = obj_type or "<unknown>"
        result.object_id = str(obj_id)

        self._check_type(obj, obj_type, result)
        self._check_common_required(obj, obj_type, result)
        self._check_id(obj, obj_type, result)
        self._check_timestamps(obj, result)
        self._check_type_required(obj, obj_type, result)
        self._check_booleans(obj, result)
        self._check_integers(obj, result)
        self._check_confidence(obj, result)
        self._check_open_vocabs(obj, result)
        self._check_closed_vocabs(obj, result)
        self._check_ref_format(obj, result)

        if self._raise and not result.valid:
            raise ObjectValidationError(result)

        return result

    # ------------------------------------------------------------------
    # Private checks
    # ------------------------------------------------------------------

    def _check_type(self, obj: dict, obj_type: str, result: ObjectValidationResult) -> None:
        """Validate the ``type`` field."""
        if not obj_type:
            result._add_error("Missing required property 'type'")
            return

        known = set(_TYPE_REQUIRED.keys())
        if obj_type not in known:
            if self._allow_custom:
                if not re.match(r"^x-[a-z][a-z0-9-]*$", obj_type):
                    result._add_warning(
                        f"Unknown type {obj_type!r} — custom types should start with 'x-'"
                    )
            else:
                result._add_error(
                    f"Unknown STIX 2.1 type {obj_type!r}; "
                    "use allow_custom=True to permit custom types"
                )

    def _check_common_required(
        self, obj: dict, obj_type: str, result: ObjectValidationResult
    ) -> None:
        """Check common required fields (type, spec_version, id, created, modified)."""
        # Bundles have a different required set
        if obj_type == "bundle":
            for prop in ("type", "id"):
                if prop not in obj:
                    result._add_error(f"Bundle missing required property '{prop}'")
            return

        # Marking definitions don't require spec_version or modified
        skip_modified = obj_type in ("marking-definition",)
        for prop in _COMMON_REQUIRED:
            if skip_modified and prop in ("modified", "spec_version"):
                continue
            if prop not in obj:
                result._add_error(f"Missing required property '{prop}'")

    def _check_id(self, obj: dict, obj_type: str, result: ObjectValidationResult) -> None:
        """Validate ``id`` format: <type>--<UUID4>."""
        obj_id = obj.get("id")
        if not obj_id:
            return  # already caught by _check_common_required
        if not isinstance(obj_id, str):
            result._add_error(f"Property 'id' must be a string, got {type(obj_id).__name__}")
            return
        if not _ID_RE.match(obj_id):
            result._add_error(f"Property 'id' must follow <type>--<UUID4> format; got {obj_id!r}")
            return
        # Type prefix must match the object's type
        id_prefix = obj_id.split("--")[0]
        if obj_type and id_prefix != obj_type:
            result._add_error(f"ID prefix {id_prefix!r} does not match object type {obj_type!r}")

    def _check_timestamps(self, obj: dict, result: ObjectValidationResult) -> None:
        """Validate all timestamp properties."""
        for prop in _TIMESTAMP_PROPS:
            val = obj.get(prop)
            if val is None:
                continue
            if not isinstance(val, str):
                result._add_error(
                    f"Property '{prop}' must be a string timestamp, got {type(val).__name__}"
                )
            elif not _TIMESTAMP_RE.match(val):
                result._add_error(
                    f"Property '{prop}' has invalid timestamp format {val!r}; "
                    "expected YYYY-MM-DDTHH:MM:SS[.fff]Z"
                )

    def _check_type_required(
        self, obj: dict, obj_type: str, result: ObjectValidationResult
    ) -> None:
        """Check per-type required properties."""
        required = _TYPE_REQUIRED.get(obj_type, frozenset())
        for prop in required:
            if prop not in obj:
                result._add_error(f"Type '{obj_type}' requires property '{prop}'")

    def _check_booleans(self, obj: dict, result: ObjectValidationResult) -> None:
        """Validate boolean properties."""
        for prop in _BOOL_PROPS:
            val = obj.get(prop)
            if val is None:
                continue
            if not isinstance(val, bool):
                result._add_error(f"Property '{prop}' must be a boolean, got {type(val).__name__}")

    def _check_integers(self, obj: dict, result: ObjectValidationResult) -> None:
        """Validate integer properties (excluding booleans which are int subclass)."""
        for prop in _INT_PROPS:
            val = obj.get(prop)
            if val is None:
                continue
            if isinstance(val, bool) or not isinstance(val, int):
                result._add_error(f"Property '{prop}' must be an integer, got {type(val).__name__}")

    def _check_confidence(self, obj: dict, result: ObjectValidationResult) -> None:
        """Validate confidence is in [0, 100]."""
        val = obj.get("confidence")
        if val is None:
            return
        if isinstance(val, bool) or not isinstance(val, int):
            result._add_error("Property 'confidence' must be an integer")
            return
        lo, hi = _CONFIDENCE_RANGE
        if not (lo <= val <= hi):
            result._add_error(f"Property 'confidence' must be in [{lo}, {hi}], got {val}")

    def _check_open_vocabs(self, obj: dict, result: ObjectValidationResult) -> None:
        """Warn (or error in strict mode) when open-vocab values are non-standard."""
        for prop, vocab in _OPEN_VOCAB.items():
            val = obj.get(prop)
            if val is None:
                continue
            values = val if isinstance(val, list) else [val]
            for v in values:
                if isinstance(v, str) and v not in vocab:
                    msg = f"Property '{prop}' value {v!r} is not in the STIX 2.1 default vocabulary"
                    if self._strict:
                        result._add_error(msg)
                    else:
                        result._add_warning(msg)

    def _check_closed_vocabs(self, obj: dict, result: ObjectValidationResult) -> None:
        """Error when closed-vocab values are invalid."""
        for prop, vocab in _CLOSED_VOCAB.items():
            val = obj.get(prop)
            if val is None:
                continue
            if isinstance(val, str) and val not in vocab:
                result._add_error(
                    f"Property '{prop}' value {val!r} is not a valid "
                    f"STIX 2.1 value; allowed: {sorted(vocab)}"
                )

    def _check_ref_format(self, obj: dict, result: ObjectValidationResult) -> None:
        """Validate _ref / _refs properties contain valid STIX identifiers."""
        for key, val in obj.items():
            if key.endswith("_ref") and isinstance(val, str):
                if not _ID_RE.match(val):
                    result._add_error(
                        f"Property '{key}' must be a valid STIX identifier, got {val!r}"
                    )
            elif key.endswith("_refs") and isinstance(val, list):
                for i, ref in enumerate(val):
                    if isinstance(ref, str) and not _ID_RE.match(ref):
                        result._add_error(
                            f"Property '{key}[{i}]' must be a valid STIX identifier, got {ref!r}"
                        )


# ---------------------------------------------------------------------------
# Bundle validator
# ---------------------------------------------------------------------------


class STIXBundleValidator:
    """
    Validates a STIX 2.1 bundle and all objects it contains.

    Parameters
    ----------
    strict : bool
        Passed through to :class:`STIXObjectValidator` for each object.
    allow_custom : bool
        Passed through to :class:`STIXObjectValidator`.
    raise_on_error : bool
        When ``True``, raises :exc:`ObjectValidationError` on the first
        object-level error encountered.
    """

    def __init__(
        self,
        strict: bool = False,
        allow_custom: bool = True,
        raise_on_error: bool = False,
    ) -> None:
        self._obj_validator = STIXObjectValidator(
            strict=strict,
            allow_custom=allow_custom,
            raise_on_error=raise_on_error,
        )

    def validate(self, bundle: dict[str, Any]) -> BundleValidationResult:
        """
        Validate a STIX 2.1 bundle dict.

        Parameters
        ----------
        bundle : dict
            A STIX 2.1 bundle as a plain Python dict.

        Returns
        -------
        BundleValidationResult
        """
        result = BundleValidationResult()

        if not isinstance(bundle, dict):
            result.bundle_errors.append("Bundle must be a dict")
            result.valid = False
            return result

        if bundle.get("type") != "bundle":
            result.bundle_errors.append(f"Expected type 'bundle', got {bundle.get('type')!r}")
            result.valid = False

        if "id" not in bundle:
            result.bundle_errors.append("Bundle missing required property 'id'")
            result.valid = False
        elif not isinstance(bundle["id"], str) or not _ID_RE.match(bundle["id"]):
            result.bundle_errors.append(
                f"Bundle 'id' must follow bundle--<UUID4> format; got {bundle.get('id')!r}"
            )
            result.valid = False

        objects = bundle.get("objects")
        if objects is not None:
            if not isinstance(objects, list):
                result.bundle_errors.append("Bundle 'objects' must be a list")
                result.valid = False
            else:
                for obj in objects:
                    obj_result = self._obj_validator.validate(obj)
                    result.object_results.append(obj_result)
                    if not obj_result.valid:
                        result.valid = False

        return result


# ---------------------------------------------------------------------------
# Module-level convenience functions
# ---------------------------------------------------------------------------


def validate_object(
    obj: dict[str, Any],
    strict: bool = False,
    allow_custom: bool = True,
    raise_on_error: bool = False,
) -> ObjectValidationResult:
    """
    Validate a single STIX 2.1 object.

    Parameters
    ----------
    obj : dict
        A STIX 2.1 object as a plain Python dict.
    strict : bool
        Treat open-vocabulary violations as errors (default False).
    allow_custom : bool
        Allow ``x-`` prefixed custom types (default True).
    raise_on_error : bool
        Raise :exc:`ObjectValidationError` on any error (default False).

    Returns
    -------
    ObjectValidationResult
        ``bool(result)`` is ``True`` iff the object is valid.
    """
    return STIXObjectValidator(
        strict=strict, allow_custom=allow_custom, raise_on_error=raise_on_error
    ).validate(obj)


def validate_bundle(
    bundle: dict[str, Any],
    strict: bool = False,
    allow_custom: bool = True,
    raise_on_error: bool = False,
) -> BundleValidationResult:
    """
    Validate a STIX 2.1 bundle and all objects it contains.

    Parameters
    ----------
    bundle : dict
        A STIX 2.1 bundle as a plain Python dict.
    strict : bool
        Treat open-vocabulary violations as errors (default False).
    allow_custom : bool
        Allow ``x-`` prefixed custom types (default True).
    raise_on_error : bool
        Raise :exc:`ObjectValidationError` on the first error (default False).

    Returns
    -------
    BundleValidationResult
        ``bool(result)`` is ``True`` iff the bundle and all objects are valid.
    """
    return STIXBundleValidator(
        strict=strict, allow_custom=allow_custom, raise_on_error=raise_on_error
    ).validate(bundle)
