# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.utils.stix_helpers
===========================
Utility functions for working with STIX 2.1 objects and bundles.

Phase 1 additions (PR #1/#2 — Tier 1 connector expansion):

* :func:`make_observed_data_envelope` — deterministic ``observed-data`` SDO
  builder used by sandbox, identity, secret-scanning, and asset connectors.
* :func:`osv_to_stix_vulnerability` — converts an OSV-schema dict to STIX 2.1
  ``vulnerability`` (OSV.dev, VulnCheck, future GitHub Security Advisories).
* :func:`cvss_to_external_reference` — builds a STIX ``external_references``
  entry for a CVSS vector string.
* :func:`make_indicator_pattern` — centralizes STIX pattern construction for
  common cyber observables (ipv4-addr, domain-name, url, file hash).
* :func:`x509_fingerprint_pattern` — builds STIX patterns for x509 / TLS
  fingerprints including JA3/JA3S.

Phase 2 Wave 1 additions:

* :func:`sandbox_report_envelope` — builds an ``observed-data`` envelope
  around a malware-sandbox behavioral report with synthetic file /
  process / network observable refs.  Consumed by every sandbox
  connector (Joe Sandbox, ANY.RUN, Hybrid Analysis, VMRay, Intezer).

Phase 2 Wave 3 additions:

* :func:`bas_simulation_envelope` — builds an ``observed-data`` envelope
  around a Breach-and-Attack-Simulation result, wrapping the targeted
  asset + the MITRE ATT&CK technique(s) being simulated.  Consumed by
  every BAS connector (SafeBreach, AttackIQ, Cymulate, Picus, Pentera,
  XM Cyber).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from gnat.stix.version import CURRENT_SPEC_VERSION

# UUID namespace for deterministic observed-data IDs derived from source +
# observation window + object_refs.  Fixed value so regenerating an ID for
# the same logical observation yields the same UUID across runs.
_NAMESPACE_OBSERVED_DATA = uuid.UUID("7b2e5d3c-4f1a-4d9a-9c3b-2a1f9e8c4d50")


def utcnow() -> str:
    """Return current UTC time in STIX timestamp format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of STIX objects in a STIX bundle."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": CURRENT_SPEC_VERSION,
        "objects": objects,
    }


def extract_objects(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the objects list from a STIX bundle."""
    return bundle.get("objects", [])


def filter_by_type(objects: list[dict[str, Any]], stix_type: str) -> list[dict[str, Any]]:
    """Filter a list of STIX objects by type."""
    return [o for o in objects if o.get("type") == stix_type]


def validate_stix_id(stix_id: str) -> bool:
    """Return True if *stix_id* follows the STIX id format ``<type>--<uuid4>``."""
    parts = stix_id.split("--", 1)
    if len(parts) != 2:
        return False
    try:
        uuid.UUID(parts[1])
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Phase 1 additions
# ---------------------------------------------------------------------------


def make_observed_data_envelope(
    first_observed: str,
    last_observed: str,
    number_observed: int = 1,
    object_refs: list[str] | None = None,
    x_extensions: dict[str, Any] | None = None,
    source_name: str = "",
    created_by_ref: str | None = None,
) -> dict[str, Any]:
    """
    Build a STIX 2.1 ``observed-data`` SDO envelope.

    The returned id is deterministic: UUID-5 derived from *source_name*,
    *first_observed*, and the sorted *object_refs* list.  This means two
    calls with the same inputs produce the same id, which is useful for
    idempotent ingestion pipelines.

    Parameters
    ----------
    first_observed : str
        ISO 8601 / STIX timestamp for the start of the observation window.
    last_observed : str
        ISO 8601 / STIX timestamp for the end of the observation window.
    number_observed : int, optional
        How many times the observation occurred.  Defaults to 1.
    object_refs : list of str, optional
        STIX IDs of cyber-observable SCOs referenced by this envelope.
    x_extensions : dict, optional
        Vendor-specific extension keys (must already be prefixed ``x_``).
    source_name : str, optional
        Short name of the producing source (e.g. ``"joe_sandbox"``).  Used
        as the deterministic id seed and as an ``x_source_name`` extension.
    created_by_ref : str, optional
        STIX ``identity`` id of the producing source, if known.

    Returns
    -------
    dict
        STIX 2.1 ``observed-data`` SDO ready for bundling.

    Examples
    --------
    >>> env = make_observed_data_envelope(
    ...     first_observed="2026-01-01T00:00:00Z",
    ...     last_observed="2026-01-01T00:00:01Z",
    ...     object_refs=["file--11111111-1111-1111-1111-111111111111"],
    ...     source_name="joe_sandbox",
    ... )
    >>> env["type"]
    'observed-data'
    """
    now = utcnow()
    refs = sorted(object_refs or [])
    seed = f"{source_name}|{first_observed}|{','.join(refs)}"
    obs_uuid = uuid.uuid5(_NAMESPACE_OBSERVED_DATA, seed)

    envelope: dict[str, Any] = {
        "type": "observed-data",
        "id": f"observed-data--{obs_uuid}",
        "spec_version": CURRENT_SPEC_VERSION,
        "created": now,
        "modified": now,
        "first_observed": first_observed,
        "last_observed": last_observed,
        "number_observed": max(1, int(number_observed)),
        "object_refs": refs,
    }
    if created_by_ref:
        envelope["created_by_ref"] = created_by_ref
    if source_name:
        envelope["x_source_name"] = source_name
    if x_extensions:
        for k, v in x_extensions.items():
            # Force x_ prefix on vendor extension keys per STIX 2.1 guidance
            key = k if k.startswith("x_") else f"x_{k}"
            envelope[key] = v
    return envelope


def cvss_to_external_reference(
    cvss_vector: str,
    cvss_score: float | None = None,
    cvss_version: str = "3.1",
) -> dict[str, str]:
    """
    Build a STIX ``external_references`` entry for a CVSS vector string.

    Parameters
    ----------
    cvss_vector : str
        The CVSS vector string, e.g. ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``.
    cvss_score : float, optional
        Base score; included in ``description`` when provided.
    cvss_version : str, optional
        CVSS version identifier (``"2.0"``, ``"3.0"``, ``"3.1"``, ``"4.0"``).

    Returns
    -------
    dict
        Dict suitable for inclusion in a STIX object's
        ``external_references`` list.

    Examples
    --------
    >>> cvss_to_external_reference(
    ...     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
    ... )["source_name"]
    'cvss'
    """
    entry: dict[str, str] = {
        "source_name": "cvss",
        "external_id": cvss_vector,
    }
    if cvss_score is not None:
        entry["description"] = f"CVSS v{cvss_version} base score {cvss_score}"
    else:
        entry["description"] = f"CVSS v{cvss_version} vector"
    return entry


def make_indicator_pattern(observable_type: str, value: str) -> str:
    """
    Build a STIX 2.1 indicator pattern string for a common cyber observable.

    Supported ``observable_type`` values:

    * ``"ipv4-addr"`` / ``"ipv6-addr"``
    * ``"domain-name"``
    * ``"url"``
    * ``"email-addr"``
    * ``"file:md5"``, ``"file:sha1"``, ``"file:sha256"``, ``"file:sha512"``
    * ``"x-cryptocurrency-wallet"``

    Parameters
    ----------
    observable_type : str
        The observable type.  File hashes use a ``"file:<algo>"`` format.
    value : str
        The value to embed in the pattern (will be escaped for single quotes).

    Returns
    -------
    str
        A STIX pattern string wrapped in square brackets.

    Raises
    ------
    ValueError
        If *observable_type* is not recognized.

    Examples
    --------
    >>> make_indicator_pattern("ipv4-addr", "1.2.3.4")
    "[ipv4-addr:value = '1.2.3.4']"
    >>> make_indicator_pattern("file:sha256", "abcd")
    "[file:hashes.'SHA-256' = 'abcd']"
    """
    safe = str(value).replace("'", r"\'")
    ot = observable_type.lower().strip()
    simple = {
        "ipv4-addr": "ipv4-addr:value",
        "ipv6-addr": "ipv6-addr:value",
        "domain-name": "domain-name:value",
        "url": "url:value",
        "email-addr": "email-addr:value",
        "x-cryptocurrency-wallet": "x-cryptocurrency-wallet:value",
    }
    if ot in simple:
        return f"[{simple[ot]} = '{safe}']"
    if ot.startswith("file:"):
        algo = ot.split(":", 1)[1].upper()
        # Normalize SHA256 → SHA-256 per STIX hash algorithm names
        if algo.startswith("SHA") and "-" not in algo:
            algo = f"SHA-{algo[3:]}"
        return f"[file:hashes.'{algo}' = '{safe}']"
    raise ValueError(f"Unsupported observable_type: {observable_type!r}")


def x509_fingerprint_pattern(
    sha1: str = "",
    sha256: str = "",
    ja3: str = "",
    ja3s: str = "",
) -> str:
    """
    Build a STIX pattern for an x509 certificate fingerprint or TLS JA3(S).

    At least one of *sha1*, *sha256*, *ja3*, or *ja3s* must be provided.
    If multiple are provided, they are joined with ``OR``.

    Parameters
    ----------
    sha1 : str
        SHA-1 fingerprint of the certificate.
    sha256 : str
        SHA-256 fingerprint of the certificate.
    ja3 : str
        JA3 client fingerprint (network-traffic extension).
    ja3s : str
        JA3S server fingerprint.

    Returns
    -------
    str
        A STIX 2.1 pattern string.

    Raises
    ------
    ValueError
        If no fingerprint values are provided.
    """
    parts: list[str] = []
    if sha256:
        parts.append(f"[x509-certificate:hashes.'SHA-256' = '{sha256}']")
    if sha1:
        parts.append(f"[x509-certificate:hashes.'SHA-1' = '{sha1}']")
    if ja3:
        parts.append(f"[network-traffic:extensions.'tls-ext'.ja3 = '{ja3}']")
    if ja3s:
        parts.append(f"[network-traffic:extensions.'tls-ext'.ja3s = '{ja3s}']")
    if not parts:
        raise ValueError("x509_fingerprint_pattern requires at least one fingerprint")
    return " OR ".join(parts)


def osv_to_stix_vulnerability(osv: dict[str, Any]) -> dict[str, Any]:
    """
    Convert an OSV-schema vulnerability dict to STIX 2.1 ``vulnerability``.

    Handles the common fields of the OSV schema
    (https://ossf.github.io/osv-schema/):

    * ``id`` → STIX ``name`` + canonical external ref
    * ``aliases`` → additional ``external_references`` (CVE, GHSA, etc.)
    * ``summary`` / ``details`` → STIX ``description``
    * ``published`` / ``modified`` → STIX timestamps
    * ``severity`` (CVSS vectors) → ``external_references`` via
      :func:`cvss_to_external_reference`
    * ``affected`` → ``x_osv_affected`` extension preserving ecosystem +
      version ranges
    * ``database_specific.cwe_ids`` → ``x_cwe_ids`` extension

    The returned id is deterministic from the OSV id, so repeat conversions
    produce stable STIX ids for the same vulnerability.

    Parameters
    ----------
    osv : dict
        OSV-schema vulnerability dict.

    Returns
    -------
    dict
        STIX 2.1 ``vulnerability`` SDO.
    """
    osv_id = osv.get("id", "")
    now = utcnow()

    # Deterministic UUID-5 from the OSV id — stable across runs
    vuln_uuid = uuid.uuid5(_NAMESPACE_OBSERVED_DATA, f"osv|{osv_id}")

    external_refs: list[dict[str, str]] = []
    if osv_id:
        # Canonical OSV reference
        if osv_id.upper().startswith("CVE-"):
            external_refs.append(
                {
                    "source_name": "cve",
                    "external_id": osv_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{osv_id}",
                }
            )
        elif osv_id.upper().startswith("GHSA-"):
            external_refs.append(
                {
                    "source_name": "ghsa",
                    "external_id": osv_id,
                    "url": f"https://github.com/advisories/{osv_id}",
                }
            )
        else:
            external_refs.append(
                {
                    "source_name": "osv",
                    "external_id": osv_id,
                    "url": f"https://osv.dev/vulnerability/{osv_id}",
                }
            )

    for alias in osv.get("aliases") or []:
        if not isinstance(alias, str):
            continue
        up = alias.upper()
        if up.startswith("CVE-"):
            external_refs.append({"source_name": "cve", "external_id": alias})
        elif up.startswith("GHSA-"):
            external_refs.append({"source_name": "ghsa", "external_id": alias})
        else:
            external_refs.append({"source_name": "osv-alias", "external_id": alias})

    # CVSS severity → external refs
    for sev in osv.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        vector = sev.get("score") or sev.get("vector") or ""
        sev_type = (sev.get("type") or "").upper()
        if vector and "CVSS" in sev_type:
            version = "3.1"
            if "V2" in sev_type:
                version = "2.0"
            elif "V4" in sev_type:
                version = "4.0"
            elif "V3" in sev_type:
                version = "3.1"
            external_refs.append(cvss_to_external_reference(vector, cvss_version=version))

    description = osv.get("details") or osv.get("summary") or ""

    affected_summary: list[dict[str, Any]] = []
    for aff in osv.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        affected_summary.append(
            {
                "ecosystem": pkg.get("ecosystem", ""),
                "name": pkg.get("name", ""),
                "purl": pkg.get("purl", ""),
                "ranges": aff.get("ranges", []),
                "versions": aff.get("versions", []),
            }
        )

    cwe_ids: list[str] = []
    db = osv.get("database_specific") or {}
    if isinstance(db, dict):
        raw_cwes = db.get("cwe_ids") or db.get("cweIds") or []
        if isinstance(raw_cwes, list):
            cwe_ids = [str(c) for c in raw_cwes]

    stix_obj: dict[str, Any] = {
        "type": "vulnerability",
        "id": f"vulnerability--{vuln_uuid}",
        "spec_version": CURRENT_SPEC_VERSION,
        "created": osv.get("published") or now,
        "modified": osv.get("modified") or now,
        "name": osv_id or "unnamed-osv-vulnerability",
        "description": description,
        "external_references": external_refs,
        "x_osv_affected": affected_summary,
    }
    if cwe_ids:
        stix_obj["x_cwe_ids"] = cwe_ids
    return stix_obj


# ---------------------------------------------------------------------------
# Sandbox report helpers (Phase 2 Wave 1)
# ---------------------------------------------------------------------------


def sandbox_report_envelope(
    source_name: str,
    analysis_id: str,
    submitted_sha256: str = "",
    submitted_filename: str = "",
    submitted_url: str = "",
    processes: list[str] | None = None,
    contacted_ips: list[str] | None = None,
    contacted_domains: list[str] | None = None,
    contacted_urls: list[str] | None = None,
    first_observed: str = "",
    last_observed: str = "",
    verdict: str = "",
    score: float | None = None,
    raw_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a STIX 2.1 ``observed-data`` envelope around a sandbox behavioral
    report.

    The envelope references a synthetic ``file`` SCO for the submitted
    sample (by SHA-256), plus ``process``, ``ipv4-addr``, ``domain-name``,
    and ``url`` SCOs for each behavioral artifact.  All SCO ids are
    deterministic UUID-5 derived from ``source_name`` + ``analysis_id`` +
    the observable value, so repeat ingest is idempotent.

    Parameters
    ----------
    source_name : str
        Short sandbox name (``"joe_sandbox"``, ``"any_run"``, etc.)
    analysis_id : str
        Sandbox-assigned analysis / web / job id.
    submitted_sha256 : str, optional
        SHA-256 of the submitted sample, if known.
    submitted_filename : str, optional
        Filename at submission time.
    submitted_url : str, optional
        URL if the submission was a URL rather than a file.
    processes, contacted_ips, contacted_domains, contacted_urls : list of str
        Behavioral artifacts extracted from the sandbox report.
    first_observed, last_observed : str
        Start / end timestamps of the observation window.
    verdict : str
        Sandbox-assigned verdict string (e.g. ``"malicious"``).
    score : float, optional
        Numeric sandbox score (vendor-specific scale).
    raw_report : dict, optional
        Original raw report dict — preserved under ``x_<source_name>``.

    Returns
    -------
    dict
        STIX 2.1 ``observed-data`` SDO with behavioral object_refs.
    """
    ns = uuid.uuid5(
        _NAMESPACE_OBSERVED_DATA, f"sandbox|{source_name}|{analysis_id}"
    )

    def _sco_ref(sco_type: str, value: str) -> str:
        return f"{sco_type}--{uuid.uuid5(ns, f'{sco_type}|{value}')}"

    refs: list[str] = []
    if submitted_sha256:
        refs.append(_sco_ref("file", submitted_sha256))
    elif submitted_url:
        refs.append(_sco_ref("url", submitted_url))

    for proc in processes or []:
        if proc:
            refs.append(_sco_ref("process", str(proc)))
    for ip in contacted_ips or []:
        if ip:
            refs.append(_sco_ref("ipv4-addr", str(ip)))
    for dom in contacted_domains or []:
        if dom:
            refs.append(_sco_ref("domain-name", str(dom)))
    for url in contacted_urls or []:
        if url:
            refs.append(_sco_ref("url", str(url)))

    first = first_observed or utcnow()
    last = last_observed or first

    extensions: dict[str, Any] = {
        f"{source_name}_analysis_id": analysis_id,
    }
    if submitted_filename:
        extensions[f"{source_name}_filename"] = submitted_filename
    if verdict:
        extensions[f"{source_name}_verdict"] = verdict
    if score is not None:
        extensions[f"{source_name}_score"] = score
    if raw_report is not None:
        extensions[f"{source_name}_raw"] = raw_report

    return make_observed_data_envelope(
        first_observed=first,
        last_observed=last,
        number_observed=1,
        object_refs=refs,
        source_name=source_name,
        x_extensions=extensions,
    )


def bas_simulation_envelope(
    source_name: str,
    simulation_id: str,
    target_assets: list[str] | None = None,
    attack_techniques: list[str] | None = None,
    result: str = "",
    score: float | None = None,
    first_observed: str = "",
    last_observed: str = "",
    raw_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a STIX 2.1 ``observed-data`` envelope around a BAS simulation
    run.

    BAS platforms (SafeBreach, AttackIQ, Cymulate, Picus, Pentera, XM
    Cyber) all emit simulation results describing "we ran attack X
    against asset Y and the result was Z".  This helper wraps that shape
    into a standard envelope with deterministic UUID-5 refs to:

    * synthetic ``identity`` SCOs for each target asset
    * synthetic ``attack-pattern`` SCOs for each MITRE ATT&CK technique

    Parameters
    ----------
    source_name : str
        BAS vendor short name (``"safebreach"``, ``"attackiq"``, …).
    simulation_id : str
        Vendor-assigned id of the simulation run.
    target_assets : list of str, optional
        Hostnames, IPs, or asset ids the simulation targeted.
    attack_techniques : list of str, optional
        MITRE ATT&CK technique ids (``T1055``, ``T1059.001``, …) or
        vendor-native technique names.
    result : str, optional
        Simulation verdict string (``"blocked"``, ``"missed"``,
        ``"detected"``, …).
    score : float, optional
        Vendor-specific numeric score (control efficacy, severity, …).
    first_observed, last_observed : str, optional
        Start / end timestamps of the simulation window.
    raw_report : dict, optional
        Original raw report preserved under ``x_<source_name>_raw``.

    Returns
    -------
    dict
        STIX 2.1 ``observed-data`` SDO with behavioral object_refs.
    """
    ns = uuid.uuid5(
        _NAMESPACE_OBSERVED_DATA, f"bas|{source_name}|{simulation_id}"
    )

    refs: list[str] = []
    for asset in target_assets or []:
        if asset:
            refs.append(f"identity--{uuid.uuid5(ns, f'identity|{asset}')}")
    for tech in attack_techniques or []:
        if tech:
            refs.append(
                f"attack-pattern--{uuid.uuid5(ns, f'attack-pattern|{tech}')}"
            )

    first = first_observed or utcnow()
    last = last_observed or first

    extensions: dict[str, Any] = {
        f"{source_name}_simulation_id": simulation_id,
    }
    if result:
        extensions[f"{source_name}_result"] = result
    if score is not None:
        extensions[f"{source_name}_score"] = score
    if attack_techniques:
        extensions[f"{source_name}_techniques"] = list(attack_techniques)
    if target_assets:
        extensions[f"{source_name}_targets"] = list(target_assets)
    if raw_report is not None:
        extensions[f"{source_name}_raw"] = raw_report

    return make_observed_data_envelope(
        first_observed=first,
        last_observed=last,
        number_observed=1,
        object_refs=refs,
        source_name=source_name,
        x_extensions=extensions,
    )
