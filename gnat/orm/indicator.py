# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.orm.indicator
=====================

STIX 2.1 Indicator SDO.

An Indicator conveys specific Observable patterns combined with contextual
information about what they mean and how to interpret them.

STIX 2.1 Reference: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v
"""

import logging

from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


class Indicator(STIXBase):
    """
    STIX 2.1 Indicator domain object.

    Parameters
    ----------
    client : GNATClient, optional
        Bound client for CRUD operations.
    name : str, optional
        Human-readable name of the indicator.
    description : str, optional
        Explanation of what the indicator represents.
    pattern : str, optional
        STIX Pattern expression (e.g. ``"[ipv4-addr:value = '1.2.3.4']"``).
    pattern_type : str, optional
        Pattern language identifier.  Defaults to ``"stix"``.
    valid_from : str, optional
        Timestamp from which the indicator is considered valid.
    indicator_types : list of str, optional
        Open vocabulary indicator type labels.
    validate : bool, optional
        When ``True`` and ``pattern_type == "stix"``, validate the STIX pattern
        syntax at construction time.  Errors are logged as warnings; no
        exception is raised.  Defaults to ``False`` (non-breaking).
    **kwargs
        Additional STIX Indicator properties.

    Examples
    --------
    >>> ind = Indicator(client=cli, name="Bad IP", pattern="[ipv4-addr:value = '1.2.3.4']")
    >>> ind.save()
    >>> ind.id
    'indicator--...'
    >>> # With validation:
    >>> ind = Indicator(pattern="[ipv4-addr:value = '1.2.3.4']", validate=True)
    """

    stix_type = "indicator"

    def __init__(self, client=None, **kwargs):
        validate = kwargs.pop("validate", False)
        kwargs.setdefault("pattern_type", "stix")
        kwargs.setdefault("indicator_types", [])
        super().__init__(client=client, **kwargs)

        if validate and kwargs.get("pattern_type", "stix") == "stix":
            pattern = kwargs.get("pattern")
            if pattern:
                self._validate_pattern(pattern)

    def _validate_pattern(self, pattern: str) -> None:
        """Validate *pattern* using the STIX pattern validator; log warnings on failure."""
        try:
            from gnat.stix.pattern_validator import validate_pattern
        except ImportError:
            return

        result = validate_pattern(pattern)
        if not result.valid:
            logger.warning(
                "Indicator pattern failed validation: %s — errors: %s",
                pattern,
                "; ".join(result.errors),
            )
        for warning in result.warnings:
            logger.debug("Indicator pattern warning: %s", warning)
