"""
ctm_sak.orm.indicator
=====================

STIX 2.1 Indicator SDO.

An Indicator conveys specific Observable patterns combined with contextual
information about what they mean and how to interpret them.

STIX 2.1 Reference: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v
"""

from ctm_sak.orm.base import STIXBase


class Indicator(STIXBase):
    """
    STIX 2.1 Indicator domain object.

    Parameters
    ----------
    client : SAKClient, optional
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
    **kwargs
        Additional STIX Indicator properties.

    Examples
    --------
    >>> ind = Indicator(client=cli, name="Bad IP", pattern="[ipv4-addr:value = '1.2.3.4']")
    >>> ind.save()
    >>> ind.id
    'indicator--...'
    """

    stix_type = "indicator"

    def __init__(self, client=None, **kwargs):
        kwargs.setdefault("pattern_type", "stix")
        kwargs.setdefault("indicator_types", [])
        super().__init__(client=client, **kwargs)
