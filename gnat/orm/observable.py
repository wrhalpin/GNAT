# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.orm.observable
======================
STIX 2.1 Cyber Observable Object (SCO) base.
"""

from gnat.orm.base import STIXBase


class Observable(STIXBase):
    """
    Generic STIX 2.1 Cyber Observable.

    For typed observables use the specific SCO subclasses:
    IPv4Address, DomainName, URL, FileObject, EmailAddress.
    """

    stix_type = "observed-data"


class IPv4Address(STIXBase):
    """STIX 2.1 IPv4 Address SCO."""

    stix_type = "ipv4-addr"


class DomainName(STIXBase):
    """STIX 2.1 Domain Name SCO."""

    stix_type = "domain-name"


class URL(STIXBase):
    """STIX 2.1 URL SCO."""

    stix_type = "url"


class FileObject(STIXBase):
    """STIX 2.1 File SCO."""

    stix_type = "file"


class EmailAddress(STIXBase):
    """STIX 2.1 Email Address SCO."""

    stix_type = "email-addr"
