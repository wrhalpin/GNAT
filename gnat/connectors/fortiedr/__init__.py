"""
gnat.connectors.fortiedr
========================

FortiEDR (Fortinet Endpoint Detection and Response) connector.
"""

from .client import FortiEDRClient

__all__ = ["FortiEDRClient"]
