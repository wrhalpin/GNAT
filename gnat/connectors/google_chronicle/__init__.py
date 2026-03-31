"""
gnat.connectors.google_chronicle
================================

Google Security Operations (formerly Chronicle) connector for SIEM search, detections, and investigation.
"""

from .client import GoogleChronicleClient

__all__ = ["GoogleChronicleClient"]
