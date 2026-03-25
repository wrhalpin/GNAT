"""
ctm_sak.connectors.base_connector
==================================

Mixin providing the STIX translation contract every connector must implement.

Connector clients should inherit from BOTH
:class:`~ctm_sak.clients.base.BaseClient` and :class:`ConnectorMixin`::

    class ThreatQClient(BaseClient, ConnectorMixin):
        stix_type_map = {...}

        def authenticate(self): ...
        def to_stix(self, native): ...
        def from_stix(self, stix_dict): ...
        def get_object(self, stix_type, object_id): ...
        def upsert_object(self, stix_type, payload): ...
        def delete_object(self, stix_type, object_id): ...
        def health_check(self): ...
"""

from typing import Any, Dict, List, Optional


class ConnectorMixin:
    """
    Contract mixin for STIX ↔ native schema translation and CRUD dispatch.

    All methods raise :class:`NotImplementedError` by default and must be
    overridden in concrete connector subclasses.

    Attributes
    ----------
    stix_type_map : dict
        Maps STIX type strings to platform-native resource paths or type
        codes.  Connectors should populate this at class level.
    """

    stix_type_map: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Translation
    # ------------------------------------------------------------------

    def to_stix(self, native_object: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a platform-native object dict to STIX 2.1 format.

        Parameters
        ----------
        native_object : dict
            Raw API response from the target platform.

        Returns
        -------
        dict
            STIX 2.1 representation of the object.
        """
        raise NotImplementedError(f"{type(self).__name__}.to_stix() not implemented")

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX 2.1 dict to the platform-native request payload.

        Parameters
        ----------
        stix_dict : dict
            STIX object dict from ``STIXBase.to_dict()``.

        Returns
        -------
        dict
            Platform-native payload ready for the API.
        """
        raise NotImplementedError(f"{type(self).__name__}.from_stix() not implemented")

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch a single object from the platform by type and id."""
        raise NotImplementedError(f"{type(self).__name__}.get_object() not implemented")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return a list of platform objects of the given STIX type."""
        raise NotImplementedError(f"{type(self).__name__}.list_objects() not implemented")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update an object on the platform."""
        raise NotImplementedError(f"{type(self).__name__}.upsert_object() not implemented")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Delete an object from the platform."""
        raise NotImplementedError(f"{type(self).__name__}.delete_object() not implemented")

    def health_check(self) -> bool:
        """Return True if the platform API is reachable."""
        raise NotImplementedError(f"{type(self).__name__}.health_check() not implemented")


