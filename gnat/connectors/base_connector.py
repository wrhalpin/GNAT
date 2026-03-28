"""
gnat.connectors.base_connector
==================================

Mixin providing the STIX translation contract every connector must implement.

Connector clients should inherit from BOTH
:class:`~gnat.clients.base.BaseClient` and :class:`ConnectorMixin`::

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

import inspect
from typing import Any, Callable, Dict, List, Optional


# Standard interface methods and their read/write classification
_STANDARD_METHODS: Dict[str, str] = {
    "authenticate":   "auth",
    "health_check":   "read",
    "get_object":     "read",
    "list_objects":   "read",
    "to_stix":        "read",
    "from_stix":      "read",
    "upsert_object":  "write",
    "delete_object":  "write",
}

# Prefixes / names that are never exposed via capabilities()
_PRIVATE_PREFIXES = ("_", "__")
_EXCLUDED_NAMES = frozenset({
    # Python object protocol
    "mro", "subclasshook",
    # BaseClient plumbing — not connector capabilities
    "request", "get", "post", "put", "delete", "patch",
    # ConnectorMixin meta methods themselves
    "capabilities", "call",
})


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

    # ------------------------------------------------------------------
    # Capability reflection
    # ------------------------------------------------------------------

    def capabilities(self) -> Dict[str, Dict[str, Any]]:
        """
        Return a structured inventory of all available connector operations.

        Combines the standard 7-method interface (always present) with any
        public extra methods defined on the concrete subclass.

        Returns
        -------
        dict
            Mapping of method name → metadata dict with keys:

            ``signature`` : str
                Human-readable parameter signature (``(self, ...)`` stripped).
            ``doc`` : str
                First line of the docstring, or ``""`` if undocumented.
            ``type`` : str
                ``"auth"`` | ``"read"`` | ``"write"`` | ``"helper"``.
            ``platform_specific`` : bool
                ``True`` for methods not in the standard 7-method interface.

        Examples
        --------
        >>> caps = client.capabilities()
        >>> caps["list_objects"]["type"]
        'read'
        >>> caps["link_incident"]["platform_specific"]
        True
        """
        result: Dict[str, Dict[str, Any]] = {}
        seen: set = set()

        # Walk the MRO so subclass methods shadow base-class stubs
        for cls in type(self).__mro__:
            for name, obj in vars(cls).items():
                if name in seen:
                    continue
                if name.startswith(_PRIVATE_PREFIXES) or name in _EXCLUDED_NAMES:
                    continue
                if not callable(obj):
                    continue
                seen.add(name)

                method_type = _STANDARD_METHODS.get(name, "helper")
                platform_specific = name not in _STANDARD_METHODS

                try:
                    sig = inspect.signature(obj)
                    params = list(sig.parameters.keys())
                    # Strip leading 'self' for display
                    if params and params[0] == "self":
                        params = params[1:]
                    sig_str = f"({', '.join(params)})"
                except (ValueError, TypeError):
                    sig_str = "(...)"

                doc = ""
                if obj.__doc__:
                    first_line = obj.__doc__.strip().splitlines()[0].strip()
                    doc = first_line

                result[name] = {
                    "signature":         sig_str,
                    "doc":               doc,
                    "type":              method_type,
                    "platform_specific": platform_specific,
                }

        return result

    def call(
        self,
        method_name: str,
        *args: Any,
        allow_write: bool = False,
        **kwargs: Any,
    ) -> Any:
        """
        Safely dispatch to a connector method by name.

        Only methods returned by :meth:`capabilities` can be called; arbitrary
        attribute chains and private methods are not reachable. Write methods
        (``type="write"``) require ``allow_write=True`` to prevent accidental
        data mutation.

        Parameters
        ----------
        method_name : str
            Name of the method to invoke (must appear in ``capabilities()``).
        *args :
            Positional arguments forwarded to the method.
        allow_write : bool
            Set to ``True`` to permit calling ``"write"``-classified methods.
            Default ``False``.
        **kwargs :
            Keyword arguments forwarded to the method.

        Returns
        -------
        Any
            Whatever the target method returns.

        Raises
        ------
        ValueError
            If *method_name* is not in ``capabilities()`` or is a write method
            called without ``allow_write=True``.

        Examples
        --------
        >>> client.call("list_objects", "indicator", limit=50)
        >>> client.call("upsert_object", "indicator", payload, allow_write=True)
        """
        caps = self.capabilities()
        if method_name not in caps:
            raise ValueError(
                f"'{method_name}' is not a known capability of "
                f"{type(self).__name__}.  Available: {sorted(caps.keys())}"
            )
        meta = caps[method_name]
        if meta["type"] == "write" and not allow_write:
            raise ValueError(
                f"'{method_name}' is a write operation.  "
                f"Pass allow_write=True to permit it."
            )
        method: Callable[..., Any] = getattr(self, method_name)
        return method(*args, **kwargs)

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


