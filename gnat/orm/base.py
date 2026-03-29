"""
gnat.orm.base
================

STIX 2.1-compatible base ORM class for all GNAT domain objects.

Every STIX Domain Object (SDO), Relationship Object (SRO), and Cyber
Observable Object (SCO) is modelled as a subclass of :class:`STIXBase`.

Design Goals
------------
* **STIX 2.1 wire-format compatible** – ``to_dict()`` / ``from_dict()``
  produce/consume valid STIX bundles.
* **Client-bound** – objects carry an optional :class:`~gnat.client.GNATClient`
  reference so CRUD methods work transparently.
* **Platform-agnostic** – translators in each connector package convert
  between STIX and the target platform's native schema.

CRUD Conventions
----------------
+----------+-----------------------------------+
| Method   | Behaviour                         |
+==========+===================================+
| select() | Fetch object by id from platform  |
+----------+-----------------------------------+
| save()   | Create if no id, update if id set |
+----------+-----------------------------------+
| delete() | Delete object from platform       |
+----------+-----------------------------------+
| refresh()| Re-fetch and update in-place      |
+----------+-----------------------------------+
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from gnat.client import GNATClient


def _utcnow() -> str:
    """Return the current UTC timestamp in STIX format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class STIXBase:
    """
    Abstract base for all GNAT ORM objects.

    Subclasses must set the class attribute :attr:`stix_type` to the
    appropriate STIX 2.1 type string (e.g. ``"indicator"``,
    ``"threat-actor"``).

    Parameters
    ----------
    client : GNATClient, optional
        Bound client used for CRUD operations.  If omitted objects can still
        be constructed and serialised but CRUD methods will raise
        :class:`RuntimeError`.
    **kwargs
        Arbitrary STIX property values (e.g. ``name=``, ``value=``).

    Examples
    --------
    >>> ind = Indicator(client=cli, value="evil.com", type="domain-name")
    >>> ind.id = "indicator--abc123"
    >>> ind.select()
    """

    stix_type: str = "stix-object"

    def __init__(
        self,
        client: Optional["GNATClient"] = None,
        **kwargs: Any,
    ):
        self._client = client
        # Core STIX identity fields
        self.id: str = kwargs.pop("id", f"{self.stix_type}--{uuid.uuid4()}")
        self.spec_version: str = kwargs.pop("spec_version", "2.1")
        self.created: str = kwargs.pop("created", _utcnow())
        self.modified: str = kwargs.pop("modified", _utcnow())
        # Additional fields stored in a generic bag
        self._properties: Dict[str, Any] = kwargs

    # ------------------------------------------------------------------
    # Property access
    # ------------------------------------------------------------------

    def __getattr__(self, name: str) -> Any:
        # Only called when normal attribute lookup fails
        try:
            return self._properties[name]
        except KeyError:
            raise AttributeError(
                f"{type(self).__name__!r} has no attribute {name!r}"
            ) from None

    def __setattr__(self, name: str, value: Any) -> None:
        _core = {"_client", "_properties", "id", "spec_version", "created", "modified"}
        if name.startswith("_") or name in _core or name in type(self).__dict__:
            super().__setattr__(name, value)
        else:
            self._properties[name] = value

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialise this object to a STIX 2.1-compatible dictionary.

        Returns
        -------
        dict
            STIX object representation suitable for JSON encoding.
        """
        d: Dict[str, Any] = {
            "type": self.stix_type,
            "spec_version": self.spec_version,
            "id": self.id,
            "created": self.created,
            "modified": self.modified,
        }
        d.update(self._properties)
        return d

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        client: Optional["GNATClient"] = None,
    ) -> "STIXBase":
        """
        Construct an instance from a STIX-format dictionary.

        Parameters
        ----------
        data : dict
            STIX object dictionary (e.g. parsed from a JSON bundle).
        client : GNATClient, optional
            Client to bind to the new instance.

        Returns
        -------
        STIXBase
            Populated instance.
        """
        data = dict(data)
        data.pop("type", None)
        return cls(client=client, **data)

    def to_stix_bundle(self) -> Dict[str, Any]:
        """
        Wrap this object in a minimal STIX 2.1 bundle.

        Returns
        -------
        dict
            A ``{"type": "bundle", ...}`` wrapper.
        """
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": [self.to_dict()],
        }

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def select(self) -> "STIXBase":
        """
        Fetch this object from the connected platform by :attr:`id`.

        The remote data is merged into *this* instance in-place.

        Returns
        -------
        STIXBase
            ``self``, updated with platform data.

        Raises
        ------
        RuntimeError
            If no client is bound to this object.
        """
        self._require_client()
        data = self._client.client.get_object(self.stix_type, self.id)
        translated = self._client.client.to_stix(data)
        self._merge(translated)
        return self

    def save(self) -> "STIXBase":
        """
        Create or update this object on the connected platform.

        If :attr:`id` contains a server-generated value (i.e. no prior
        ``select()`` has run) a new object is created; otherwise the
        existing object is updated.

        Returns
        -------
        STIXBase
            ``self``, potentially with server-assigned fields updated.
        """
        self._require_client()
        payload = self._client.client.from_stix(self.to_dict())
        result = self._client.client.upsert_object(self.stix_type, payload)
        translated = self._client.client.to_stix(result)
        self._merge(translated)
        return self

    def delete(self) -> None:
        """
        Delete this object from the connected platform.

        Raises
        ------
        RuntimeError
            If no client is bound.
        """
        self._require_client()
        self._client.client.delete_object(self.stix_type, self.id)

    def refresh(self) -> "STIXBase":
        """Re-fetch and update this object from the platform. Alias of select()."""
        return self.select()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_client(self) -> None:
        if self._client is None or self._client.client is None:
            raise RuntimeError(
                f"No client bound to this {type(self).__name__}. "
                "Pass client= when constructing the object or call "
                "GNATClient.connect() first."
            )

    def _merge(self, data: Dict[str, Any]) -> None:
        """Merge a STIX dict into this instance, updating all properties."""
        for key, value in data.items():
            if key in ("type", "spec_version"):
                continue
            if key == "id":
                self.id = value
            elif key == "created":
                self.created = value
            elif key == "modified":
                self.modified = value
            else:
                self._properties[key] = value

    def __repr__(self) -> str:  # pragma: no cover
        return f"{type(self).__name__}(id={self.id!r})"
