"""
gnat.connectors.misp.sightings
====================================
Sighting commands for the MISP connector.

Sightings are reports that an attribute value was observed in the wild.
They provide temporal context and crowd-sourced confirmation of IOCs.

Sighting types
--------------
  0 — Sighting (positive observation — "I saw this IOC")
  1 — False positive (attribute is wrong or benign)
  2 — Expiration notification (marking an IOC as expired)

References
----------
- https://www.misp-project.org/openapi/#tag/Sightings
"""

from .client import MISPClient


class MISPSightingCommands:
    """Sighting management operations."""

    def __init__(self, client: MISPClient) -> None:
        self._client = client

    def add_sighting(
        self,
        attribute_id: int | str | None = None,
        value: str | None = None,
        type_sighting: int = 0,
        source: str = "gnat",
        timestamp: int | None = None,
    ) -> dict:
        """
        Report a sighting for an attribute.

        Parameters
        ----------
        attribute_id : int | str | None
            MISP attribute ID to sight. Provide this OR value.
        value : str | None
            Attribute value to sight (MISP resolves to attribute IDs).
        type_sighting : int
            0=Sighting, 1=False positive, 2=Expiration.
        source : str
            Sighting source label.
        timestamp : int | None
            Unix timestamp of the sighting. Defaults to now.

        Returns
        -------
        dict
        """
        import time as _time
        sighting: dict = {
            "type": str(type_sighting),
            "source": source,
            "timestamp": str(timestamp or int(_time.time())),
        }
        if attribute_id:
            sighting["id"] = str(attribute_id)
        if value:
            sighting["values"] = [value]

        response = self._client.post_json("sightings/add", body=sighting)
        return response

    def add_sightings_bulk(
        self,
        values: list[str],
        type_sighting: int = 0,
        source: str = "gnat",
    ) -> dict:
        """
        Report sightings for multiple attribute values at once.

        Parameters
        ----------
        values : list[str]
            IOC values to sight.
        type_sighting : int
            Sighting type.
        source : str
            Source label.

        Returns
        -------
        dict
        """
        import time as _time
        sighting: dict = {
            "values": values,
            "type": str(type_sighting),
            "source": source,
            "timestamp": str(int(_time.time())),
        }
        return self._client.post_json("sightings/add", body=sighting)

    def list_sightings(
        self,
        attribute_id: int | str | None = None,
        event_id: int | str | None = None,
    ) -> list[dict]:
        """
        List sightings for an attribute or event.

        Parameters
        ----------
        attribute_id : int | str | None
        event_id : int | str | None

        Returns
        -------
        list[dict]
        """
        if attribute_id:
            response = self._client.post_json(
                f"sightings/listSightings/{attribute_id}"
            )
        elif event_id:
            response = self._client.post_json(
                f"sightings/listSightings/{event_id}/event"
            )
        else:
            response = self._client.get_json("sightings/index")

        if isinstance(response, list):
            return response
        if isinstance(response, dict):
            return response.get("Sighting", [])
        return []

    def report_false_positive(
        self,
        attribute_id: int | str,
        source: str = "gnat",
    ) -> dict:
        """Report an attribute as a false positive."""
        return self.add_sighting(
            attribute_id=attribute_id,
            type_sighting=1,
            source=source,
        )
