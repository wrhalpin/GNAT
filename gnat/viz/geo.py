# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.viz.geo
=============

Geospatial threat heatmap visualisation.

Renders country-level threat intensity heatmaps from STIX objects that carry
``country`` or ``x_country`` metadata.  The output is a self-contained HTML
file using Plotly choropleth (no server required).

Usage::

    from gnat.viz.geo import GeoView
    from gnat.orm.base import STIXBase

    view = GeoView(objects)
    view.render_threat_heatmap(output="threats_by_country.html")
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Mapping from common country aliases to ISO-3 alpha codes
_COUNTRY_ISO3: dict[str, str] = {
    "united states": "USA",
    "us": "USA",
    "usa": "USA",
    "united kingdom": "GBR",
    "uk": "GBR",
    "gb": "GBR",
    "russia": "RUS",
    "ru": "RUS",
    "china": "CHN",
    "cn": "CHN",
    "iran": "IRN",
    "north korea": "PRK",
    "germany": "DEU",
    "de": "DEU",
    "france": "FRA",
    "fr": "FRA",
    "canada": "CAN",
    "ca": "CAN",
    "australia": "AUS",
    "au": "AUS",
    "brazil": "BRA",
    "br": "BRA",
    "india": "IND",
    "in": "IND",
    "japan": "JPN",
    "jp": "JPN",
    "ukraine": "UKR",
    "ua": "UKR",
    "israel": "ISR",
    "il": "ISR",
    "netherlands": "NLD",
    "nl": "NLD",
    "singapore": "SGP",
    "sg": "SGP",
    "south korea": "KOR",
    "kr": "KOR",
}


def _normalise_country(raw: str) -> str:
    """Map a country name or code to ISO-3 alpha, or return raw upper-cased."""
    key = raw.strip().lower()
    return _COUNTRY_ISO3.get(key, raw.upper()[:3])


class GeoView:
    """
    Geospatial visualisation of threat intelligence data.

    Parameters
    ----------
    objects : list[STIXBase]
        STIX objects to visualise.  Objects without country metadata are ignored.
    country_field : str
        Attribute name on STIX objects holding the country value.
        Defaults to ``"country"``.  Also checks ``"x_country"`` and
        ``"x_gnat_country"`` as fallbacks.
    """

    def __init__(
        self,
        objects: list[Any],
        country_field: str = "country",
    ) -> None:
        self._objects = objects
        self._country_field = country_field

    # ── Public API ──────────────────────────────────────────────────────────────

    def render_threat_heatmap(
        self,
        output: str = "threat_heatmap.html",
        title: str = "Threat Intensity by Country",
        stix_types: list[str] | None = None,
        color_scale: str = "Reds",
    ) -> str:
        """
        Render a country choropleth heatmap of threat object counts.

        Parameters
        ----------
        output : str
            Output HTML file path.
        title : str
            Chart title.
        stix_types : list[str], optional
            Filter to these STIX object types.
        color_scale : str
            Plotly colour scale (e.g. ``"Reds"``, ``"YlOrRd"``, ``"Plasma"``).

        Returns
        -------
        str
            Path to the written HTML file.
        """
        counts = self._count_by_country(stix_types)
        if not counts:
            logger.warning("GeoView.render_threat_heatmap: no country data found")
            counts = {"USA": 0}  # empty placeholder

        locations = list(counts.keys())
        z_values = [counts[loc] for loc in locations]

        # Build self-contained HTML with embedded Plotly
        import json as _json

        chart_data = _json.dumps(
            {
                "type": "choropleth",
                "locations": locations,
                "z": z_values,
                "locationmode": "ISO-3",
                "colorscale": color_scale,
                "colorbar": {"title": "Object Count"},
                "hovertemplate": "%{location}: %{z} objects<extra></extra>",
            }
        )

        layout = _json.dumps(
            {
                "title": title,
                "paper_bgcolor": "#1e1e2e",
                "plot_bgcolor": "#1e1e2e",
                "font": {"color": "#e8eaf6"},
                "geo": {
                    "showframe": False,
                    "showcoastlines": True,
                    "projection": {"type": "natural earth"},
                    "bgcolor": "#263238",
                    "landcolor": "#37474f",
                    "coastlinecolor": "#546e7a",
                    "countrycolor": "#455a64",
                },
            }
        )

        html = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>GNAT — {title}</title>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<style>
body {{ margin:0; background:#1e1e2e; }}
#chart {{ width:100vw; height:100vh; }}
</style>
</head><body>
<div id="chart"></div>
<script>
Plotly.newPlot("chart", [{chart_data}], {layout}, {{responsive:true}});
</script>
</body></html>"""

        with open(output, "w", encoding="utf-8") as fh:
            fh.write(html)
        logger.info("GeoView.render_threat_heatmap: written %s (%d countries)", output, len(counts))
        return output

    def country_counts(
        self,
        stix_types: list[str] | None = None,
    ) -> dict[str, int]:
        """
        Return object counts per ISO-3 country code.

        Parameters
        ----------
        stix_types : list[str], optional
            Filter to these STIX types.

        Returns
        -------
        dict[str, int]
            ``{"USA": 42, "CHN": 15, ...}``
        """
        return self._count_by_country(stix_types)

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _count_by_country(
        self,
        stix_types: list[str] | None,
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        _fallback_fields = ("x_country", "x_gnat_country", "x_geo_country")
        for obj in self._objects:
            if stix_types and getattr(obj, "type", "") not in stix_types:
                continue
            raw = self._get_country(obj, _fallback_fields)
            if not raw:
                continue
            iso3 = _normalise_country(raw)
            counts[iso3] = counts.get(iso3, 0) + 1
        return counts

    def _get_country(self, obj: Any, fallback_fields: tuple[str, ...]) -> str:
        """Extract raw country string from a STIX object."""
        # Primary field
        val = getattr(obj, self._country_field, None)
        if val:
            return str(val)
        # Fallback fields
        for f in fallback_fields:
            val = getattr(obj, f, None)
            if val:
                return str(val)
        # Check _properties dict
        props = getattr(obj, "_properties", {}) or {}
        for key in (self._country_field, *fallback_fields):
            if key in props and props[key]:
                return str(props[key])
        return ""
