"""
gnat.tui.widgets.stix_table
==============================
Reusable DataTable widget for displaying STIX objects.

Columns shown by default: type, name/ID, created, confidence, source platform.
"""

from typing import Any, Dict, List

from textual.widgets import DataTable


class STIXTable(DataTable):
    """
    DataTable pre-configured for displaying STIX object dicts.

    Parameters
    ----------
    show_columns : list of str, optional
        Subset of column keys to show.  Defaults to the standard five.
    """

    DEFAULT_COLUMNS = [
        ("type",    "Type",     12),
        ("name",    "Name / Value", 35),
        ("created", "Created",  20),
        ("conf",    "Conf",      6),
        ("source",  "Source",   16),
    ]

    def __init__(self, show_columns: List[str] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._show = set(show_columns) if show_columns else {c[0] for c in self.DEFAULT_COLUMNS}
        self.cursor_type = "row"
        self.zebra_stripes = True

    def on_mount(self) -> None:
        """Add column headers on mount."""
        for key, label, width in self.DEFAULT_COLUMNS:
            if key in self._show:
                self.add_column(label, key=key, width=width)

    def load_stix(self, objects: List[Dict[str, Any]]) -> None:
        """
        Clear the table and populate it with a list of STIX dicts.

        Parameters
        ----------
        objects : list of dict
            STIX dicts as returned by ``NLPQueryEngine.query()`` or
            ``ResearchLibrary`` methods.
        """
        self.clear()
        for obj in objects:
            row = []
            for key, _label, _width in self.DEFAULT_COLUMNS:
                if key not in self._show:
                    continue
                if key == "type":
                    row.append(obj.get("type", ""))
                elif key == "name":
                    row.append(
                        obj.get("name")
                        or obj.get("value")
                        or obj.get("indicator_value")
                        or obj.get("id", "")[:40]
                    )
                elif key == "created":
                    row.append(str(obj.get("created", obj.get("first_observed", "")))[:19])
                elif key == "conf":
                    conf = obj.get("confidence", obj.get("mscore", ""))
                    row.append(str(conf) if conf != "" else "—")
                elif key == "source":
                    row.append(obj.get("x_source_platform", obj.get("_source", "")))
            self.add_row(*row)
