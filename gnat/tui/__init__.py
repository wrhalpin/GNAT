"""
gnat.tui
=========
Interactive terminal UI for GNAT, built with Textual.

Launch::

    gnat tui               # full app (query screen first)
    gnat tui query         # open directly on the query screen

Requires the ``[tui]`` extras group::

    pip install "gnat[tui]"
"""

from gnat.tui.app import GNATApp

__all__ = ["GNATApp"]
