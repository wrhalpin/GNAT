"""
gnat.nlp
==========
Natural-language query layer for GNAT.

Translates free-text queries like
``"Get all IPs related to Lazarus Group since January"``
into structured :class:`QuerySpec` objects, which are then dispatched to
one or more connectors via :meth:`~gnat.client.GNATClient.natural_language_query`.

Two backends are provided:

- :class:`~gnat.nlp.builtin.BuiltinParser` — regex + keyword rules, no
  external dependencies.
- :class:`~gnat.nlp.claude_backend.ClaudeParser` — structured extraction
  via the Claude API; requires ``[claude]`` in ``config.ini``.

Configure via ``[nlp]`` in ``config.ini``::

    [nlp]
    backend = builtin          # builtin | claude
    model   = claude-sonnet-4-6
"""

from gnat.nlp.query_spec import QuerySpec
from gnat.nlp.parser import NLPQueryEngine

__all__ = ["QuerySpec", "NLPQueryEngine"]
