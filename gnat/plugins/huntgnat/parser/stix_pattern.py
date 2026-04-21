# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.parser.stix_pattern
=============================================

Recursive-descent parser for STIX 2.1 Indicator pattern expressions
(spec §9). Produces a typed AST suitable for rule translation.

Why not ``stix2-patterns``?
---------------------------
The OASIS ``stix2-patterns`` library exposes a *validator* (``run()``)
but not a walkable AST. Its internal ANTLR parse tree is undocumented
and version-coupled. This parser covers the subset of the grammar that
HuntGNAT needs for detection-rule translation and produces a stable,
typed AST that the translator hierarchy can walk without fragile
casts.

Supported constructs (Phase 1)
------------------------------
* Simple comparisons: ``[type:path op value]``
* Property paths with dot notation and dictionary keys
* Operators: ``=  !=  <  >  <=  >=  IN  LIKE  MATCHES``
* Compound expressions: ``AND``, ``OR`` within an observation
* Multiple observations: ``[A] AND [B]``, ``[A] OR [B]``
* Parenthesized sub-expressions within an observation

Deferred to Phase 2
--------------------
* ``ISSUBSET``, ``ISSUPERSET``
* ``FOLLOWEDBY`` observation operator
* Temporal qualifiers: ``WITHIN``, ``REPEATS``, ``START``, ``STOP``
* ``NOT`` operator (target-language support varies)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class STIXPatternParseError(Exception):
    """Raised when a STIX pattern cannot be parsed."""


# ---------------------------------------------------------------------------
# AST node types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ObjectPath:
    """``object-type:property.path`` — e.g. ``file:hashes.'SHA-256'``."""

    object_type: str
    property_path: list[str]

    def __str__(self) -> str:
        return f"{self.object_type}:{'.'.join(self.property_path)}"


@dataclass(frozen=True)
class Comparison:
    """A single ``object-path operator value`` triple."""

    object_path: ObjectPath
    operator: str
    value: Any

    def __str__(self) -> str:
        v = f"'{self.value}'" if isinstance(self.value, str) else str(self.value)
        return f"{self.object_path} {self.operator} {v}"


@dataclass
class ComparisonExpr:
    """
    A boolean tree of :class:`Comparison` nodes joined by AND/OR.

    Leaf nodes have ``operands = [Comparison]`` and ``operator = None``.
    Branch nodes have ``operands = [ComparisonExpr, ...]`` and
    ``operator = 'AND'`` or ``'OR'``.
    """

    operands: list[Comparison | ComparisonExpr]
    operator: str | None = None

    @property
    def is_leaf(self) -> bool:
        return self.operator is None and len(self.operands) == 1

    @property
    def comparison(self) -> Comparison:
        if not self.is_leaf:
            raise TypeError("not a leaf ComparisonExpr")
        return self.operands[0]  # type: ignore[return-value]

    def iter_comparisons(self) -> list[Comparison]:
        """Flatten into a list of all leaf Comparison nodes."""
        out: list[Comparison] = []
        for op in self.operands:
            if isinstance(op, Comparison):
                out.append(op)
            elif isinstance(op, ComparisonExpr):
                out.extend(op.iter_comparisons())
        return out


@dataclass(frozen=True)
class Observation:
    """A single ``[comparison_expr]`` bracket group."""

    expression: ComparisonExpr


@dataclass
class CompoundObservation:
    """
    Multiple observations joined by AND/OR.

    Single-observation patterns produce ``observations = [Observation]``
    with ``operator = None``.
    """

    observations: list[Observation]
    operator: str | None = None


# Public alias for the top-level parse result
PatternAST = CompoundObservation


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(
    r"""
    (?P<LBRACKET>   \[                              )  |
    (?P<RBRACKET>   \]                              )  |
    (?P<LPAREN>     \(                              )  |
    (?P<RPAREN>     \)                              )  |
    (?P<OP>         !=|<=|>=|<|>|=                  )  |
    (?P<COMMA>      ,                               )  |
    (?P<COLON>      :                               )  |
    (?P<DOT>        \.                              )  |
    (?P<SQUOTE_STR> '[^']*'                         )  |
    (?P<KEYWORD>    AND|OR|NOT|IN|LIKE|MATCHES|
                    ISSUBSET|ISSUPERSET|FOLLOWEDBY|
                    WITHIN|REPEATS|START|STOP|
                    true|false                      )  |
    (?P<INT>        -?\d+                           )  |
    (?P<FLOAT>      -?\d+\.\d+                      )  |
    (?P<IDENT>      [A-Za-z_][A-Za-z0-9_-]*         )  |
    (?P<LSQUARE>    \[                              )  |
    (?P<RSQUARE>    \]                              )  |
    (?P<STAR>       \*                              )  |
    (?P<WS>         \s+                             )
    """,
    re.VERBOSE,
)

_KW_OPS = frozenset({"IN", "LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET"})
_UNSUPPORTED_KW = frozenset({"FOLLOWEDBY", "WITHIN", "REPEATS", "START", "STOP", "NOT"})


@dataclass
class _Token:
    kind: str
    value: str
    pos: int


def _tokenize(pattern: str) -> list[_Token]:
    tokens: list[_Token] = []
    pos = 0
    while pos < len(pattern):
        m = _TOKEN_RE.match(pattern, pos)
        if not m:
            raise STIXPatternParseError(f"unexpected character at position {pos}: {pattern[pos]!r}")
        kind = m.lastgroup
        value = m.group()
        if kind == "WS":
            pos = m.end()
            continue
        if kind == "SQUOTE_STR":
            value = value[1:-1]
            kind = "STRING"
        elif kind == "KEYWORD":
            if value in ("true", "false"):
                kind = "BOOL"
            elif value in _KW_OPS:
                kind = "OP"
            elif value in _UNSUPPORTED_KW:
                raise STIXPatternParseError(
                    f"unsupported qualifier/operator {value!r} at position {pos} "
                    f"(Phase 2 — not yet implemented)"
                )
            else:
                kind = "KEYWORD"
        elif kind == "FLOAT":
            value = float(value)
            kind = "NUMBER"
        elif kind == "INT":
            value = int(value)
            kind = "NUMBER"
        tokens.append(_Token(kind=kind, value=value, pos=m.start()))
        pos = m.end()
    return tokens


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class _Parser:
    """Recursive descent parser for STIX pattern expressions."""

    def __init__(self, tokens: list[_Token], raw: str) -> None:
        self._tokens = tokens
        self._raw = raw
        self._pos = 0

    # -- helpers --

    def _peek(self) -> _Token | None:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def _advance(self) -> _Token:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def _expect(self, kind: str, value: str | None = None) -> _Token:
        tok = self._peek()
        if tok is None:
            raise STIXPatternParseError(
                f"unexpected end of pattern; expected {kind}" + (f" {value!r}" if value else "")
            )
        if tok.kind != kind or (value is not None and tok.value != value):
            raise STIXPatternParseError(
                f"expected {kind}"
                + (f" {value!r}" if value else "")
                + f" at position {tok.pos}, got {tok.kind} {tok.value!r}"
            )
        return self._advance()

    def _at(self, kind: str, value: str | None = None) -> bool:
        tok = self._peek()
        if tok is None:
            return False
        if tok.kind != kind:
            return False
        return value is None or tok.value == value

    # -- grammar rules --

    def parse(self) -> CompoundObservation:
        """Top-level: one or more ``[comparison_expr]`` joined by AND/OR."""
        first = self._observation()
        observations = [first]
        op: str | None = None
        while self._at("KEYWORD", "AND") or self._at("KEYWORD", "OR"):
            kw = self._advance()
            if op is not None and kw.value != op:
                raise STIXPatternParseError("mixed AND/OR at observation level without parentheses")
            op = kw.value
            observations.append(self._observation())
        if self._peek() is not None:
            tok = self._peek()
            raise STIXPatternParseError(
                f"unexpected token {tok.kind} {tok.value!r} at position {tok.pos}"
            )
        return CompoundObservation(observations=observations, operator=op)

    def _observation(self) -> Observation:
        """``[comparison_expr]``."""
        self._expect("LBRACKET")
        expr = self._comparison_expr()
        self._expect("RBRACKET")
        return Observation(expression=expr)

    def _comparison_expr(self) -> ComparisonExpr:
        """comparison (('AND'|'OR') comparison)*"""
        first = self._comparison_or_paren()
        operands: list[Comparison | ComparisonExpr] = [first]
        op: str | None = None
        while self._at("KEYWORD", "AND") or self._at("KEYWORD", "OR"):
            kw = self._advance()
            if op is not None and kw.value != op:
                raise STIXPatternParseError(
                    "mixed AND/OR within a single observation bracket — "
                    "use parentheses to disambiguate"
                )
            op = kw.value
            operands.append(self._comparison_or_paren())
        if len(operands) == 1:
            return ComparisonExpr(operands=operands)
        return ComparisonExpr(operands=operands, operator=op)

    def _comparison_or_paren(self) -> Comparison | ComparisonExpr:
        """comparison | '(' comparison_expr ')'"""
        if self._at("LPAREN"):
            self._advance()
            expr = self._comparison_expr()
            self._expect("RPAREN")
            return expr
        return self._comparison()

    def _comparison(self) -> Comparison:
        """object_path operator value"""
        obj_path = self._object_path()
        op_tok = self._expect("OP")
        val = self._value(op_tok.value)
        return Comparison(object_path=obj_path, operator=op_tok.value, value=val)

    def _object_path(self) -> ObjectPath:
        """object_type ':' property_path"""
        parts: list[str] = [self._expect("IDENT").value]
        while self._at("IDENT") and self._tokens[self._pos - 1].kind == "IDENT":
            break
        # Handle hyphenated type names (e.g., domain-name, ipv4-addr)
        # Hyphens are part of the IDENT token already via [A-Za-z0-9_-]
        self._expect("COLON")
        prop_path = self._property_path()
        return ObjectPath(object_type=parts[0], property_path=prop_path)

    def _property_path(self) -> list[str]:
        """step ('.' step)*"""
        steps = [self._path_step()]
        while self._at("DOT"):
            self._advance()
            steps.append(self._path_step())
        return steps

    def _path_step(self) -> str:
        """identifier | '\\'key\\'' | identifier '[' index ']'"""
        if self._at("STRING"):
            return self._advance().value
        tok = self._expect("IDENT")
        step = tok.value
        # Array index: property[*] or property[0]
        if self._at("LBRACKET") or self._at("LSQUARE"):
            self._advance()
            if self._at("STAR"):
                self._advance()
                step += "[*]"
            elif self._at("NUMBER"):
                idx = self._advance()
                step += f"[{idx.value}]"
            self._expect("RBRACKET")
        return step

    def _value(self, operator: str) -> Any:
        """Parse the RHS value based on operator context."""
        if operator == "IN":
            return self._value_list()
        tok = self._peek()
        if tok is None:
            raise STIXPatternParseError("unexpected end of pattern; expected value")
        if tok.kind == "STRING":
            return self._advance().value
        if tok.kind == "NUMBER":
            return self._advance().value
        if tok.kind == "BOOL":
            self._advance()
            return tok.value == "true"
        raise STIXPatternParseError(
            f"expected value at position {tok.pos}, got {tok.kind} {tok.value!r}"
        )

    def _value_list(self) -> list[Any]:
        """'(' value (',' value)* ')'"""
        self._expect("LPAREN")
        values = [self._value("=")]
        while self._at("COMMA"):
            self._advance()
            values.append(self._value("="))
        self._expect("RPAREN")
        return values


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_pattern(pattern: str) -> PatternAST:
    """
    Parse a STIX 2.1 Indicator pattern into a typed AST.

    Parameters
    ----------
    pattern : str
        A STIX pattern expression, e.g.
        ``"[file:hashes.'SHA-256' = 'abc123']"``.

    Returns
    -------
    PatternAST
        A :class:`CompoundObservation` tree that translators can walk.

    Raises
    ------
    STIXPatternParseError
        If the pattern is syntactically invalid or uses unsupported
        constructs (Phase 2 qualifiers, ``FOLLOWEDBY``, ``NOT``).
    """
    if not pattern or not pattern.strip():
        raise STIXPatternParseError("empty pattern")
    tokens = _tokenize(pattern.strip())
    if not tokens:
        raise STIXPatternParseError("pattern produced no tokens")
    parser = _Parser(tokens, pattern)
    return parser.parse()
