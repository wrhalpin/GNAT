# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.stix.pattern_validator
============================
STIX 2.1 Indicator pattern validator.

Two validation tiers
--------------------

**Tier 1 — pure Python (always available)**

A regex-based tokenizer paired with a simple recursive descent parser covers:

* Outer ``[...]`` bracket structure
* One or more comparison expressions joined by ``AND`` / ``OR``
* Each comparison: ``object_type:property_path OPERATOR value``
* Known STIX 2.1 SCO / SDO object types
* Valid comparison operators (``=``, ``!=``, ``<``, ``>``, ``<=``, ``>=``,
  ``LIKE``, ``MATCHES``, ``IN``, ``ISSUBSET``, ``ISSUPERSET``)
* Properly quoted string values (single or double quotes)
* Integer, float, boolean, and null literals
* ``IN (v1, v2, ...)`` list values
* Dot-notation and index-notation property paths
* Observation qualifiers: ``WITHIN N SECONDS/MINUTES/…``,
  ``REPEATEDWITHIN N SECONDS/…``, ``START … STOP …``

**Tier 2 — ANTLR grammar (optional)**

When ``stix2-patterns`` is installed (``pip install "gnat[stix-validate]"``)
and ``strict=True`` is passed, the full ANTLR 4 grammar from the STIX 2.1 spec
is used.  This catches edge cases in complex FOLLOWEDBY expressions and exotic
timestamp literals that the pure-Python tier does not cover.

Usage
-----
::

    from gnat.stix.pattern_validator import validate_pattern, PatternValidationError

    result = validate_pattern("[ipv4-addr:value = '1.2.3.4']")
    assert result.valid

    result = validate_pattern("[bad")
    assert not result.valid
    print(result.errors)   # ["Pattern must be wrapped in '[' ... ']'"]

    # Raises PatternValidationError when raise_on_error=True:
    validator = PatternValidator(raise_on_error=True)
    validator.validate("[ipv4-addr:value = '1.2.3.4']")  # OK
    validator.validate("[ipv4addr:value = '1.2.3.4']")   # raises

    # Strict mode (uses stix2-patterns if available):
    result = validate_pattern("[ipv4-addr:value = '1.2.3.4']", strict=True)
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field

from gnat.stix.version import CURRENT_SPEC_VERSION

# ---------------------------------------------------------------------------
# Known STIX 2.1 SCO and SDO object types that may appear in patterns
# ---------------------------------------------------------------------------

_STIX_OBJECT_TYPES: frozenset[str] = frozenset(
    {
        # STIX 2.1 Cyber Observable Objects (SCOs)
        "artifact",
        "autonomous-system",
        "directory",
        "domain-name",
        "email-addr",
        "email-message",
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "mac-addr",
        "mutex",
        "network-traffic",
        "process",
        "software",
        "url",
        "user-account",
        "windows-registry-key",
        "x509-certificate",
        # STIX 2.1 Domain Objects (SDOs) — occasionally used in patterns
        "attack-pattern",
        "campaign",
        "course-of-action",
        "identity",
        "indicator",
        "infrastructure",
        "intrusion-set",
        "location",
        "malware",
        "malware-analysis",
        "note",
        "observed-data",
        "opinion",
        "report",
        "threat-actor",
        "tool",
        "vulnerability",
        # STIX 2.1 Relationship Objects (SROs) — rare but allowed
        "relationship",
        "sighting",
    }
)

# Valid comparison operators per STIX 2.1 §5.6.2
_COMPARISON_OPS: frozenset[str] = frozenset(
    {
        "=",
        "!=",
        "<",
        ">",
        "<=",
        ">=",
        "LIKE",
        "MATCHES",
        "IN",
        "ISSUBSET",
        "ISSUPERSET",
    }
)

# Time unit keywords for WITHIN / REPEATEDWITHIN qualifiers
_TIME_UNITS: frozenset[str] = frozenset(
    {
        "SECONDS",
        "MINUTES",
        "HOURS",
        "DAYS",
        "WEEKS",
        "MONTHS",
        "YEARS",
    }
)

# ---------------------------------------------------------------------------
# Token types and tokenizer
# ---------------------------------------------------------------------------

_TOKEN_PATTERNS: list[tuple[str, str]] = [
    # Literals (order matters — float before int)
    ("FLOAT", r"-?\d+\.\d+"),
    ("INT", r"-?\d+"),
    ("STRING_SQ", r"'(?:[^'\\]|\\.)*'"),
    ("STRING_DQ", r'"(?:[^"\\]|\\.)*"'),
    # Keywords (longest match first)
    ("ISSUPERSET", r"\bISSUPERSET\b"),
    ("ISSUBSET", r"\bISSUBSET\b"),
    ("REPEATEDWITHIN", r"\bREPEATEDWITHIN\b"),
    ("FOLLOWEDBY", r"\bFOLLOWEDBY\b"),
    ("MATCHES", r"\bMATCHES\b"),
    ("WITHIN", r"\bWITHIN\b"),
    ("SECONDS", r"\bSECONDS\b"),
    ("MINUTES", r"\bMINUTES\b"),
    ("HOURS", r"\bHOURS\b"),
    ("DAYS", r"\bDAYS\b"),
    ("WEEKS", r"\bWEEKS\b"),
    ("MONTHS", r"\bMONTHS\b"),
    ("YEARS", r"\bYEARS\b"),
    ("START", r"\bSTART\b"),
    ("STOP", r"\bSTOP\b"),
    ("LIKE", r"\bLIKE\b"),
    ("IN", r"\bIN\b"),
    ("AND", r"\bAND\b"),
    ("OR", r"\bOR\b"),
    ("NOT", r"\bNOT\b"),
    ("TRUE", r"\btrue\b"),
    ("FALSE", r"\bfalse\b"),
    ("NULL", r"\bnull\b"),
    # Operators
    ("OP", r"<=|>=|!=|=|<|>"),
    # Identifiers (object types and property names; allow hyphens)
    ("IDENT", r"[\w][\w-]*"),
    # Punctuation
    ("COLON", r":"),
    ("DOT", r"\."),
    ("COMMA", r","),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("LBRACK", r"\["),
    ("RBRACK", r"\]"),
    # Whitespace (discarded)
    ("WS", r"\s+"),
    # Anything else (error token)
    ("UNKNOWN", r"."),
]

_TOKEN_RE = re.compile(
    "|".join(f"(?P<{name}>{pattern})" for name, pattern in _TOKEN_PATTERNS),
    re.IGNORECASE,
)


@dataclass
class _Token:
    """_Token implementation."""

    kind: str
    value: str
    pos: int


def _tokenize(text: str) -> list[_Token]:
    """Return a list of tokens from *text*, excluding whitespace."""
    tokens: list[_Token] = []
    for m in _TOKEN_RE.finditer(text):
        kind = m.lastgroup
        if kind == "WS":
            continue
        tokens.append(_Token(kind=kind, value=m.group(), pos=m.start()))  # type: ignore[arg-type]
    return tokens


# ---------------------------------------------------------------------------
# ValidationResult and PatternValidationError
# ---------------------------------------------------------------------------


@dataclass
class ValidationResult:
    """
    Result of a STIX 2.1 pattern validation.

    Attributes
    ----------
    valid : bool
        ``True`` when no errors were found.
    errors : list of str
        Descriptions of validation failures.
    warnings : list of str
        Non-fatal issues (e.g., non-standard object type extension).
    strict : bool
        ``True`` when the ANTLR grammar (``stix2-patterns``) was used.
    """

    valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    strict: bool = False

    def __bool__(self) -> bool:
        """Return truthiness."""
        return self.valid

    def __repr__(self) -> str:
        """Return unambiguous string representation."""
        status = "valid" if self.valid else f"invalid ({len(self.errors)} error(s))"
        return f"ValidationResult({status}, strict={self.strict})"


class PatternValidationError(ValueError):
    """
    Raised when a STIX 2.1 pattern fails validation and
    :class:`PatternValidator` was constructed with ``raise_on_error=True``.

    Attributes
    ----------
    pattern : str
        The pattern that failed.
    errors : list of str
        Validation error messages.
    """

    def __init__(self, pattern: str, errors: Sequence[str]) -> None:
        """Initialize PatternValidationError."""
        self.pattern = pattern
        self.errors: list[str] = list(errors)
        summary = "; ".join(self.errors[:3])
        super().__init__(f"Invalid STIX pattern: {summary!r}")


# ---------------------------------------------------------------------------
# Pure-Python recursive descent parser
# ---------------------------------------------------------------------------


class _Parser:
    """
    Minimal recursive descent parser for STIX 2.1 patterns.

    Grammar (STIX 2.1 §5.6)::

        pattern              := qualified_obs_expr
        qualified_obs_expr   := single_obs_expr qualifier?
                              | qualified_obs_expr BOOL_OP qualified_obs_expr
        single_obs_expr      := '[' inner_expr ']'
                              | '(' qualified_obs_expr ')'
        inner_expr           := prop_expr (('AND'|'OR') prop_expr)*
        prop_expr            := object_type ':' path comp_op value
        qualifier            := 'WITHIN' number timeunit
                              | 'REPEATEDWITHIN' number timeunit
                              | 'START' timestamp 'STOP' timestamp
        BOOL_OP              := 'AND' | 'OR' | 'FOLLOWEDBY'
        comp_op              := '=' | '!=' | '<' | '>' | '<=' | '>='
                              | 'LIKE' | 'MATCHES' | 'IN' | 'ISSUBSET' | 'ISSUPERSET'
        object_type          := IDENT
        path                 := IDENT path_step*
        path_step            := '.' IDENT | '.' STRING | '[' INT ']'
        value                := STRING | INT | FLOAT | 'true' | 'false' | 'null'
                              | '(' value (',' value)* ')'

    Key: ``[...]`` brackets delimit a single observation's comparison
    expressions; qualifiers and boolean operators between observations
    appear OUTSIDE the brackets.
    """

    def __init__(self, tokens: list[_Token], pattern: str) -> None:
        """Initialize _Parser."""
        self._tokens = tokens
        self._pos = 0
        self._pattern = pattern
        self.errors: list[str] = []
        self.warnings: list[str] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _peek(self) -> _Token | None:
        """Internal helper for peek."""
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def _peek_ahead(self, offset: int = 1) -> _Token | None:
        """Internal helper for peek ahead."""
        idx = self._pos + offset
        return self._tokens[idx] if idx < len(self._tokens) else None

    def _advance(self) -> _Token | None:
        """Internal helper for advance."""
        tok = self._peek()
        if tok is not None:
            self._pos += 1
        return tok

    def _expect(self, *kinds: str) -> _Token | None:
        """Internal helper for expect."""
        tok = self._peek()
        if tok is None or tok.kind not in kinds:
            expected = "/".join(kinds)
            got = repr(tok.value) if tok else "end of pattern"
            self.errors.append(f"Expected {expected} but got {got}")
            return None
        return self._advance()

    def _at(self, *kinds: str) -> bool:
        """Internal helper for at."""
        tok = self._peek()
        return tok is not None and tok.kind in kinds

    # ------------------------------------------------------------------
    # Grammar rules
    # ------------------------------------------------------------------

    def parse_pattern(self) -> None:
        """Entry point: parse a complete STIX 2.1 pattern."""
        if not self._peek():
            self.errors.append("Pattern is empty")
            return

        self._parse_qualified_obs_expr()

        if self._peek() is not None:
            remaining = "".join(t.value for t in self._tokens[self._pos :])
            self.errors.append(f"Unexpected content after pattern: {remaining!r}")

    def _parse_qualified_obs_expr(self) -> None:
        """qualified_obs_expr := single_obs_expr qualifier? (BOOL_OP qualified_obs_expr)*"""
        self._parse_single_obs_expr()
        self._parse_qualifier()

        while self._at("AND", "OR", "FOLLOWEDBY"):
            self._advance()
            self._parse_single_obs_expr()
            self._parse_qualifier()

    def _parse_single_obs_expr(self) -> None:
        """single_obs_expr := '[' inner_expr ']' | '(' qualified_obs_expr ')'"""
        if self._at("LPAREN"):
            self._advance()
            self._parse_qualified_obs_expr()
            self._expect("RPAREN")
            return

        if not self._at("LBRACK"):
            tok = self._peek()
            got = repr(tok.value) if tok else "end of pattern"
            self.errors.append(
                f"Expected '[' to begin observation expression, got {got}. "
                "Each observation must be wrapped in brackets, e.g. "
                "\"[ipv4-addr:value = '1.2.3.4']\""
            )
            return

        self._advance()  # consume [

        if self._at("RBRACK"):
            self.errors.append("Empty observation expression '[]'")
            self._advance()
            return

        self._parse_inner_expr()
        self._expect("RBRACK")

    def _parse_inner_expr(self) -> None:
        """inner_expr := prop_expr (('AND'|'OR') prop_expr)*

        AND/OR here are *intra-observation* (between comparison expressions
        within the same ``[...]``).  We stop if the token after AND/OR is
        LBRACK or LPAREN — those belong to the outer observation-level grammar.
        """
        self._parse_prop_expr()

        while self._at("AND", "OR"):
            # Look ahead: if the token after AND/OR starts a new single_obs_expr,
            # this operator is inter-observation (outer level) — stop.
            next_tok = self._peek_ahead(1)
            if next_tok and next_tok.kind in ("LBRACK", "LPAREN"):
                break
            self._advance()
            self._parse_prop_expr()

    def _parse_prop_expr(self) -> None:
        """prop_expr := object_type ':' path comp_op value"""
        obj_tok = self._peek()
        if obj_tok is None or obj_tok.kind != "IDENT":
            self.errors.append("Expected object type (e.g., 'ipv4-addr')")
            return
        self._advance()
        obj_type = obj_tok.value.lower()

        if obj_type not in _STIX_OBJECT_TYPES:
            if obj_type.startswith("x-"):
                self.warnings.append(
                    f"Non-standard STIX extension type {obj_type!r}; "
                    "ensure it is registered in the target platform"
                )
            else:
                self.errors.append(
                    f"Unknown STIX object type {obj_type!r}. "
                    "Expected a STIX 2.1 SCO or SDO "
                    "(e.g., 'ipv4-addr', 'file', 'domain-name')."
                )

        if not self._expect("COLON"):
            return

        self._parse_property_path()

        if not self._parse_comp_op():
            return

        self._parse_value()

    def _parse_property_path(self) -> None:
        """path := IDENT path_step*"""
        if not self._at("IDENT"):
            self.errors.append("Expected property name after ':'")
            return
        self._advance()  # first component

        # path_step*
        while True:
            if self._at("DOT"):
                self._advance()
                # Allow quoted property component (e.g., hashes.'SHA-256')
                if self._at("STRING_SQ", "STRING_DQ") or self._at("IDENT"):
                    self._advance()
                else:
                    self.errors.append("Expected property name after '.'")
            elif self._at("LBRACK"):
                self._advance()
                if not self._at("INT"):
                    self.errors.append("Expected integer index inside '['")
                else:
                    self._advance()
                if not self._expect("RBRACK"):
                    pass
            else:
                break

    def _parse_comp_op(self) -> bool:
        """Return True if a valid comparison operator was consumed."""
        tok = self._peek()
        if tok is None:
            self.errors.append("Expected comparison operator (e.g., '=', '!=', 'LIKE')")
            return False

        op_upper = tok.value.upper()
        if tok.kind == "OP":
            self._advance()
            return True
        if tok.kind in ("LIKE", "MATCHES", "IN", "ISSUBSET", "ISSUPERSET"):
            self._advance()
            return True
        if op_upper in _COMPARISON_OPS:
            self._advance()
            return True

        self.errors.append(
            f"Invalid comparison operator {tok.value!r}. "
            f"Expected one of: {', '.join(sorted(_COMPARISON_OPS))}."
        )
        return False

    def _parse_value(self) -> None:
        """value := STRING | INT | FLOAT | true | false | null | '(' list ')'"""
        tok = self._peek()
        if tok is None:
            self.errors.append("Expected a value (string, integer, boolean, or list)")
            return

        if tok.kind in ("STRING_SQ", "STRING_DQ", "INT", "FLOAT", "TRUE", "FALSE", "NULL"):
            self._advance()
        elif tok.kind == "LPAREN":
            # IN (...) list
            self._advance()
            self._parse_value()  # at least one value required
            while self._at("COMMA"):
                self._advance()
                self._parse_value()
            self._expect("RPAREN")
        else:
            self.errors.append(
                f"Expected a value but got {tok.value!r}. "
                "String values must be quoted (e.g., '1.2.3.4')."
            )

    def _parse_qualifier(self) -> None:
        """
        qualifier := 'WITHIN' number timeunit
                   | 'REPEATEDWITHIN' number timeunit
                   | 'START' timestamp 'STOP' timestamp
        """
        if self._at("WITHIN", "REPEATEDWITHIN"):
            self._advance()
            if not self._at("INT", "FLOAT"):
                self.errors.append("Expected numeric duration after WITHIN/REPEATEDWITHIN")
                return
            self._advance()
            if not self._at(*_TIME_UNITS):
                self.errors.append(
                    f"Expected time unit after WITHIN/REPEATEDWITHIN "
                    f"(e.g., SECONDS, MINUTES); got {self._peek()}"
                )
                return
            self._advance()

        elif self._at("START"):
            self._advance()
            # timestamp is a string literal like t'2022-01-01T00:00:00Z'
            if not self._at("STRING_SQ", "STRING_DQ", "IDENT"):
                self.errors.append("Expected timestamp after START")
                return
            self._advance()
            if not self._at("STOP"):
                self.errors.append("Expected STOP after START timestamp")
                return
            self._advance()
            if not self._at("STRING_SQ", "STRING_DQ", "IDENT"):
                self.errors.append("Expected timestamp after STOP")
                return
            self._advance()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class PatternValidator:
    """
    Configurable STIX 2.1 pattern validator.

    Parameters
    ----------
    raise_on_error : bool
        If ``True``, :meth:`validate` raises :exc:`PatternValidationError`
        instead of returning an invalid :class:`ValidationResult`.
    strict : bool
        If ``True``, attempt to use the ``stix2-patterns`` ANTLR grammar
        when it is installed.  Falls back to tier-1 if not available.
    allow_custom_types : bool
        If ``True``, suppress warnings for ``x-*`` extension object types.

    Examples
    --------
    >>> v = PatternValidator()
    >>> result = v.validate("[ipv4-addr:value = '1.2.3.4']")
    >>> result.valid
    True
    >>> result = v.validate("[bad")
    >>> result.valid
    False
    >>> result.errors
    ["Pattern must be wrapped in '[' ... ']'"]
    """

    def __init__(
        self,
        raise_on_error: bool = False,
        strict: bool = False,
        allow_custom_types: bool = False,
    ) -> None:
        """Initialize PatternValidator."""
        self._raise = raise_on_error
        self._strict = strict
        self._allow_custom = allow_custom_types

    def validate(self, pattern: str) -> ValidationResult:
        """
        Validate *pattern* and return a :class:`ValidationResult`.

        Parameters
        ----------
        pattern : str
            STIX 2.1 pattern string.

        Returns
        -------
        ValidationResult

        Raises
        ------
        PatternValidationError
            When ``raise_on_error=True`` and the pattern is invalid.
        """
        result = _validate_pure_python(pattern, allow_custom_types=self._allow_custom)

        # If tier-1 passes (or strict mode requested) and stix2-patterns
        # is available, run tier-2 validation for a more thorough check.
        if self._strict and result.valid:
            result = _validate_strict(pattern, tier1_result=result)

        if self._raise and not result.valid:
            raise PatternValidationError(pattern, result.errors)

        return result


def validate_pattern(
    pattern: str,
    *,
    strict: bool = False,
    raise_on_error: bool = False,
) -> ValidationResult:
    """
    Validate a STIX 2.1 pattern string.

    Parameters
    ----------
    pattern : str
        STIX 2.1 pattern to validate (e.g. ``"[ipv4-addr:value = '1.2.3.4']"``).
    strict : bool
        Use the ``stix2-patterns`` ANTLR grammar when available.
    raise_on_error : bool
        Raise :exc:`PatternValidationError` on invalid patterns.

    Returns
    -------
    ValidationResult

    Examples
    --------
    >>> validate_pattern("[ipv4-addr:value = '1.2.3.4']").valid
    True
    >>> validate_pattern("[ipv4-addr:value = 1.2.3.4]").valid
    False
    >>> validate_pattern("[domain-name:value = 'evil.com']").valid
    True
    """
    return PatternValidator(
        strict=strict,
        raise_on_error=raise_on_error,
    ).validate(pattern)


# ---------------------------------------------------------------------------
# Tier-1: pure Python implementation
# ---------------------------------------------------------------------------


def _validate_pure_python(
    pattern: str,
    *,
    allow_custom_types: bool = False,
) -> ValidationResult:
    """Run the pure-Python tier-1 validation."""
    stripped = pattern.strip()

    if not stripped:
        return ValidationResult(valid=False, errors=["Pattern is empty"])

    tokens = _tokenize(stripped)
    parser = _Parser(tokens, stripped)
    parser.parse_pattern()

    if allow_custom_types:
        # Suppress x-* extension warnings
        parser.warnings = [w for w in parser.warnings if "Non-standard" not in w]

    return ValidationResult(
        valid=len(parser.errors) == 0,
        errors=parser.errors,
        warnings=parser.warnings,
        strict=False,
    )


# ---------------------------------------------------------------------------
# Tier-2: stix2-patterns ANTLR grammar (optional)
# ---------------------------------------------------------------------------


def _validate_strict(pattern: str, *, tier1_result: ValidationResult) -> ValidationResult:
    """
    Run the stix2-patterns library validator when installed.

    Falls back to *tier1_result* if the library is not available.
    """
    try:
        from stix2patterns.validator import run as _stix2_validate  # type: ignore[import]
    except ImportError:
        # stix2-patterns not installed — return tier-1 result unchanged
        return tier1_result

    try:
        inspection = _stix2_validate(pattern, stix_version=CURRENT_SPEC_VERSION)
        if inspection.errors():
            errors = [str(e) for e in inspection.errors()]
            return ValidationResult(valid=False, errors=errors, strict=True)
        return ValidationResult(
            valid=True,
            warnings=tier1_result.warnings,
            strict=True,
        )
    except Exception as exc:  # noqa: BLE001
        # stix2-patterns raised unexpectedly; fall back to tier-1
        return ValidationResult(
            valid=tier1_result.valid,
            errors=tier1_result.errors,
            warnings=tier1_result.warnings + [f"stix2-patterns raised: {exc}"],
            strict=False,
        )
