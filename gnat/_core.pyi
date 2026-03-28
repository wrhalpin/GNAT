"""
gnat._core — type stubs for the optional Rust acceleration extension.

This module is built via ``make build-rust`` (``maturin develop``).
All functions have identical pure-Python fallbacks in:
  - ``gnat.ingest._ioc_classifier`` (classify_ioc, defang, refang)
  - ``gnat.export.transforms.edl``  (extract_pattern_value, defang)
"""

__version__: str

def classify_ioc(value: str) -> str:
    """
    Classify an IOC string into one of:
    ``"sha256"``, ``"sha1"``, ``"md5"``, ``"ip"``, ``"ipv6"``,
    ``"url"``, ``"email"``, ``"domain"``, ``"unknown"``.
    """
    ...

def defang(value: str) -> str:
    """
    Remove common defanging substitutions to restore canonical IOC values.

    Reverses ``[.]`` → ``.``, ``hxxp://`` → ``http://``,
    ``hxxps://`` → ``https://``.
    """
    ...

def refang(value: str) -> str:
    """
    Apply defanging substitutions to an IOC value for safe display.

    ``http://`` → ``hxxp://``, ``.`` → ``[.]``, etc.
    """
    ...

def extract_pattern_value(pattern: str) -> str | None:
    """
    Extract the quoted value from a STIX pattern string.

    Given ``"[ipv4-addr:value = '1.2.3.4']"`` returns ``"1.2.3.4"``.
    Returns ``None`` if no quoted value is found.
    """
    ...

def classify_ioc_batch(values: list[str]) -> list[str]:
    """
    Classify a list of IOC strings in bulk.

    More efficient than calling ``classify_ioc()`` in a Python loop.
    Returns a list of type strings in the same order as the input.
    """
    ...
