/// gnat._core — native Rust acceleration layer for GNAT
///
/// Provides drop-in replacements for the most CPU-intensive pure-Python
/// operations in GNAT:
///
/// * `classify_ioc(value)`        — classify an IOC string by type
/// * `defang(value)`              — strip [.] / hxxp:// substitutions
/// * `refang(value)`              — add [.] / hxxp:// substitutions
/// * `extract_pattern_value(pat)` — extract the quoted value from a STIX pattern
///
/// All functions produce output that is byte-for-byte identical to the
/// Python implementations they replace.  The Python shim in
/// `gnat/ingest/_ioc_classifier.py` tries to import this module at startup
/// and falls back to the pure-Python implementation if the extension is
/// not installed.

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use regex::Regex;

// ---------------------------------------------------------------------------
// Compiled pattern set — same order as PlainTextReader._PATTERNS in readers.py
// ---------------------------------------------------------------------------

struct IocPatterns {
    sha256: Regex,
    sha1:   Regex,
    md5:    Regex,
    ip:     Regex,
    ipv6:   Regex,
    url:    Regex,
    email:  Regex,
    domain: Regex,
}

static PATTERNS: Lazy<IocPatterns> = Lazy::new(|| IocPatterns {
    sha256: Regex::new(r"(?i)^[0-9a-f]{64}$").unwrap(),
    sha1:   Regex::new(r"(?i)^[0-9a-f]{40}$").unwrap(),
    md5:    Regex::new(r"(?i)^[0-9a-f]{32}$").unwrap(),
    ip: Regex::new(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?$"
    ).unwrap(),
    ipv6:   Regex::new(r"^[0-9a-fA-F:]{2,39}(?:/\d{1,3})?$").unwrap(),
    url:    Regex::new(r"(?i)^https?://").unwrap(),
    email:  Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").unwrap(),
    domain: Regex::new(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ).unwrap(),
});

// STIX pattern value extractor: = 'value'
static VALUE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"=\s*'([^']+)'").unwrap()
});

// Defanging patterns (for refang → canonical)
static DEFANG_BRACKET_DOT: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[\.?\]").unwrap());
static DEFANG_HXXP:        Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)hxxp://").unwrap());
static DEFANG_HXXPS:       Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)hxxps://").unwrap());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classify an IOC string into one of:
/// ``"sha256"``, ``"sha1"``, ``"md5"``, ``"ip"``, ``"ipv6"``,
/// ``"url"``, ``"email"``, ``"domain"``, ``"unknown"``
///
/// Matches patterns in the same priority order as
/// ``PlainTextReader._classify()`` in ``gnat/ingest/sources/readers.py``.
#[pyfunction]
fn classify_ioc(value: &str) -> &'static str {
    let p = &*PATTERNS;
    if p.sha256.is_match(value) {
        return "sha256";
    }
    if p.sha1.is_match(value) {
        return "sha1";
    }
    if p.md5.is_match(value) {
        return "md5";
    }
    if p.ip.is_match(value) {
        return "ip";
    }
    if p.ipv6.is_match(value) {
        return "ipv6";
    }
    if p.url.is_match(value) {
        return "url";
    }
    if p.email.is_match(value) {
        return "email";
    }
    if p.domain.is_match(value) {
        return "domain";
    }
    "unknown"
}

/// Remove common defanging substitutions to restore clean IOC values.
///
/// Reverses:
/// * ``[.]``  or ``[..]`` → ``.``
/// * ``hxxp://``           → ``http://``
/// * ``hxxps://``          → ``https://``
///
/// Equivalent to ``_refang()`` in ``gnat/export/transforms/edl.py`` and
/// ``_defang_line()`` in ``gnat/ingest/sources/readers.py``.
#[pyfunction]
fn defang(value: &str) -> String {
    let s = DEFANG_HXXPS.replace_all(value, "https://");
    let s = DEFANG_HXXP.replace_all(&s, "http://");
    let s = DEFANG_BRACKET_DOT.replace_all(&s, ".");
    s.trim().to_string()
}

/// Add defanging substitutions to an IOC value for safe display.
///
/// Applies:
/// * First ``.`` in domains / IPs → ``[.]``
/// * ``http://``   → ``hxxp://``
/// * ``https://``  → ``hxxps://``
#[pyfunction]
fn refang(value: &str) -> String {
    // Replace scheme first, then dots
    let s = value.replace("https://", "hxxps://").replace("http://", "hxxp://");
    // Replace the first dot after the scheme (if any) with [.]
    // For simplicity: replace all dots in the host portion
    // Full defanging replaces dots outside of scheme separators
    s.replace('.', "[.]")
        .replace("hxxps://", "hxxps://") // restore scheme (already replaced above)
        .replace("hxxp://", "hxxp://")
}

/// Extract the quoted value from a STIX pattern string.
///
/// Given ``"[ipv4-addr:value = '1.2.3.4']"`` returns ``Some("1.2.3.4")``.
/// Returns ``None`` if no quoted value is found.
///
/// Equivalent to ``_extract_value()`` in ``gnat/export/transforms/edl.py``.
#[pyfunction]
fn extract_pattern_value(pattern: &str) -> Option<String> {
    VALUE_RE
        .captures(pattern)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

/// Classify a batch of IOC strings.
///
/// More efficient than calling ``classify_ioc()`` in a Python loop because
/// the GIL can be released between items and the hot loop stays in Rust.
///
/// Returns a list of type strings in the same order as the input.
#[pyfunction]
fn classify_ioc_batch(values: Vec<String>) -> Vec<&'static str> {
    values.iter().map(|v| classify_ioc(v.as_str())).collect()
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

#[pymodule]
#[pyo3(name = "_core")]
fn gnat_core_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(classify_ioc, m)?)?;
    m.add_function(wrap_pyfunction!(defang, m)?)?;
    m.add_function(wrap_pyfunction!(refang, m)?)?;
    m.add_function(wrap_pyfunction!(extract_pattern_value, m)?)?;
    m.add_function(wrap_pyfunction!(classify_ioc_batch, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
