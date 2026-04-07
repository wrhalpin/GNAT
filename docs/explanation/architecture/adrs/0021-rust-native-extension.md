# ADR-0021: Rust Native Extension (`gnat-core`)

**Decision:** Optional PyO3/maturin Rust extension for hot-path IOC functions; pure Python always available as fallback.

**Why Rust for IOC classification:**
- Every ingested line passes through `classify_ioc()` and `defang()`.
- At 100K IOCs/run these functions are measurable in profiles.
- The logic is purely computational (regex automata, string transforms) — ideal for Rust.
- PyO3 + maturin make integration seamless: the wheel installs as `gnat._core` and is
  imported via a shim in `gnat/ingest/_ioc_classifier.py`.

**Shim pattern:**
```python
try:
    from gnat._core import classify_ioc, defang, refang, ...
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    def classify_ioc(value): ...   # pure-Python equivalent
```
This means `RUST_AVAILABLE` is a public API flag; all callers check it in tests.

**Build targets:**
- `make build-rust` — `maturin build --release` + pip install wheel (CI/CD)
- `make build-rust-dev` — `maturin develop` (local iteration)

**Extras group:**
`pip install "gnat[fast]"` documents the native extension as optional. The core library
never requires it — the extra is purely for performance-critical deployments.

---

*Licensed under the Apache License, Version 2.0*
