# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.yaml_condition
======================================

Compiles YAML condition specs into callable predicates and actions.
Maps helper function names to the Python helpers at load time.
"""

from __future__ import annotations

import operator
from typing import Any, Callable

from gnat.analysis.rules.decisions import annotate, no_op, set_status
from gnat.analysis.rules.helpers import (
    confidence as _cf,
)
from gnat.analysis.rules.helpers import (
    evidence as _ev,
)
from gnat.analysis.rules.helpers import (
    policy as _po,
)
from gnat.analysis.rules.helpers import (
    source as _sr,
)
from gnat.analysis.rules.helpers import (
    status as _st,
)
from gnat.analysis.rules.helpers import (
    temporal as _tm,
)

_HELPERS_NO_CTX: dict[str, Callable] = {
    "supporting_count": _ev.supporting_count,
    "refuting_count": _ev.refuting_count,
    "evidence_count": _ev.evidence_count,
    "has_refutation": _ev.has_refutation,
    "support_ratio": _ev.support_ratio,
    "has_confidence": _cf.has_confidence,
    "stix_confidence": _cf.stix_confidence,
    "confidence_band": _cf.confidence_band,
    "reliability_of": _cf.reliability_of,
    "credibility_of": _cf.credibility_of,
    "reliability_at_least": _cf.reliability_at_least,
    "credibility_at_least": _cf.credibility_at_least,
    "age_days": _tm.age_days,
    "days_since_update": _tm.days_since_update,
    "stale": _tm.stale,
    "fresh": _tm.fresh,
    "status_of": _st.status_of,
    "is_open": _st.is_open,
    "is_supported": _st.is_supported,
    "is_refuted": _st.is_refuted,
    "is_inconclusive": _st.is_inconclusive,
}

_HELPERS_WITH_CTX: dict[str, Callable] = {
    "within_ai_ceiling": _po.within_ai_ceiling,
    "evidence_sources": _sr.evidence_sources,
    "trust_levels": _sr.trust_levels,
    "has_trusted_evidence": _sr.has_trusted_evidence,
    "all_evidence_trusted": _sr.all_evidence_trusted,
    "evidence_from": _sr.evidence_from,
    "unknown_source_count": _sr.unknown_source_count,
    "ai_only": _sr.ai_only,
}

_CMP_OPS: dict[str, Callable] = {
    "eq": operator.eq,
    "neq": operator.ne,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
}


def compile_condition(spec: Any) -> Callable[[Any, Any], bool]:
    if isinstance(spec, dict):
        if "all" in spec:
            subs = [compile_condition(s) for s in spec["all"]]
            return lambda h, ctx: all(s(h, ctx) for s in subs)
        if "any" in spec:
            subs = [compile_condition(s) for s in spec["any"]]
            return lambda h, ctx: any(s(h, ctx) for s in subs)
        if "not" in spec:
            inner = compile_condition(spec["not"])
            return lambda h, ctx: not inner(h, ctx)

        for name, arg in spec.items():
            return _compile_leaf(name, arg)

    raise ValueError(f"Invalid condition spec: {spec!r}")


def _compile_leaf(name: str, arg: Any) -> Callable[[Any, Any], bool]:
    if name in _HELPERS_NO_CTX:
        fn = _HELPERS_NO_CTX[name]
        return _build_no_ctx_check(fn, name, arg)
    if name in _HELPERS_WITH_CTX:
        fn = _HELPERS_WITH_CTX[name]
        return _build_ctx_check(fn, name, arg)
    raise ValueError(f"Unknown helper function: {name!r}")


def _build_no_ctx_check(
    fn: Callable, name: str, arg: Any
) -> Callable[[Any, Any], bool]:
    if isinstance(arg, dict):
        if "days" in arg:
            days_val = arg["days"]
            return lambda h, ctx: fn(h, days_val)
        for op_name, threshold in arg.items():
            if op_name in _CMP_OPS:
                cmp = _CMP_OPS[op_name]
                return lambda h, ctx, _fn=fn, _cmp=cmp, _t=threshold: _cmp(_fn(h), _t)
        raise ValueError(f"Unknown operator in {name}: {arg!r}")

    if isinstance(arg, bool):
        return lambda h, ctx, _fn=fn, _a=arg: bool(_fn(h)) == _a
    if isinstance(arg, (int, float)):
        return lambda h, ctx, _fn=fn, _a=arg: _fn(h, _a)
    if isinstance(arg, str):
        return lambda h, ctx, _fn=fn, _a=arg: _fn(h, _a)

    return lambda h, ctx, _fn=fn: bool(_fn(h))


def _build_ctx_check(
    fn: Callable, name: str, arg: Any
) -> Callable[[Any, Any], bool]:
    if isinstance(arg, bool):
        return lambda h, ctx, _fn=fn, _a=arg: bool(_fn(h, ctx)) == _a
    if isinstance(arg, str):
        return lambda h, ctx, _fn=fn, _a=arg: _fn(h, ctx, _a)
    if isinstance(arg, dict):
        for op_name, threshold in arg.items():
            if op_name in _CMP_OPS:
                cmp = _CMP_OPS[op_name]
                return lambda h, ctx, _fn=fn, _cmp=cmp, _t=threshold: _cmp(_fn(h, ctx), _t)
    return lambda h, ctx, _fn=fn: bool(_fn(h, ctx))


def compile_action(spec: dict[str, Any]) -> Callable[[Any, Any], Any]:
    if "set_status" in spec:
        cfg = spec["set_status"]
        target = cfg.get("target", "supported")
        reason = cfg.get("reason", "")
        return lambda h, ctx: set_status(target, reason)

    if "annotate" in spec:
        cfg = spec["annotate"]
        key = cfg.get("key", "")
        value = cfg.get("value")
        reason = cfg.get("reason", "")
        return lambda h, ctx: annotate(key, value, reason)

    if "no_op" in spec:
        cfg = spec["no_op"]
        reason = cfg.get("reason", "") if isinstance(cfg, dict) else ""
        return lambda h, ctx: no_op(reason)

    raise ValueError(f"Unknown action in 'then': {spec!r}")
