"""
tests/unit/export/test_export.py
==================================

Unit tests for gnat.export — filters, transforms, delivery, pipeline, jobs.

Coverage:
- All filter classes: TypeFilter, ConfidenceFilter, TLPFilter, TagFilter,
  AgeFilter, IOCTypeFilter, LimitFilter, DeduplicateFilter, FunctionFilter,
  composite & operator
- EDLTransform: per-type files, combine mode, dedup, max_per_file, header,
  defang/refang, unknown type handling, value extraction
- NetskopeCETransform: payload structure, reputation mapping, active_only,
  category, ioc_types filter
- STIXBundleTransform, CSVTransform
- ExportPipeline: list source, workspace source, filter/transform/deliver chain,
  dry_run, preview, missing source, zero-match filtering
- FileDelivery: atomic write, directory creation, content verification
- LogDelivery: delivers all payloads
- MultiDelivery: both targets receive payload, failure propagation
- ExportJob: execute(), success/failure, callbacks, scheduler integration
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from gnat.export import DeliveryResult, ExportPipeline, TransformResult
from gnat.export.delivery.targets import (
    FileDelivery,
    LogDelivery,
    MultiDelivery,
)
from gnat.export.filters import (
    AgeFilter,
    ConfidenceFilter,
    DeduplicateFilter,
    FunctionFilter,
    IOCTypeFilter,
    LimitFilter,
    TagFilter,
    TLPFilter,
    TypeFilter,
)
from gnat.export.jobs import ExportJob
from gnat.export.transforms.edl import EDLTransform
from gnat.export.transforms.netskope import (
    CSVTransform,
    NetskopeCETransform,
    STIXBundleTransform,
)
from gnat.orm.indicator import Indicator
from gnat.orm.malware import Malware

# ===========================================================================
# Fixtures
# ===========================================================================

def _ind(name="evil.com", pattern=None, confidence=70, tlp="white",
         tags=None, modified_days_ago=1):
    if pattern is None:
        pattern = f"[domain-name:value = '{name}']"
    dt = (datetime.now(timezone.utc) - timedelta(days=modified_days_ago)).isoformat()
    obj = Indicator(
        name=name, pattern=pattern, pattern_type="stix",
        confidence=confidence, x_tlp=tlp,
    )
    if tags:
        obj._properties["x_gm_tags"] = tags
    obj._properties["modified"] = dt
    obj._properties["created"]  = dt
    return obj


def _ip(addr="1.2.3.4", confidence=80):
    return Indicator(
        name=addr,
        pattern=f"[ipv4-addr:value = '{addr}']",
        pattern_type="stix",
        confidence=confidence, x_tlp="white",
    )


def _indicators():
    return [
        _ind("evil-0.com", confidence=40, tlp="white", tags=["apt28"]),
        _ind("evil-1.com", confidence=60, tlp="green", tags=["apt28"]),
        _ind("evil-2.com", confidence=80, tlp="amber", tags=["internal"]),
        _ind("evil-3.com", confidence=90, tlp="red",   tags=["apt28"]),
        _ip("10.0.0.1", confidence=85),
        _ip("10.0.0.2", confidence=55),
    ]


def _sha256_ind():
    return Indicator(
        name="abc123",
        pattern="[file:hashes.SHA-256 = 'abc123def456']",
        pattern_type="stix", confidence=75, x_tlp="white",
    )


# ===========================================================================
# Filters
# ===========================================================================

class TestTypeFilter:
    def test_passes_matching_type(self):
        objs = _indicators() + [Malware(name="X")]
        result = list(TypeFilter("indicator")(objs))
        assert len(result) == 6
        assert all(o.stix_type == "indicator" for o in result)

    def test_multiple_types(self):
        objs = _indicators() + [Malware(name="X")]
        result = list(TypeFilter("indicator", "malware")(objs))
        assert len(result) == 7

    def test_no_match_yields_empty(self):
        assert list(TypeFilter("vulnerability")(_indicators())) == []

    def test_requires_at_least_one_type(self):
        with pytest.raises(ValueError):
            TypeFilter()


class TestConfidenceFilter:
    def test_passes_above_threshold(self):
        objs = _indicators()
        result = list(ConfidenceFilter(min_confidence=70)(objs))
        assert all(o._properties.get("confidence", 50) >= 70 for o in result)

    def test_drops_below_threshold(self):
        result = list(ConfidenceFilter(min_confidence=100)(_indicators()))
        assert result == []

    def test_x_rf_risk_score_fallback(self):
        ind = _ind("a.com", confidence=30)
        ind._properties["x_rf_risk_score"] = 90
        result = list(ConfidenceFilter(min_confidence=80, score_fields=["x_rf_risk_score"])([ind]))
        assert len(result) == 1

    def test_default_confidence_when_missing(self):
        ind = Indicator(name="x.com")
        # confidence not set → uses default_confidence
        result = list(ConfidenceFilter(min_confidence=60, default_confidence=70)([ind]))
        assert len(result) == 1

    def test_drop_missing_when_default_low(self):
        ind = Indicator(name="x.com")
        result = list(ConfidenceFilter(min_confidence=60, default_confidence=0)([ind]))
        assert len(result) == 0


class TestTLPFilter:
    def test_passes_allowed(self):
        objs = _indicators()
        result = list(TLPFilter(["white", "green"])(objs))
        assert all(o._properties.get("x_tlp") in ("white", "green") for o in result)

    def test_drops_excluded(self):
        result = list(TLPFilter(["white"])(_indicators()))
        assert all(o._properties.get("x_tlp") == "white" for o in result)

    def test_default_tlp_for_missing_field(self):
        ind = Indicator(name="x.com")
        # no x_tlp set — default is "white"
        result = list(TLPFilter(["white"])([ind]))
        assert len(result) == 1

    def test_strict_default_drops_unlabelled(self):
        ind = Indicator(name="x.com")
        result = list(TLPFilter(["white"], default_tlp="amber")([ind]))
        assert len(result) == 0


class TestTagFilter:
    def test_required_all(self):
        objs = _indicators()
        result = list(TagFilter(required=["apt28"])(objs))
        assert all("apt28" in (o._properties.get("x_gm_tags") or []) for o in result)

    def test_required_any(self):
        ind = _ind(tags=["a"])
        ind2 = _ind(tags=["b"])
        ind3 = _ind(tags=[])
        result = list(TagFilter(required=["a", "b"], match_any=True)([ind, ind2, ind3]))
        assert len(result) == 2

    def test_excluded(self):
        objs = _indicators()
        result = list(TagFilter(excluded=["internal"])(objs))
        assert all("internal" not in (o._properties.get("x_gm_tags") or []) for o in result)

    def test_combined_required_and_excluded(self):
        objs = _indicators()
        result = list(TagFilter(required=["apt28"], excluded=["internal"])(objs))
        assert all("apt28" in (o._properties.get("x_gm_tags") or []) for o in result)
        assert all("internal" not in (o._properties.get("x_gm_tags") or []) for o in result)


class TestAgeFilter:
    def test_passes_recent(self):
        ind = _ind(modified_days_ago=5)
        result = list(AgeFilter(max_age_days=30)([ind]))
        assert len(result) == 1

    def test_drops_old(self):
        ind = _ind(modified_days_ago=60)
        result = list(AgeFilter(max_age_days=30)([ind]))
        assert len(result) == 0

    def test_keeps_missing_by_default(self):
        ind = Indicator(name="x.com")  # no modified field
        result = list(AgeFilter(max_age_days=7, drop_missing=False)([ind]))
        assert len(result) == 1

    def test_drops_missing_when_strict(self):
        ind = Indicator(name="x.com")
        result = list(AgeFilter(max_age_days=7, drop_missing=True)([ind]))
        assert len(result) == 0


class TestIOCTypeFilter:
    def test_ipv4_only(self):
        objs = _indicators()
        result = list(IOCTypeFilter(["ipv4"])(objs))
        assert all("ipv4-addr" in o._properties.get("pattern", "") for o in result)

    def test_domain_only(self):
        result = list(IOCTypeFilter(["domain"])(_indicators()))
        assert all("domain-name" in o._properties.get("pattern", "") for o in result)

    def test_multiple_types(self):
        result = list(IOCTypeFilter(["ipv4", "domain"])(_indicators()))
        assert len(result) == 6  # all indicators

    def test_sha256(self):
        result = list(IOCTypeFilter(["sha256"])([_sha256_ind()]))
        assert len(result) == 1

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="unknown IOC types"):
            IOCTypeFilter(["fqdn"])

    def test_non_indicators_skipped(self):
        objs = _indicators() + [Malware(name="X")]
        result = list(IOCTypeFilter(["ipv4"])(objs))
        assert all(o.stix_type == "indicator" for o in result)


class TestLimitFilter:
    def test_caps_output(self):
        assert len(list(LimitFilter(3)(_indicators()))) == 3

    def test_passthrough_when_under_limit(self):
        objs = _indicators()
        assert len(list(LimitFilter(100)(objs))) == len(objs)


class TestDeduplicateFilter:
    def test_removes_exact_duplicates(self):
        ind = _ind("dup.com")
        result = list(DeduplicateFilter()([ind, ind, ind]))
        assert len(result) == 1

    def test_keeps_distinct_objects(self):
        result = list(DeduplicateFilter()(_indicators()))
        assert len(result) == len(_indicators())

    def test_custom_key_field(self):
        ind1 = _ind("a.com")
        ind1._properties["x_key"] = "same"
        ind2 = _ind("b.com")
        ind2._properties["x_key"] = "same"
        ind3 = _ind("c.com")
        ind3._properties["x_key"] = "different"
        result = list(DeduplicateFilter(key_field="x_key")([ind1, ind2, ind3]))
        assert len(result) == 2


class TestFunctionFilter:
    def test_custom_predicate(self):
        result = list(FunctionFilter(
            lambda o: o._properties.get("confidence", 0) > 70
        )(_indicators()))
        assert all(o._properties.get("confidence", 0) > 70 for o in result)


class TestCompositeFilter:
    def test_and_operator(self):
        f = TypeFilter("indicator") & ConfidenceFilter(70) & TLPFilter(["white"])
        result = list(f(_indicators() + [Malware(name="X")]))
        assert all(o.stix_type == "indicator" for o in result)
        assert all(o._properties.get("confidence", 0) >= 70 for o in result)
        assert all(o._properties.get("x_tlp") == "white" for o in result)

    def test_chained_and(self):
        f1 = TypeFilter("indicator") & ConfidenceFilter(50)
        f2 = f1 & TLPFilter(["white", "green"])
        result = list(f2(_indicators()))
        assert len(result) > 0


# ===========================================================================
# EDLTransform
# ===========================================================================

class TestEDLTransform:

    def test_produces_per_type_files(self):
        t = EDLTransform(ioc_types=["ipv4", "domain"])
        r = t.transform(_indicators())
        assert "indicators-ipv4.txt" in r.payloads
        assert "indicators-domain.txt" in r.payloads

    def test_domain_file_contains_domain_values(self):
        t = EDLTransform(ioc_types=["domain"])
        r = t.transform(_indicators())
        content = r.payloads["indicators-domain.txt"]
        assert "evil-0.com" in content

    def test_ip_file_contains_ip_values(self):
        t = EDLTransform(ioc_types=["ipv4"])
        r = t.transform(_indicators())
        assert "10.0.0.1" in r.payloads["indicators-ipv4.txt"]

    def test_sha256_file(self):
        t = EDLTransform(ioc_types=["sha256"])
        r = t.transform([_sha256_ind()])
        assert "indicators-sha256.txt" in r.payloads
        assert "abc123def456" in r.payloads["indicators-sha256.txt"]

    def test_header_comment(self):
        t = EDLTransform(ioc_types=["domain"], header_comment=True)
        r = t.transform(_indicators())
        assert r.payloads["indicators-domain.txt"].startswith("# Generated")

    def test_no_header(self):
        t = EDLTransform(ioc_types=["domain"], header_comment=False)
        r = t.transform(_indicators())
        assert not r.payloads["indicators-domain.txt"].startswith("#")

    def test_combine_mode_single_file(self):
        t = EDLTransform(combine=True)
        r = t.transform(_indicators())
        assert "indicators-all.txt" in r.payloads
        assert len(r.payloads) == 1

    def test_deduplication(self):
        ind = _ind("dup.com")
        t = EDLTransform(ioc_types=["domain"], deduplicate=True)
        r = t.transform([ind, ind, ind])
        lines = [ln for ln in r.payloads.get("indicators-domain.txt","").splitlines()
                 if not ln.startswith("#")]
        assert lines.count("dup.com") == 1

    def test_max_per_file_truncates(self):
        inds = [_ind(f"x{i}.com") for i in range(20)]
        t = EDLTransform(ioc_types=["domain"], max_per_file=5)
        r = t.transform(inds)
        lines = [ln for ln in r.payloads["indicators-domain.txt"].splitlines()
                 if not ln.startswith("#")]
        assert len(lines) == 5
        assert "domain" in r.metadata.get("truncated", {})

    def test_sort_output(self):
        inds = [_ind("z.com"), _ind("a.com"), _ind("m.com")]
        t = EDLTransform(ioc_types=["domain"], sort_output=True)
        r = t.transform(inds)
        lines = [ln for ln in r.payloads["indicators-domain.txt"].splitlines()
                 if not ln.startswith("#")]
        assert lines == sorted(lines)

    def test_malware_objects_skipped(self):
        objs = _indicators() + [Malware(name="skip-me")]
        t = EDLTransform(ioc_types=["domain"])
        r = t.transform(objs)
        assert r.metadata["skipped"] >= 1  # malware was skipped

    def test_custom_prefix(self):
        t = EDLTransform(ioc_types=["ipv4"], filename_prefix="palo-alto")
        r = t.transform(_indicators())
        assert "palo-alto-ipv4.txt" in r.payloads

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="unknown IOC types"):
            EDLTransform(ioc_types=["unknown"])

    def test_empty_input_no_files(self):
        t = EDLTransform(ioc_types=["domain"])
        r = t.transform([])
        assert r.object_count == 0
        assert r.payloads == {}

    def test_object_count_reflects_extracted(self):
        t = EDLTransform(ioc_types=["domain"])
        r = t.transform(_indicators())
        domain_lines = [ln for ln in r.payloads.get("indicators-domain.txt","").splitlines()
                        if not ln.startswith("#")]
        assert r.object_count == len(domain_lines)


# ===========================================================================
# NetskopeCETransform
# ===========================================================================

class TestNetskopeCETransform:

    def test_produces_json_payload(self):
        t = NetskopeCETransform()
        r = t.transform(_indicators())
        assert "netskope_payload.json" in r.payloads
        payload = json.loads(r.payloads["netskope_payload.json"])
        assert "indicator_list" in payload

    def test_indicator_structure(self):
        ind = _ind("evil.com", confidence=80)
        t = NetskopeCETransform()
        r = t.transform([ind])
        entry = json.loads(r.payloads["netskope_payload.json"])["indicator_list"][0]
        assert "value" in entry and "type" in entry
        assert "reputation" in entry and "comment" in entry
        assert entry["active"] is True

    def test_source_label_in_comment(self):
        t = NetskopeCETransform(source_label="ThreatQ-APT28")
        r = t.transform([_ind("x.com")])
        entry = json.loads(r.payloads["netskope_payload.json"])["indicator_list"][0]
        assert "ThreatQ-APT28" in entry["comment"]

    def test_reputation_from_confidence(self):
        ind = _ind("x.com", confidence=85)
        t = NetskopeCETransform()
        r = t.transform([ind])
        entry = json.loads(r.payloads["netskope_payload.json"])["indicator_list"][0]
        assert entry["reputation"] == 85

    def test_default_reputation_when_no_score(self):
        ind = Indicator(name="x.com", pattern="[domain-name:value = 'x.com']",
                        pattern_type="stix")
        t = NetskopeCETransform(default_reputation=42)
        r = t.transform([ind])
        entry = json.loads(r.payloads["netskope_payload.json"])["indicator_list"][0]
        assert entry["reputation"] == 42

    def test_malware_objects_skipped(self):
        t = NetskopeCETransform()
        r = t.transform([Malware(name="skip")])
        payload = json.loads(r.payloads["netskope_payload.json"])
        assert len(payload["indicator_list"]) == 0

    def test_ioc_types_filter(self):
        t = NetskopeCETransform(ioc_types=["domain"])
        r = t.transform(_indicators())
        payload = json.loads(r.payloads["netskope_payload.json"])
        assert all(e["type"] == "domain" for e in payload["indicator_list"])

    def test_category_field(self):
        t = NetskopeCETransform(category="Phishing")
        r = t.transform([_ind("x.com")])
        entry = json.loads(r.payloads["netskope_payload.json"])["indicator_list"][0]
        assert entry["category"] == "Phishing"

    def test_ipv4_type_mapping(self):
        t = NetskopeCETransform()
        r = t.transform([_ip("1.2.3.4")])
        entry = json.loads(r.payloads["netskope_payload.json"])["indicator_list"][0]
        assert entry["type"] == "ip"
        assert entry["value"] == "1.2.3.4"


class TestSTIXBundleTransform:
    def test_produces_bundle_json(self):
        r = STIXBundleTransform().transform(_indicators()[:3])
        bundle = json.loads(r.payloads["bundle.json"])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) == 3

    def test_object_count(self):
        r = STIXBundleTransform().transform(_indicators())
        assert r.object_count == len(_indicators())


class TestCSVTransform:
    def test_produces_csv(self):
        r = CSVTransform(fields=["name", "confidence"]).transform(_indicators()[:3])
        lines = r.payloads["export.csv"].splitlines()
        assert "name" in lines[0].lower()
        assert len(lines) == 4  # header + 3

    def test_custom_filename(self):
        r = CSVTransform(filename="output.csv").transform(_indicators())
        assert "output.csv" in r.payloads

    def test_all_default_fields(self):
        r = CSVTransform().transform(_indicators()[:2])
        assert "export.csv" in r.payloads


# ===========================================================================
# ExportPipeline
# ===========================================================================

class TestExportPipeline:

    def test_list_source(self):
        p = ExportPipeline("t").read_from(_indicators()).transform_with(
            EDLTransform(ioc_types=["domain"])
        ).deliver_to(LogDelivery())
        result = p.run()
        assert result.success
        assert result.source_objects == len(_indicators())

    def test_filter_reduces_objects(self):
        p = ExportPipeline("t").read_from(_indicators()).filter_with(
            ConfidenceFilter(min_confidence=85)
        ).transform_with(EDLTransform(ioc_types=["domain", "ipv4"])).deliver_to(LogDelivery())
        result = p.run()
        assert result.filtered_objects < result.source_objects

    def test_zero_match_skips_transform_and_deliver(self):
        p = ExportPipeline("t").read_from(_indicators()).filter_with(
            ConfidenceFilter(min_confidence=999)
        ).transform_with(EDLTransform()).deliver_to(LogDelivery())
        result = p.run()
        assert result.success
        assert result.filtered_objects == 0
        assert result.transform_result is None

    def test_dry_run_skips_delivery(self):
        p = ExportPipeline("t").read_from(_indicators()).transform_with(
            EDLTransform(ioc_types=["domain"])
        ).deliver_to(LogDelivery())
        result = p.dry_run()
        assert result.delivery_result is None
        assert result.transform_result is not None

    def test_preview(self):
        p = ExportPipeline("t").read_from(_indicators()).filter_with(TypeFilter("indicator"))
        prev = p.preview(n=3)
        assert len(prev) == 3

    def test_missing_source_returns_error_result(self):
        result = ExportPipeline("t").run()
        assert not result.success
        assert result.errors

    def test_multiple_filters_chained(self):
        p = (ExportPipeline("t")
             .read_from(_indicators())
             .filter_with(TypeFilter("indicator"))
             .filter_with(ConfidenceFilter(70))
             .filter_with(TLPFilter(["white"]))
             .transform_with(EDLTransform(ioc_types=["domain", "ipv4"]))
             .deliver_to(LogDelivery()))
        result = p.run()
        assert result.success

    def test_no_transform_passthrough(self):
        p = ExportPipeline("t").read_from(_indicators()).deliver_to(LogDelivery())
        result = p.run()
        assert result.success
        assert result.transform_result is not None


# ===========================================================================
# Delivery
# ===========================================================================

class TestFileDelivery:

    def test_creates_files(self, tmp_path):
        t = EDLTransform(ioc_types=["domain"])
        tr = t.transform(_indicators())
        dr = FileDelivery(str(tmp_path)).deliver(tr)
        assert dr.success
        assert (tmp_path / "indicators-domain.txt").exists()

    def test_content_is_correct(self, tmp_path):
        t = EDLTransform(ioc_types=["domain"], header_comment=False)
        tr = t.transform([_ind("target.com")])
        FileDelivery(str(tmp_path)).deliver(tr)
        content = (tmp_path / "indicators-domain.txt").read_text()
        assert "target.com" in content

    def test_atomic_write_replaces_atomically(self, tmp_path):
        # Write once, then overwrite — no partial reads possible
        t = EDLTransform(ioc_types=["domain"])
        tr1 = t.transform([_ind("first.com")])
        tr2 = t.transform([_ind("second.com")])
        fd = FileDelivery(str(tmp_path), atomic=True)
        fd.deliver(tr1)
        fd.deliver(tr2)
        content = (tmp_path / "indicators-domain.txt").read_text()
        assert "second.com" in content

    def test_creates_output_dir(self, tmp_path):
        output_dir = str(tmp_path / "nested" / "dir")
        tr = TransformResult(payloads={"test.txt": "content"}, object_count=1)
        dr = FileDelivery(output_dir).deliver(tr)
        assert dr.success
        assert os.path.exists(os.path.join(output_dir, "test.txt"))


class TestLogDelivery:
    def test_delivers_all_payloads(self):
        tr = TransformResult(
            payloads={"a.txt": "content-a", "b.txt": "content-b"},
            object_count=2,
        )
        dr = LogDelivery().deliver(tr)
        assert dr.success
        assert set(dr.delivered) == {"a.txt", "b.txt"}


class TestMultiDelivery:
    def test_requires_at_least_two_targets(self):
        with pytest.raises(ValueError):
            MultiDelivery(LogDelivery())

    def test_both_targets_receive_payload(self, tmp_path):
        tr = TransformResult(payloads={"test.txt": "hello"}, object_count=1)
        md = MultiDelivery(FileDelivery(str(tmp_path)), LogDelivery())
        dr = md.deliver(tr)
        assert dr.success
        assert (tmp_path / "test.txt").exists()

    def test_failure_in_one_target_propagates(self, tmp_path):
        class _FailDelivery(LogDelivery):
            def deliver(self, result):
                return DeliveryResult(success=False, failed=["f"], errors=["oops"])

        tr = TransformResult(payloads={"t.txt": "x"}, object_count=1)
        md = MultiDelivery(_FailDelivery(), LogDelivery())
        dr = md.deliver(tr)
        assert not dr.success
        assert dr.errors


# ===========================================================================
# ExportJob
# ===========================================================================

class TestExportJob:

    def _build_pipeline(self):
        return (
            ExportPipeline("test")
            .read_from(_indicators())
            .filter_with(TypeFilter("indicator"))
            .transform_with(EDLTransform(ioc_types=["domain"]))
            .deliver_to(LogDelivery())
        )

    def test_execute_success(self):
        job = ExportJob("j", lambda ctx: self._build_pipeline(), interval_seconds=60)
        rec = job.execute()
        assert rec.status == "success"
        assert job.run_count == 1
        assert job.last_export_result is not None
        assert job.last_export_result.success

    def test_on_success_callback(self):
        fired = []
        job = ExportJob("j", lambda ctx: self._build_pipeline(),
                        interval_seconds=60,
                        on_success=lambda rec: fired.append(rec.status))
        job.execute()
        assert fired == ["success"]

    def test_execute_failure(self):
        def bad_factory(ctx):
            raise RuntimeError("pipeline error")

        fired = []
        job = ExportJob("j", bad_factory, interval_seconds=60,
                        on_failure=lambda rec: fired.append(rec.error))
        rec = job.execute()
        assert rec.status == "failed"
        assert "pipeline error" in (rec.error or "")
        assert fired and "pipeline error" in fired[0]

    def test_disabled_returns_skipped(self):
        job = ExportJob("j", lambda ctx: self._build_pipeline(),
                        interval_seconds=60, enabled=False)
        rec = job.execute()
        assert rec.status == "skipped"
        assert job.run_count == 0

    def test_ctx_last_success_iso_propagates(self):
        seen = []
        def factory(ctx):
            seen.append(ctx.last_success_iso)
            return self._build_pipeline()

        job = ExportJob("j", factory, interval_seconds=60)
        job.execute()
        job.execute()
        assert seen[0] is None
        assert seen[1] is not None

    def test_integrates_with_feed_scheduler(self):
        from gnat.schedule import FeedScheduler
        job = ExportJob("j", lambda ctx: self._build_pipeline(), interval_seconds=60)
        sched = FeedScheduler()
        sched.add(job)
        assert "j" in sched
        rec = sched.run_now("j")
        assert rec.status == "success"

    def test_max_history_respected(self):
        job = ExportJob("j", lambda ctx: self._build_pipeline(),
                        interval_seconds=60, max_history=3)
        for _ in range(5):
            job.execute()
        assert len(job.history) == 3
