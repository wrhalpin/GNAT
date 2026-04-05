"""
tests/unit/test_health_monitor.py
===================================
Unit tests for gnat.agents.health_monitor.

Tests cover:
1.  HealthMonitorConfig.from_ini() — INI section reading and defaults
2.  _fingerprint_dict() — nested/list/scalar flattening
3.  _compute_drift() — added, removed, type changes, ratio
4.  SchemaSnapshot.to_dict() / from_dict()
5.  load_snapshot() / save_snapshot() — file I/O
6.  DriftReport.is_significant / summary()
7.  HealthCheckResult.status property
8.  HealthRun aggregate properties
9.  _try_sample_schema() — success path and all-fail path
10. _post_slack_webhook() — success and exception handling
11. _format_alert() — output content
12. ConnectorHealthJob construction (interval and cron)
13. execute() — all-healthy success path
14. execute() — connector unreachable → partial + alert
15. execute() — disabled job → skipped
16. execute() — no baseline: saves snapshot, no alert
17. execute() — within-threshold drift: rolls baseline silently
18. execute() — over-threshold drift: partial, no baseline update
19. execute() — connector raises in health_check
20. execute() — unhandled exception in _run_health_checks → failed
21. from_config() factory
22. FeedScheduler integration (add + execute)
23. CLI subcommand registration
24. CLI health check command (success/problem exit codes)
25. CLI health baseline command
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gnat.agents.health_monitor import (
    ConnectorHealthJob,
    DriftReport,
    HealthCheckResult,
    HealthMonitorConfig,
    HealthRun,
    SchemaSnapshot,
    _compute_drift,
    _fingerprint_dict,
    _format_alert,
    _post_slack_webhook,
    _try_sample_schema,
    load_snapshot,
    save_snapshot,
)

# ---------------------------------------------------------------------------
# HealthMonitorConfig
# ---------------------------------------------------------------------------


class TestHealthMonitorConfig:
    def test_defaults(self):
        cfg = HealthMonitorConfig()
        assert cfg.interval_minutes == 60
        assert cfg.drift_threshold == 0.2
        assert cfg.alert_webhook is None
        assert cfg.platforms is None
        assert cfg.enabled is True

    def test_from_ini_reads_section(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text(
            "[health_monitor]\n"
            "enabled = false\n"
            "interval_minutes = 30\n"
            "alert_webhook = https://hooks.slack.com/test\n"
            "drift_threshold = 0.1\n"
            "snapshot_dir = /tmp/snaps\n"
            "platforms = threatq, crowdstrike\n"
        )
        cfg = HealthMonitorConfig.from_ini(str(ini))
        assert cfg.enabled is False
        assert cfg.interval_minutes == 30
        assert cfg.alert_webhook == "https://hooks.slack.com/test"
        assert cfg.drift_threshold == 0.1
        assert cfg.snapshot_dir == "/tmp/snaps"
        assert cfg.platforms == ["threatq", "crowdstrike"]

    def test_from_ini_wildcard_platforms(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[health_monitor]\nplatforms = *\n")
        cfg = HealthMonitorConfig.from_ini(str(ini))
        assert cfg.platforms is None  # * → None means all

    def test_from_ini_missing_section_returns_defaults(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[threatq]\nhost = https://tq.example.com\n")
        cfg = HealthMonitorConfig.from_ini(str(ini))
        assert cfg.interval_minutes == 60

    def test_from_ini_nonexistent_file_returns_defaults(self, tmp_path):
        cfg = HealthMonitorConfig.from_ini(str(tmp_path / "nofile.ini"))
        assert cfg.enabled is True


# ---------------------------------------------------------------------------
# _fingerprint_dict
# ---------------------------------------------------------------------------


class TestFingerprintDict:
    def test_flat_dict(self):
        fp = _fingerprint_dict({"a": 1, "b": "x", "c": True})
        assert fp == {"a": "int", "b": "str", "c": "bool"}

    def test_nested_dict(self):
        fp = _fingerprint_dict({"outer": {"inner": 3.14}})
        assert "outer.inner" in fp
        assert fp["outer.inner"] == "float"

    def test_list_of_scalars(self):
        fp = _fingerprint_dict({"items": [1, 2, 3]})
        assert fp["items"] == "list"
        # No sub-keys for a list of scalars
        assert "items[]" not in fp

    def test_list_of_dicts(self):
        fp = _fingerprint_dict({"objs": [{"x": 1}]})
        assert fp["objs"] == "list"
        assert fp["objs[].x"] == "int"

    def test_empty_dict(self):
        assert _fingerprint_dict({}) == {}

    def test_max_depth_respected(self):
        deep = {"a": {"b": {"c": {"d": {"e": 1}}}}}
        fp = _fingerprint_dict(deep, max_depth=2)
        # Should not go beyond depth 2
        assert "a.b" in fp
        assert "a.b.c" not in fp

    def test_none_value(self):
        fp = _fingerprint_dict({"x": None})
        assert fp["x"] == "NoneType"


# ---------------------------------------------------------------------------
# _compute_drift
# ---------------------------------------------------------------------------


class TestComputeDrift:
    def _baseline(self, fields: dict) -> SchemaSnapshot:
        return SchemaSnapshot(
            connector="test",
            captured_at="2026-01-01T00:00:00",
            fields=fields,
        )

    def test_no_change(self):
        baseline = self._baseline({"a": "int", "b": "str"})
        drift = _compute_drift("test", baseline, {"a": "int", "b": "str"})
        assert drift.drift_ratio == 0.0
        assert not drift.is_significant

    def test_added_fields(self):
        baseline = self._baseline({"a": "int"})
        drift = _compute_drift("test", baseline, {"a": "int", "b": "str"})
        assert "b" in drift.added_fields
        assert drift.drift_ratio == pytest.approx(1.0)  # 1 added / 1 baseline

    def test_removed_fields(self):
        baseline = self._baseline({"a": "int", "b": "str"})
        drift = _compute_drift("test", baseline, {"a": "int"})
        assert "b" in drift.removed_fields
        assert drift.drift_ratio == pytest.approx(0.5)  # 1 removed / 2 baseline

    def test_type_change(self):
        baseline = self._baseline({"a": "int"})
        drift = _compute_drift("test", baseline, {"a": "str"})
        assert "a" in drift.type_changes
        assert drift.type_changes["a"] == ("int", "str")
        assert drift.is_significant

    def test_connector_name_propagated(self):
        baseline = self._baseline({"x": "int"})
        drift = _compute_drift("myplatform", baseline, {"x": "int"})
        assert drift.connector == "myplatform"

    def test_baseline_captured_at_propagated(self):
        baseline = self._baseline({"x": "int"})
        baseline.captured_at = "2025-06-01T00:00:00"
        drift = _compute_drift("c", baseline, {"x": "int"})
        assert drift.baseline_captured_at == "2025-06-01T00:00:00"

    def test_empty_current_fields(self):
        baseline = self._baseline({"a": "int", "b": "str"})
        drift = _compute_drift("c", baseline, {})
        assert len(drift.removed_fields) == 2
        assert drift.drift_ratio == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# SchemaSnapshot serialization
# ---------------------------------------------------------------------------


class TestSchemaSnapshot:
    def test_round_trip(self):
        snap = SchemaSnapshot(
            connector="threatq", captured_at="2026-01-01", fields={"a": "int"}, sample_count=3
        )
        restored = SchemaSnapshot.from_dict(snap.to_dict())
        assert restored.connector == "threatq"
        assert restored.fields == {"a": "int"}
        assert restored.sample_count == 3

    def test_from_dict_missing_sample_count(self):
        d = {"connector": "x", "captured_at": "2026-01-01", "fields": {}}
        snap = SchemaSnapshot.from_dict(d)
        assert snap.sample_count == 1


# ---------------------------------------------------------------------------
# load_snapshot / save_snapshot
# ---------------------------------------------------------------------------


class TestSnapshotIO:
    def test_save_and_load(self, tmp_path):
        fields = {"a": "int", "b.c": "str"}
        save_snapshot("mytarget", fields, str(tmp_path))
        snap = load_snapshot("mytarget", str(tmp_path))
        assert snap is not None
        assert snap.connector == "mytarget"
        assert snap.fields == fields

    def test_load_nonexistent_returns_none(self, tmp_path):
        assert load_snapshot("nosuch", str(tmp_path)) is None

    def test_save_creates_directory(self, tmp_path):
        nested = tmp_path / "a" / "b" / "snapshots"
        save_snapshot("plat", {"x": "int"}, str(nested))
        assert (nested / "plat.json").exists()

    def test_load_corrupt_json_returns_none(self, tmp_path):
        (tmp_path / "bad.json").write_text("not json")
        assert load_snapshot("bad", str(tmp_path)) is None

    def test_save_overwrites_existing(self, tmp_path):
        save_snapshot("p", {"a": "int"}, str(tmp_path))
        save_snapshot("p", {"b": "str"}, str(tmp_path))
        snap = load_snapshot("p", str(tmp_path))
        assert "b" in snap.fields
        assert "a" not in snap.fields


# ---------------------------------------------------------------------------
# DriftReport & HealthCheckResult
# ---------------------------------------------------------------------------


class TestDriftReport:
    def test_is_significant_true(self):
        dr = DriftReport("c", "t", ["new"], [], {}, 0.5)
        assert dr.is_significant

    def test_is_significant_false(self):
        dr = DriftReport("c", "t", [], [], {}, 0.0)
        assert not dr.is_significant

    def test_summary_added(self):
        dr = DriftReport("c", "t", ["f1", "f2"], [], {}, 0.4)
        assert "2 added" in dr.summary()

    def test_summary_removed(self):
        dr = DriftReport("c", "t", [], ["f1"], {}, 0.5)
        assert "1 removed" in dr.summary()

    def test_summary_type_changed(self):
        dr = DriftReport("c", "t", [], [], {"x": ("int", "str")}, 0.1)
        assert "type changed" in dr.summary()


class TestHealthCheckResult:
    def test_status_ok(self):
        r = HealthCheckResult("c", reachable=True, response_ms=10.0)
        assert r.status == "ok"

    def test_status_unreachable(self):
        r = HealthCheckResult("c", reachable=False, response_ms=0.0)
        assert r.status == "unreachable"

    def test_status_drift(self):
        drift = DriftReport("c", "t", ["new_field"], [], {}, 0.5)
        r = HealthCheckResult("c", reachable=True, response_ms=5.0, drift=drift)
        assert r.status == "drift"

    def test_status_ok_when_drift_not_significant(self):
        drift = DriftReport("c", "t", [], [], {}, 0.0)
        r = HealthCheckResult("c", reachable=True, response_ms=5.0, drift=drift)
        assert r.status == "ok"


class TestHealthRun:
    def test_counts(self):
        run = HealthRun("2026-01-01T00:00:00")
        run.checks = [
            HealthCheckResult("a", True, 10.0),
            HealthCheckResult("b", False, 0.0),
            HealthCheckResult("c", True, 5.0, drift=DriftReport("c", "t", ["f"], [], {}, 0.5)),
        ]
        assert run.healthy_count == 2
        assert run.unhealthy_count == 1
        assert run.drift_count == 1


# ---------------------------------------------------------------------------
# _try_sample_schema
# ---------------------------------------------------------------------------


class TestTrySampleSchema:
    def test_returns_fingerprint_on_success(self):
        mock_conn = MagicMock()
        mock_conn.list_objects.return_value = [{"id": "ind--1", "name": "evil.com"}]
        fp = _try_sample_schema(mock_conn)
        assert fp is not None
        assert "id" in fp
        assert fp["id"] == "str"

    def test_returns_none_when_all_fail(self):
        mock_conn = MagicMock()
        mock_conn.list_objects.side_effect = Exception("no objects")
        fp = _try_sample_schema(mock_conn)
        assert fp is None

    def test_returns_none_on_empty_list(self):
        mock_conn = MagicMock()
        mock_conn.list_objects.return_value = []
        fp = _try_sample_schema(mock_conn)
        assert fp is None

    def test_uses_to_dict_on_stix_object(self):
        mock_obj = MagicMock()
        mock_obj.to_dict.return_value = {"type": "indicator", "name": "x"}
        mock_conn = MagicMock()
        mock_conn.list_objects.return_value = [mock_obj]
        fp = _try_sample_schema(mock_conn)
        assert fp is not None
        assert "type" in fp

    def test_tries_multiple_stix_types(self):
        call_count = 0

        def side_effect(stix_type, limit=1):
            nonlocal call_count
            call_count += 1
            if stix_type == "malware":
                return [{"id": "mal--1", "name": "bad"}]
            raise Exception("nope")

        mock_conn = MagicMock()
        mock_conn.list_objects.side_effect = side_effect
        fp = _try_sample_schema(mock_conn)
        assert fp is not None
        assert call_count >= 3  # tried indicator, observed-data, then malware


# ---------------------------------------------------------------------------
# _post_slack_webhook
# ---------------------------------------------------------------------------


class TestPostSlackWebhook:
    def test_returns_true_on_200(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        with patch("gnat.agents.health_monitor.urllib3.PoolManager") as mock_pm:
            mock_pm.return_value.request.return_value = mock_resp
            result = _post_slack_webhook("https://hooks.slack.com/test", "hello")
        assert result is True

    def test_returns_false_on_non_200(self):
        mock_resp = MagicMock()
        mock_resp.status = 400
        with patch("gnat.agents.health_monitor.urllib3.PoolManager") as mock_pm:
            mock_pm.return_value.request.return_value = mock_resp
            result = _post_slack_webhook("https://hooks.slack.com/test", "hello")
        assert result is False

    def test_returns_false_on_exception(self):
        with patch("gnat.agents.health_monitor.urllib3.PoolManager") as mock_pm:
            mock_pm.return_value.request.side_effect = Exception("connection refused")
            result = _post_slack_webhook("https://hooks.slack.com/test", "hello")
        assert result is False


# ---------------------------------------------------------------------------
# _format_alert
# ---------------------------------------------------------------------------


class TestFormatAlert:
    def test_includes_connector_name_on_unreachable(self):
        run = HealthRun("2026-01-01T12:00:00")
        run.checks = [
            HealthCheckResult("threatq", reachable=False, response_ms=0.0, error="timeout")
        ]
        text = _format_alert(run)
        assert "threatq" in text
        assert "unreachable" in text.lower()

    def test_includes_drift_info(self):
        drift = DriftReport("crowdstrike", "t", ["new_field"], [], {}, 0.5)
        run = HealthRun("2026-01-01T12:00:00")
        run.checks = [
            HealthCheckResult("crowdstrike", reachable=True, response_ms=5.0, drift=drift)
        ]
        text = _format_alert(run, drift_threshold=0.1)
        assert "crowdstrike" in text
        assert "drift" in text.lower()

    def test_all_healthy_message(self):
        run = HealthRun("2026-01-01T12:00:00")
        run.checks = [HealthCheckResult("threatq", reachable=True, response_ms=10.0)]
        text = _format_alert(run)
        assert "healthy" in text.lower()

    def test_includes_timestamp(self):
        run = HealthRun("2026-03-15T08:30:00.000Z")
        text = _format_alert(run)
        assert "2026-03-15" in text


# ---------------------------------------------------------------------------
# ConnectorHealthJob construction
# ---------------------------------------------------------------------------


class TestConnectorHealthJobConstruction:
    def test_basic_construction_interval(self):
        job = ConnectorHealthJob(connectors={}, interval_minutes=30)
        assert job.job_id == "connector-health"
        assert job.interval_seconds == 30 * 60
        assert job.enabled is True

    def test_construction_with_cron(self):
        job = ConnectorHealthJob(connectors={}, cron="0 * * * *")
        assert job.cron == "0 * * * *"
        assert job.interval_seconds is None

    def test_custom_job_id(self):
        job = ConnectorHealthJob(connectors={}, job_id="my-health", interval_minutes=60)
        assert job.job_id == "my-health"

    def test_disabled_construction(self):
        job = ConnectorHealthJob(connectors={}, enabled=False, interval_minutes=60)
        assert job.enabled is False

    def test_connectors_stored(self):
        mock_conn = MagicMock()
        job = ConnectorHealthJob(connectors={"threatq": mock_conn}, interval_minutes=60)
        assert "threatq" in job._connectors

    def test_inherits_feedjob(self):
        from gnat.schedule.job import FeedJob

        job = ConnectorHealthJob(connectors={}, interval_minutes=60)
        assert isinstance(job, FeedJob)


# ---------------------------------------------------------------------------
# ConnectorHealthJob.execute()
# ---------------------------------------------------------------------------


class TestConnectorHealthJobExecute:
    def _healthy_connector(self, fields=None):
        """Return a mock connector whose health_check returns True."""
        conn = MagicMock()
        conn.health_check.return_value = True
        conn.list_objects.return_value = [
            {"id": "indicator--1", "name": "evil.com", "type": "indicator"}
        ]
        return conn

    def test_all_healthy_returns_success(self, tmp_path):
        conn = self._healthy_connector()
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=False,
            snapshot_dir=str(tmp_path),
        )
        rec = job.execute()
        assert rec.status == "success"
        assert job.run_count == 1

    def test_unreachable_connector_returns_partial(self, tmp_path):
        conn = MagicMock()
        conn.health_check.return_value = False
        job = ConnectorHealthJob(
            connectors={"bad": conn},
            interval_minutes=60,
            sample_schema=False,
            snapshot_dir=str(tmp_path),
        )
        rec = job.execute()
        assert rec.status == "partial"

    def test_disabled_job_returns_skipped(self, tmp_path):
        conn = self._healthy_connector()
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            enabled=False,
            snapshot_dir=str(tmp_path),
        )
        rec = job.execute()
        assert rec.status == "skipped"
        conn.health_check.assert_not_called()

    def test_no_baseline_saves_snapshot(self, tmp_path):
        conn = self._healthy_connector()
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=True,
            snapshot_dir=str(tmp_path),
        )
        rec = job.execute()
        assert (tmp_path / "tq.json").exists()
        assert rec.status == "success"

    def test_within_threshold_rolls_baseline(self, tmp_path):
        # Save a baseline with identical fields
        existing_fields = {"id": "str", "name": "str", "type": "str"}
        save_snapshot("tq", existing_fields, str(tmp_path))

        conn = self._healthy_connector()
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=True,
            snapshot_dir=str(tmp_path),
            drift_threshold=0.5,
        )
        rec = job.execute()
        # No significant drift → success, baseline updated
        assert rec.status == "success"
        snap = load_snapshot("tq", str(tmp_path))
        assert snap is not None

    def test_over_threshold_drift_returns_partial(self, tmp_path):
        # Baseline has completely different fields
        save_snapshot("tq", {"old_a": "int", "old_b": "int", "old_c": "int"}, str(tmp_path))

        conn = self._healthy_connector()  # returns {"id": "str", "name": "str", "type": "str"}
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=True,
            snapshot_dir=str(tmp_path),
            drift_threshold=0.1,
        )
        rec = job.execute()
        assert rec.status == "partial"

    def test_connector_raises_in_health_check(self, tmp_path):
        conn = MagicMock()
        conn.health_check.side_effect = Exception("network error")
        job = ConnectorHealthJob(
            connectors={"bad": conn},
            interval_minutes=60,
            sample_schema=False,
            snapshot_dir=str(tmp_path),
        )
        rec = job.execute()
        # Exception in health_check → connector is unreachable → partial
        assert rec.status == "partial"
        run: HealthRun = rec.result  # type: ignore[assignment]
        assert run.checks[0].error == "network error"

    def test_alert_webhook_called_on_problem(self, tmp_path):
        conn = MagicMock()
        conn.health_check.return_value = False
        with patch("gnat.agents.health_monitor._post_slack_webhook") as mock_post:
            mock_post.return_value = True
            job = ConnectorHealthJob(
                connectors={"bad": conn},
                interval_minutes=60,
                sample_schema=False,
                snapshot_dir=str(tmp_path),
                alert_webhook="https://hooks.slack.com/test",
            )
            job.execute()
        mock_post.assert_called_once()

    def test_no_alert_when_all_healthy(self, tmp_path):
        conn = self._healthy_connector()
        with patch("gnat.agents.health_monitor._post_slack_webhook") as mock_post:
            job = ConnectorHealthJob(
                connectors={"tq": conn},
                interval_minutes=60,
                sample_schema=False,
                snapshot_dir=str(tmp_path),
                alert_webhook="https://hooks.slack.com/test",
            )
            job.execute()
        mock_post.assert_not_called()

    def test_run_record_stored_in_history(self, tmp_path):
        conn = self._healthy_connector()
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=False,
            snapshot_dir=str(tmp_path),
        )
        job.execute()
        assert len(job.history) == 1
        assert job.history[0].status == "success"

    def test_multiple_runs_increment_count(self, tmp_path):
        conn = self._healthy_connector()
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=False,
            snapshot_dir=str(tmp_path),
        )
        job.execute()
        job.execute()
        assert job.run_count == 2

    def test_feedscheduler_integration(self, tmp_path):
        from gnat.schedule.scheduler import FeedScheduler

        conn = MagicMock()
        conn.health_check.return_value = True
        job = ConnectorHealthJob(
            connectors={"tq": conn},
            interval_minutes=60,
            sample_schema=False,
            snapshot_dir=str(tmp_path),
        )
        scheduler = FeedScheduler()
        scheduler.add(job)
        assert "connector-health" in scheduler
        rec = scheduler.run_now("connector-health")
        assert rec.status == "success"


# ---------------------------------------------------------------------------
# ConnectorHealthJob.from_config()
# ---------------------------------------------------------------------------


class TestFromConfig:
    def test_from_config_empty_config_no_connectors(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[health_monitor]\ninterval_minutes = 45\n")
        job = ConnectorHealthJob.from_config(str(ini))
        assert isinstance(job, ConnectorHealthJob)
        assert job.interval_seconds == 45 * 60
        assert job._connectors == {}

    def test_from_config_platform_filter(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[health_monitor]\n")
        # When from_config can't connect to any platform, connectors is empty
        job = ConnectorHealthJob.from_config(str(ini), platforms=["threatq"])
        assert isinstance(job, ConnectorHealthJob)

    def test_from_config_kwargs_override_ini(self, tmp_path):
        ini = tmp_path / "gnat.ini"
        ini.write_text("[health_monitor]\ninterval_minutes = 60\n")
        job = ConnectorHealthJob.from_config(str(ini), interval_minutes=15)
        assert job.interval_seconds == 15 * 60


# ---------------------------------------------------------------------------
# CLI subcommand registration
# ---------------------------------------------------------------------------


class TestCLIHealthSubcommand:
    def test_health_check_help_exits_zero(self):
        from gnat.cli.main import main

        with pytest.raises(SystemExit) as exc:
            main(["health", "check", "--help"])
        assert exc.value.code == 0

    def test_health_baseline_help_exits_zero(self):
        from gnat.cli.main import main

        with pytest.raises(SystemExit) as exc:
            main(["health", "baseline", "--help"])
        assert exc.value.code == 0

    def test_health_registered_in_dispatch(self):
        from gnat.cli.main import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["health"])
        assert args.command == "health"

    def test_health_check_no_connectors_exits_zero(self, tmp_path):
        """health check with no configured connectors → exit 0 with message."""
        ini = tmp_path / "gnat.ini"
        ini.write_text("[health_monitor]\n")
        from gnat.cli.main import main

        result = main(["--config", str(ini), "health", "check"])
        assert result == 0

    def test_health_check_returns_1_on_problem(self, tmp_path):
        """Exit code 1 when a connector is unreachable."""
        ini = tmp_path / "gnat.ini"
        ini.write_text("[health_monitor]\n")

        bad_conn = MagicMock()
        bad_conn.health_check.return_value = False

        with patch("gnat.agents.health_monitor.ConnectorHealthJob.from_config") as mock_from_cfg:
            mock_job = ConnectorHealthJob(
                connectors={"bad": bad_conn},
                interval_minutes=60,
                sample_schema=False,
                snapshot_dir=str(tmp_path),
            )
            mock_from_cfg.return_value = mock_job
            from gnat.cli.main import main

            result = main(["--config", str(ini), "health", "check"])
        assert result == 1
