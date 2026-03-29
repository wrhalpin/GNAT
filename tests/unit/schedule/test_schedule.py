"""
tests/unit/schedule/test_schedule.py
======================================

Unit tests for gnat.schedule — FeedJob and FeedScheduler.

Coverage:
- JobRunContext / RunRecord dataclasses
- FeedJob construction validation
- FeedJob.execute(): success, partial, failure, disabled, overlap skip
- FeedJob state: run_count, history, last_success_at, consecutive_failures, is_healthy
- FeedJob callbacks: on_success, on_failure, safe error handling
- FeedJob.next_run_at() for interval jobs
- FeedJob.status_dict()
- FeedJob.max_history rolling cap
- FeedScheduler: add, remove, replace, duplicate guard
- FeedScheduler: run_all_now (sequential + parallel)
- FeedScheduler: run_now, statuses, summary
- FeedScheduler: failing_jobs, healthy_jobs
- FeedScheduler: start/stop lifecycle with live threads
- FeedScheduler: context manager
- FeedScheduler: to_cron_lines
"""

from __future__ import annotations

import time
import threading
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from gnat.schedule import FeedJob, FeedScheduler, JobRunContext, RunRecord
from gnat.schedule.job import _utcnow
from gnat.ingest.base import IngestResult


# ===========================================================================
# Fixtures
# ===========================================================================

def _mock_result(total=5, written=5, errors=None):
    return IngestResult(
        source_id="test",
        total_records=total,
        written_objects=written,
        errors=errors or [],
    )

def _mock_reader(ctx):
    r = MagicMock()
    r.__enter__ = lambda s: s
    r.__exit__ = MagicMock(return_value=False)
    r.__iter__ = MagicMock(return_value=iter([]))
    return r

def _mock_mapper(ctx):
    m = MagicMock()
    m.map.return_value = iter([])
    return m

def _simple_job(job_id="test", interval=60, **kwargs):
    return FeedJob(
        job_id=job_id,
        reader_factory=_mock_reader,
        mapper_factory=_mock_mapper,
        interval_seconds=interval,
        **kwargs,
    )

PATCH_RUN = "gnat.ingest.pipeline.pipeline.IngestPipeline.run"


# ===========================================================================
# JobRunContext
# ===========================================================================

class TestJobRunContext:

    def test_defaults(self):
        ctx = JobRunContext(
            job_id="j", run_number=1, scheduled_at=_utcnow()
        )
        assert ctx.last_success_at is None
        assert ctx.last_success_iso is None
        assert ctx.last_result is None
        assert ctx.custom == {}

    def test_all_fields(self):
        now = _utcnow()
        ctx = JobRunContext(
            job_id="j", run_number=3, scheduled_at=now,
            last_success_at=now, last_success_iso=now.isoformat(),
            custom={"cursor": "abc"},
        )
        assert ctx.run_number == 3
        assert ctx.custom["cursor"] == "abc"


# ===========================================================================
# RunRecord
# ===========================================================================

class TestRunRecord:

    def test_as_dict_success(self):
        now = _utcnow()
        result = _mock_result(total=10, written=10)
        rec = RunRecord(
            run_number=1, scheduled_at=now, started_at=now,
            finished_at=now, status="success",
            result=result, duration_seconds=1.5,
        )
        d = rec.as_dict()
        assert d["status"] == "success"
        assert d["total_records"] == 10
        assert d["written_objects"] == 10
        assert d["errors"] == 0
        assert d["duration_seconds"] == 1.5

    def test_as_dict_failed(self):
        now = _utcnow()
        rec = RunRecord(
            run_number=1, scheduled_at=now, started_at=now,
            status="failed", error="boom", duration_seconds=0.1,
        )
        d = rec.as_dict()
        assert d["status"] == "failed"
        assert d["total_records"] == 0
        assert d["finished_at"] is None


# ===========================================================================
# FeedJob — construction
# ===========================================================================

class TestFeedJobConstruction:

    def test_requires_schedule(self):
        with pytest.raises(ValueError, match="interval_seconds or cron"):
            FeedJob("x", _mock_reader, _mock_mapper)

    def test_mutually_exclusive(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            FeedJob("x", _mock_reader, _mock_mapper,
                    interval_seconds=60, cron="* * * * *")

    def test_invalid_overlap_policy(self):
        with pytest.raises(ValueError, match="overlap_policy"):
            FeedJob("x", _mock_reader, _mock_mapper,
                    interval_seconds=60, overlap_policy="invalid")

    def test_valid_interval(self):
        job = _simple_job()
        assert job.job_id == "test"
        assert job.interval_seconds == 60
        assert job.enabled is True
        assert job.run_count == 0

    def test_valid_cron(self):
        job = FeedJob("c", _mock_reader, _mock_mapper, cron="0 * * * *")
        assert job.cron == "0 * * * *"
        assert job.interval_seconds is None


# ===========================================================================
# FeedJob — execute()
# ===========================================================================

class TestFeedJobExecute:

    def test_success_updates_state(self):
        job = _simple_job()
        with patch(PATCH_RUN, return_value=_mock_result()):
            rec = job.execute()
        assert rec.status == "success"
        assert job.run_count == 1
        assert job.last_success_at is not None
        assert job.is_healthy
        assert job.consecutive_failures == 0
        assert len(job.history) == 1

    def test_first_run_has_null_last_success(self):
        seen = []
        def capturing_reader(ctx):
            seen.append(ctx.last_success_iso)
            return _mock_reader(ctx)
        job = FeedJob("j", capturing_reader, _mock_mapper, interval_seconds=60)
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
        assert seen[0] is None

    def test_second_run_receives_last_success_iso(self):
        seen = []
        def capturing_reader(ctx):
            seen.append(ctx.last_success_iso)
            return _mock_reader(ctx)
        job = FeedJob("j", capturing_reader, _mock_mapper, interval_seconds=60)
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
            job.execute()
        assert seen[0] is None
        assert seen[1] is not None

    def test_failure_sets_status(self):
        job = FeedJob("f",
                      lambda ctx: (_ for _ in ()).throw(RuntimeError("boom")),
                      _mock_mapper, interval_seconds=60)
        rec = job.execute()
        assert rec.status == "failed"
        assert "boom" in rec.error
        assert not job.is_healthy
        assert job.consecutive_failures == 1
        assert job.last_success_at is None

    def test_partial_result_on_errors(self):
        job = _simple_job()
        with patch(PATCH_RUN, return_value=_mock_result(errors=["parse error"])):
            rec = job.execute()
        assert rec.status == "partial"

    def test_disabled_returns_skipped(self):
        job = _simple_job(enabled=False)
        rec = job.execute()
        assert rec.status == "skipped"
        assert job.run_count == 0

    def test_run_count_increments(self):
        job = _simple_job()
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
            job.execute()
        assert job.run_count == 2

    def test_duration_is_positive(self):
        job = _simple_job()
        with patch(PATCH_RUN, return_value=_mock_result()):
            rec = job.execute()
        assert rec.duration_seconds >= 0

    def test_on_success_callback(self):
        fired = []
        job = _simple_job(on_success=lambda rec: fired.append(rec.status))
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
        assert fired == ["success"]

    def test_on_failure_callback(self):
        fired = []
        job = FeedJob("f",
                      lambda ctx: (_ for _ in ()).throw(RuntimeError("x")),
                      _mock_mapper, interval_seconds=60,
                      on_failure=lambda rec: fired.append(rec.status))
        job.execute()
        assert fired == ["failed"]

    def test_on_partial_triggers_on_failure(self):
        fired = []
        job = _simple_job(on_failure=lambda rec: fired.append(rec.status))
        with patch(PATCH_RUN, return_value=_mock_result(errors=["e"])):
            job.execute()
        assert fired == ["partial"]

    def test_callback_exception_does_not_propagate(self):
        job = _simple_job(on_success=lambda rec: (_ for _ in ()).throw(RuntimeError("cb")))
        with patch(PATCH_RUN, return_value=_mock_result()):
            rec = job.execute()
        assert rec.status == "success"  # exception in callback is swallowed

    def test_scheduled_at_propagated(self):
        scheduled = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        job = _simple_job()
        with patch(PATCH_RUN, return_value=_mock_result()):
            rec = job.execute(scheduled_at=scheduled)
        assert rec.scheduled_at == scheduled

    def test_overlap_skip_policy(self):
        """A second execute() while one is running should return 'skipped'."""
        job = _simple_job(overlap_policy="skip")
        barrier = threading.Event()
        results = []

        def slow_reader(ctx):
            barrier.wait()
            return _mock_reader(ctx)

        job.reader_factory = slow_reader

        def run_first():
            with patch(PATCH_RUN, return_value=_mock_result()):
                results.append(job.execute())

        t = threading.Thread(target=run_first)
        t.start()
        time.sleep(0.05)  # let first run acquire lock

        # Second run should skip
        rec2 = job.execute()
        assert rec2.status == "skipped"
        barrier.set()
        t.join()


# ===========================================================================
# FeedJob — state properties
# ===========================================================================

class TestFeedJobState:

    def test_consecutive_failures_counts_correctly(self):
        job = FeedJob("f",
                      lambda ctx: (_ for _ in ()).throw(RuntimeError("x")),
                      _mock_mapper, interval_seconds=60)
        job.execute()
        job.execute()
        assert job.consecutive_failures == 2

    def test_consecutive_failures_resets_after_success(self):
        fail = True

        def toggling_reader(ctx):
            nonlocal fail
            if fail:
                raise RuntimeError("x")
            return _mock_reader(ctx)

        job = FeedJob("t", toggling_reader, _mock_mapper, interval_seconds=60)
        job.execute()
        assert job.consecutive_failures == 1
        fail = False
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
        assert job.consecutive_failures == 0

    def test_max_history_caps(self):
        job = _simple_job(max_history=3)
        with patch(PATCH_RUN, return_value=_mock_result()):
            for _ in range(7):
                job.execute()
        assert len(job.history) == 3
        assert job.history[0].run_number == 5  # oldest kept

    def test_last_run_property(self):
        job = _simple_job()
        assert job.last_run is None
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
        assert job.last_run is not None
        assert job.last_run.run_number == 1

    def test_next_run_at_interval(self):
        job = _simple_job(interval=120)
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
        nxt = job.next_run_at()
        assert nxt is not None
        delta = (nxt - _utcnow()).total_seconds()
        assert 0 < delta <= 122

    def test_next_run_at_disabled(self):
        job = _simple_job(enabled=False)
        assert job.next_run_at() is None

    def test_next_run_at_no_history_returns_now(self):
        job = _simple_job(interval=3600)
        nxt = job.next_run_at()
        assert nxt is not None
        assert (nxt - _utcnow()).total_seconds() < 2

    def test_status_dict_fields(self):
        job = _simple_job()
        with patch(PATCH_RUN, return_value=_mock_result()):
            job.execute()
        sd = job.status_dict()
        assert sd["job_id"] == "test"
        assert sd["is_healthy"] is True
        assert "every 60s" in sd["schedule"]
        assert sd["run_count"] == 1
        assert sd["last_run_status"] == "success"
        assert sd["last_success_at"] is not None


# ===========================================================================
# FeedScheduler — management
# ===========================================================================

class TestFeedSchedulerManagement:

    def test_add_job(self):
        s = FeedScheduler()
        s.add(_simple_job("j1"))
        assert "j1" in s and len(s) == 1

    def test_add_duplicate_raises(self):
        s = FeedScheduler()
        s.add(_simple_job("j1"))
        with pytest.raises(ValueError, match="already registered"):
            s.add(_simple_job("j1"))

    def test_remove_existing(self):
        s = FeedScheduler()
        s.add(_simple_job("j1"))
        assert s.remove("j1") is True
        assert "j1" not in s

    def test_remove_nonexistent_returns_false(self):
        s = FeedScheduler()
        assert s.remove("nope") is False

    def test_replace_updates_job(self):
        s = FeedScheduler()
        j_old = _simple_job("j1", interval=60)
        j_new = _simple_job("j1", interval=120)
        s.add(j_old)
        s.replace(j_new)
        assert s.get("j1").interval_seconds == 120

    def test_replace_new_job_adds_it(self):
        s = FeedScheduler()
        s.replace(_simple_job("new"))
        assert "new" in s

    def test_get_existing(self):
        s = FeedScheduler()
        j = _simple_job("j1")
        s.add(j)
        assert s.get("j1") is j

    def test_get_missing_raises(self):
        s = FeedScheduler()
        with pytest.raises(KeyError):
            s.get("missing")

    def test_contains(self):
        s = FeedScheduler()
        s.add(_simple_job("j1"))
        assert "j1" in s
        assert "nope" not in s

    def test_iter(self):
        s = FeedScheduler()
        s.add(_simple_job("a"))
        s.add(_simple_job("b"))
        job_ids = {j.job_id for j in s}
        assert job_ids == {"a", "b"}

    def test_len(self):
        s = FeedScheduler()
        s.add(_simple_job("a"))
        s.add(_simple_job("b"))
        assert len(s) == 2


# ===========================================================================
# FeedScheduler — execution
# ===========================================================================

class TestFeedSchedulerExecution:

    def test_run_now(self):
        s = FeedScheduler()
        s.add(_simple_job("j"))
        with patch(PATCH_RUN, return_value=_mock_result()):
            rec = s.run_now("j")
        assert rec.status == "success"

    def test_run_now_missing_raises(self):
        s = FeedScheduler()
        with pytest.raises(KeyError):
            s.run_now("nope")

    def test_run_all_now_sequential(self):
        s = FeedScheduler()
        s.add(_simple_job("a"))
        s.add(_simple_job("b"))
        with patch(PATCH_RUN, return_value=_mock_result()):
            res = s.run_all_now()
        assert set(res.keys()) == {"a", "b"}
        assert all(r.status == "success" for r in res.values())

    def test_run_all_now_parallel(self):
        s = FeedScheduler()
        s.add(_simple_job("a"))
        s.add(_simple_job("b"))
        with patch(PATCH_RUN, return_value=_mock_result()):
            res = s.run_all_now(parallel=True)
        assert set(res.keys()) == {"a", "b"}

    def test_run_all_now_skips_disabled(self):
        s = FeedScheduler()
        s.add(_simple_job("active"))
        s.add(_simple_job("inactive", enabled=False))
        with patch(PATCH_RUN, return_value=_mock_result()):
            res = s.run_all_now()
        # disabled job returns skipped
        assert res["inactive"].status == "skipped"

    def test_statuses(self):
        s = FeedScheduler()
        s.add(_simple_job("a"))
        s.add(_simple_job("b"))
        statuses = s.statuses()
        assert len(statuses) == 2
        assert all("job_id" in st for st in statuses)

    def test_summary_fields(self):
        s = FeedScheduler()
        s.add(_simple_job("ok"))
        sm = s.summary()
        assert sm["total_jobs"] == 1
        assert sm["running"] is False
        assert "healthy" in sm and "failing" in sm

    def test_healthy_and_failing_jobs(self):
        s = FeedScheduler()
        ok_job = _simple_job("ok")
        bad_job = FeedJob("bad",
                          lambda ctx: (_ for _ in ()).throw(RuntimeError("x")),
                          _mock_mapper, interval_seconds=60)
        s.add(ok_job)
        s.add(bad_job)
        with patch(PATCH_RUN, return_value=_mock_result()):
            s.run_now("ok")
        s.run_now("bad")
        assert ok_job  in s.healthy_jobs()
        assert bad_job in s.failing_jobs()


# ===========================================================================
# FeedScheduler — lifecycle
# ===========================================================================

class TestFeedSchedulerLifecycle:

    def test_start_stop(self):
        s = FeedScheduler()
        s.add(_simple_job("j", interval=3600))
        s.start()
        assert s.running
        assert "j" in s._threads
        s.stop()
        assert not s.running
        assert not s._threads

    def test_context_manager(self):
        with FeedScheduler() as s:
            s.add(_simple_job("j", interval=3600))
            assert s.running
        assert not s.running

    def test_double_start_is_noop(self):
        s = FeedScheduler()
        s.add(_simple_job("j", interval=3600))
        s.start()
        s.start()  # second call should not raise
        assert len(s._threads) == 1
        s.stop()

    def test_stop_before_start_is_noop(self):
        s = FeedScheduler()
        s.stop()  # should not raise

    def test_live_thread_fires_jobs(self):
        fired = []
        job = FeedJob(
            job_id="live",
            reader_factory=_mock_reader,
            mapper_factory=_mock_mapper,
            interval_seconds=1,
            on_success=lambda rec: fired.append(rec.run_number),
        )
        s = FeedScheduler()
        s.add(job)
        with patch(PATCH_RUN, return_value=_mock_result()):
            s.start(run_immediately=True)
            time.sleep(2.8)
            s.stop()
        assert len(fired) >= 2

    def test_threads_cleaned_up_after_stop(self):
        s = FeedScheduler()
        s.add(_simple_job("j", interval=1))
        with patch(PATCH_RUN, return_value=_mock_result()):
            s.start()
            time.sleep(0.1)
            s.stop()
        assert not s._threads

    def test_add_job_while_running_starts_thread(self):
        s = FeedScheduler()
        s.add(_simple_job("j1", interval=3600))
        s.start()
        s.add(_simple_job("j2", interval=3600))
        assert "j2" in s._threads
        s.stop()

    def test_remove_job_while_running_stops_thread(self):
        s = FeedScheduler()
        s.add(_simple_job("j1", interval=3600))
        s.start()
        s.remove("j1")
        assert "j1" not in s._threads
        s.stop()


# ===========================================================================
# FeedScheduler — adapters
# ===========================================================================

class TestFeedSchedulerAdapters:

    def test_to_cron_lines_interval(self):
        s = FeedScheduler()
        s.add(FeedJob("hourly", lambda c: None, lambda c: None, interval_seconds=3600))
        s.add(FeedJob("daily",  lambda c: None, lambda c: None, interval_seconds=86400))
        lines = s.to_cron_lines()
        assert "hourly" in lines
        assert "daily" in lines
        assert "# GNAT" in lines

    def test_to_cron_lines_skips_disabled(self):
        s = FeedScheduler()
        s.add(FeedJob("off", lambda c: None, lambda c: None,
                      interval_seconds=60, enabled=False))
        lines = s.to_cron_lines()
        assert "off" not in lines

    def test_to_cron_lines_cron_expr(self):
        s = FeedScheduler()
        s.add(FeedJob("morning", lambda c: None, lambda c: None, cron="0 7 * * *"))
        lines = s.to_cron_lines()
        assert "morning" in lines
        assert "0 7 * * *" in lines

    def test_to_apscheduler_requires_apscheduler(self):
        s = FeedScheduler()
        s.add(_simple_job("j"))
        try:
            import apscheduler  # noqa: F401
            aps = s.to_apscheduler()
            assert aps is not None
        except ImportError:
            with pytest.raises(ImportError, match="apscheduler"):
                s.to_apscheduler()
