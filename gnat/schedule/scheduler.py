"""
ctm_sak.schedule.scheduler
============================

:class:`FeedScheduler` — the threading engine that drives
:class:`~ctm_sak.schedule.job.FeedJob` instances.

Design
------
Each registered job gets its own :class:`threading.Thread` (daemon).
Threads sleep until the next trigger time, fire ``job.execute()``, then
sleep again.  The scheduler never shares threads between jobs, so a slow
feed cannot delay a fast one.

The scheduling loop uses a **drift-corrected** sleep: it computes the
*wall-clock time* of the next trigger and sleeps exactly that long, so
intervals stay accurate even when ``execute()`` takes non-zero time.

For cron expressions the next trigger is computed via ``croniter`` on each
wakeup, so DST transitions and irregular month lengths are handled correctly.

Persistence
-----------
The scheduler itself is stateless — it holds ``FeedJob`` objects in memory.
Run history is stored on the job (``job.history``).  To survive process
restarts you have two options:

1. **Re-register jobs at startup** (simplest).  Time-windowed readers use
   ``ctx.last_success_iso`` which starts as ``None`` on first run and
   accumulates naturally.

2. **Persist job history** to a :class:`~ctm_sak.context.store.FlatFileStore`
   or :class:`~ctm_sak.context.store.WorkspaceStore` by attaching an
   ``on_success`` callback that serialises ``record.as_dict()``.

External scheduler adapters
----------------------------
:meth:`FeedScheduler.to_apscheduler` and :meth:`FeedScheduler.to_celery_tasks`
export registered jobs to APScheduler ``BlockingScheduler`` / Celery tasks for
teams that already have those systems in place.

Usage::

    from ctm_sak.schedule import FeedJob, FeedScheduler
    from ctm_sak.ingest.sources.readers import PlainTextReader, TAXIICollectionReader
    from ctm_sak.ingest.mappers.mappers import FlatIOCMapper, STIXPassthroughMapper

    # Define jobs
    blocklist_job = FeedJob(
        job_id="blocklist-hourly",
        reader_factory=lambda ctx: PlainTextReader("https://blocklist.example.com/ips.txt"),
        mapper_factory=lambda ctx: FlatIOCMapper(confidence=70, tlp_marking="white"),
        interval_seconds=3600,
        client=tq_client,
        on_failure=lambda rec: logger.error("Blocklist feed failed: %s", rec.error),
    )

    taxii_job = FeedJob(
        job_id="taxii-daily",
        reader_factory=lambda ctx: TAXIICollectionReader(
            collection,
            added_after=ctx.last_success_iso or "2024-01-01T00:00:00Z",
        ),
        mapper_factory=lambda ctx: STIXPassthroughMapper(client=tq_client),
        interval_seconds=86400,
        client=tq_client,
    )

    # Run scheduler
    scheduler = FeedScheduler()
    scheduler.add(blocklist_job)
    scheduler.add(taxii_job)
    scheduler.start()            # returns immediately, jobs run in background
    # ... application keeps running ...
    scheduler.stop()             # graceful shutdown

    # Status check
    for status in scheduler.statuses():
        print(status)

    # Run all jobs once immediately (e.g. on startup backfill)
    scheduler.run_all_now()

    # Manual single-job trigger
    scheduler.run_now("blocklist-hourly")
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, TYPE_CHECKING

from ctm_sak.schedule.job import FeedJob, RunRecord, _utcnow

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class FeedScheduler:
    """
    Threading engine for :class:`~ctm_sak.schedule.job.FeedJob` instances.

    Parameters
    ----------
    max_workers : int
        Maximum number of concurrent job threads.  Default ``16``.
        Jobs that exceed this limit are queued.
    default_jitter_seconds : float
        Random jitter (0 to this value) added to each job's initial start
        time.  Spreads burst load when many jobs start simultaneously.
        Default ``0`` (no jitter).
    on_job_error : callable, optional
        Global fallback called when any job raises an unhandled exception.
        Signature: ``(job_id: str, exc: Exception) -> None``.

    Attributes
    ----------
    running : bool
        ``True`` after :meth:`start` is called and before :meth:`stop`.

    Examples
    --------
    ::

        scheduler = FeedScheduler()
        scheduler.add(blocklist_job)
        scheduler.add(taxii_job)
        scheduler.start()
        # ... runs in background threads ...
        scheduler.stop()

    As a context manager::

        with FeedScheduler() as sched:
            sched.add(my_job)
            time.sleep(3600)
    """

    def __init__(
        self,
        max_workers: int = 16,
        default_jitter_seconds: float = 0.0,
        on_job_error: Optional[Callable[[str, Exception], None]] = None,
    ):
        self._jobs:    Dict[str, FeedJob]    = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._max_workers = max_workers
        self._jitter      = default_jitter_seconds
        self._on_job_error = on_job_error
        self._lock = threading.Lock()
        self.running = False

    # ── Job management ─────────────────────────────────────────────────────

    def add(self, job: FeedJob) -> "FeedScheduler":
        """
        Register a job.  If the scheduler is already running, the job
        thread starts immediately.

        Parameters
        ----------
        job : FeedJob
            The job to add.

        Returns
        -------
        FeedScheduler
            ``self`` for chaining.

        Raises
        ------
        ValueError
            If a job with the same ``job_id`` is already registered.
        """
        with self._lock:
            if job.job_id in self._jobs:
                raise ValueError(
                    f"FeedScheduler: job {job.job_id!r} is already registered. "
                    "Use replace() to update it."
                )
            self._jobs[job.job_id] = job
            if self.running:
                self._start_job_thread(job)
        logger.info("FeedScheduler: registered %r (%s)", job.job_id,
                    f"every {job.interval_seconds}s" if job.interval_seconds
                    else f"cron={job.cron!r}")
        return self

    def remove(self, job_id: str) -> bool:
        """
        Unregister and stop a job.

        The running thread is signalled to stop and joined with a 5-second
        timeout.  Returns ``True`` if the job was found.
        """
        with self._lock:
            if job_id not in self._jobs:
                return False
            self._signal_stop(job_id)
            del self._jobs[job_id]
        logger.info("FeedScheduler: removed %r", job_id)
        return True

    def replace(self, job: FeedJob) -> "FeedScheduler":
        """
        Replace an existing job with a new definition (stops old thread,
        starts new one).  If the job_id is not registered, behaves like
        :meth:`add`.
        """
        with self._lock:
            if job.job_id in self._jobs:
                self._signal_stop(job.job_id)
            self._jobs[job.job_id] = job
            if self.running:
                self._start_job_thread(job)
        return self

    def get(self, job_id: str) -> FeedJob:
        """Return a registered job by id."""
        try:
            return self._jobs[job_id]
        except KeyError:
            raise KeyError(
                f"FeedScheduler: no job {job_id!r}. "
                f"Registered: {sorted(self._jobs.keys())}"
            )

    def __iter__(self) -> Iterator[FeedJob]:
        return iter(list(self._jobs.values()))

    def __len__(self) -> int:
        return len(self._jobs)

    def __contains__(self, job_id: str) -> bool:
        return job_id in self._jobs

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self, run_immediately: bool = False) -> "FeedScheduler":
        """
        Start the scheduler — launches background threads for all registered jobs.

        Parameters
        ----------
        run_immediately : bool
            If ``True``, execute all enabled jobs once before entering the
            normal schedule loop.  Useful for startup backfill.
            Default ``False``.

        Returns
        -------
        FeedScheduler
            ``self`` for chaining.
        """
        if self.running:
            logger.warning("FeedScheduler: already running")
            return self

        self.running = True
        for job in self._jobs.values():
            self._start_job_thread(job, run_immediately=run_immediately)

        n = len(self._jobs)
        logger.info("FeedScheduler: started with %d job%s", n, "s" if n != 1 else "")
        return self

    def stop(self, timeout: float = 10.0) -> None:
        """
        Stop all job threads gracefully.

        Signals every thread to stop at its next sleep checkpoint, then
        joins with *timeout* seconds per thread.

        Parameters
        ----------
        timeout : float
            Per-thread join timeout in seconds.  Default 10.
        """
        if not self.running:
            return
        self.running = False
        job_ids = list(self._stop_events.keys())
        for job_id in job_ids:
            self._signal_stop(job_id, join_timeout=timeout)
        logger.info("FeedScheduler: stopped")

    def __enter__(self) -> "FeedScheduler":
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()

    # ── Manual triggers ────────────────────────────────────────────────────

    def run_now(self, job_id: str) -> RunRecord:
        """
        Execute a specific job immediately in the calling thread (blocking).

        This bypasses the schedule — useful for manual backfills or testing.
        The run is recorded in the job's history and counts toward
        ``consecutive_failures``.

        Parameters
        ----------
        job_id : str
            Id of the job to run.

        Returns
        -------
        RunRecord
            The outcome of this run.
        """
        job = self.get(job_id)
        logger.info("FeedScheduler: manual trigger of %r", job_id)
        return job.execute(scheduled_at=_utcnow())

    def run_all_now(self, parallel: bool = False) -> Dict[str, RunRecord]:
        """
        Execute all registered enabled jobs immediately.

        Parameters
        ----------
        parallel : bool
            If ``True``, run all jobs concurrently in separate threads.
            If ``False`` (default), run them sequentially in the calling
            thread.

        Returns
        -------
        dict
            ``{job_id: RunRecord}`` for every job that was triggered.
        """
        jobs = [j for j in self._jobs.values() if j.enabled]
        results: Dict[str, RunRecord] = {}

        if not parallel:
            for job in jobs:
                results[job.job_id] = job.execute(scheduled_at=_utcnow())
            return results

        threads = []
        run_results: Dict[str, RunRecord] = {}
        lock = threading.Lock()

        def _run(j: FeedJob) -> None:
            rec = j.execute(scheduled_at=_utcnow())
            with lock:
                run_results[j.job_id] = rec

        for job in jobs:
            t = threading.Thread(target=_run, args=(job,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return run_results

    # ── Introspection ──────────────────────────────────────────────────────

    def statuses(self) -> List[dict]:
        """
        Return a list of status dicts for all registered jobs.

        Each dict is the output of :meth:`~ctm_sak.schedule.job.FeedJob.status_dict`.
        """
        return [job.status_dict() for job in self._jobs.values()]

    def healthy_jobs(self) -> List[FeedJob]:
        """Return all jobs whose last run was successful or have never run."""
        return [j for j in self._jobs.values() if j.is_healthy]

    def failing_jobs(self) -> List[FeedJob]:
        """Return all jobs with at least one consecutive failure."""
        return [j for j in self._jobs.values() if not j.is_healthy]

    def summary(self) -> dict:
        """Return a high-level health summary dict."""
        jobs       = list(self._jobs.values())
        n_healthy  = sum(1 for j in jobs if j.is_healthy)
        n_failing  = len(jobs) - n_healthy
        total_runs = sum(j.run_count for j in jobs)
        return {
            "running":     self.running,
            "total_jobs":  len(jobs),
            "healthy":     n_healthy,
            "failing":     n_failing,
            "total_runs":  total_runs,
        }

    # ── External scheduler adapters ────────────────────────────────────────

    def to_apscheduler(self) -> Any:
        """
        Export all registered jobs to an APScheduler ``BlockingScheduler``.

        Returns a configured (but not yet started) APScheduler instance.
        Callers call ``scheduler.start()`` when ready.

        Requires ``apscheduler``: ``pip install apscheduler``.

        Returns
        -------
        apscheduler.schedulers.blocking.BlockingScheduler

        Examples
        --------
        ::

            aps = feed_scheduler.to_apscheduler()
            aps.start()   # blocking
        """
        try:
            from apscheduler.schedulers.blocking import BlockingScheduler
            from apscheduler.triggers.interval import IntervalTrigger
            from apscheduler.triggers.cron import CronTrigger
        except ImportError:
            raise ImportError(
                "apscheduler is required: pip install apscheduler"
            )

        aps = BlockingScheduler()
        for job in self._jobs.values():
            if job.interval_seconds:
                trigger = IntervalTrigger(seconds=job.interval_seconds)
            else:
                trigger = CronTrigger.from_crontab(job.cron)
            aps.add_job(
                func=lambda j=job: j.execute(),
                trigger=trigger,
                id=job.job_id,
                name=job.job_id,
                max_instances=1,
                coalesce=True,
            )
        logger.info(
            "FeedScheduler: exported %d jobs to APScheduler", len(self._jobs)
        )
        return aps

    def to_celery_tasks(self, celery_app: Any) -> Dict[str, Any]:
        """
        Register all jobs as Celery periodic tasks.

        Requires a configured Celery app with ``beat_schedule`` support.
        Each job becomes a Celery task named ``ctm_sak.feed.<job_id>``.

        Parameters
        ----------
        celery_app : celery.Celery
            A configured Celery application instance.

        Returns
        -------
        dict
            ``{job_id: celery_task}`` mapping.

        Examples
        --------
        ::

            app = Celery("ctm_sak", broker="redis://localhost/0")
            tasks = scheduler.to_celery_tasks(app)
        """
        task_map: Dict[str, Any] = {}
        beat_schedule: Dict[str, dict] = {}

        for job in self._jobs.values():
            task_name = f"ctm_sak.feed.{job.job_id}"

            @celery_app.task(name=task_name, bind=True, max_retries=0)
            def _celery_task(self_task, _job_id=job.job_id):
                j = self._jobs.get(_job_id)
                if j:
                    return j.execute().as_dict()

            task_map[job.job_id] = _celery_task

            if job.interval_seconds:
                beat_schedule[task_name] = {
                    "task":     task_name,
                    "schedule": job.interval_seconds,
                }
            elif job.cron:
                try:
                    from celery.schedules import crontab as celery_crontab
                    minute, hour, day_of_month, month_of_year, day_of_week = (
                        job.cron.split() + ["*"] * 5
                    )[:5]
                    beat_schedule[task_name] = {
                        "task":     task_name,
                        "schedule": celery_crontab(
                            minute=minute,
                            hour=hour,
                            day_of_month=day_of_month,
                            month_of_year=month_of_year,
                            day_of_week=day_of_week,
                        ),
                    }
                except ImportError:
                    logger.warning("Celery not importable for cron schedule on %r",
                                   job.job_id)

        celery_app.conf.beat_schedule = {
            **getattr(celery_app.conf, "beat_schedule", {}),
            **beat_schedule,
        }
        return task_map

    def to_cron_lines(self, python_path: str = "python3",
                      script_path: str = "ctm_sak_run_job.py") -> str:
        """
        Generate crontab lines for all interval-based jobs.

        Cron expressions are passed through verbatim.  Interval-based jobs
        are converted to the closest cron-compatible interval (minute
        granularity).

        Parameters
        ----------
        python_path : str
            Path to the Python interpreter.  Default ``"python3"``.
        script_path : str
            Path to the runner script.  Default ``"ctm_sak_run_job.py"``.

        Returns
        -------
        str
            Crontab lines suitable for ``crontab -e``.
        """
        lines = [f"# CTM-SAK feed schedule — generated by FeedScheduler", ""]
        for job in self._jobs.values():
            if not job.enabled:
                continue
            if job.cron:
                expr = job.cron
            elif job.interval_seconds:
                minutes = max(1, job.interval_seconds // 60)
                if minutes < 60:
                    expr = f"*/{minutes} * * * *"
                elif minutes < 1440:
                    hours = minutes // 60
                    expr = f"0 */{hours} * * *"
                else:
                    days = minutes // 1440
                    expr = f"0 0 */{days} * *"
            else:
                continue
            lines.append(
                f"{expr}  {python_path} {script_path} --job {job.job_id}"
                f"  # {job.job_id}"
            )
        return "\n".join(lines)

    # ── Internal threading ─────────────────────────────────────────────────

    def _start_job_thread(
        self, job: FeedJob, run_immediately: bool = False
    ) -> None:
        """Spawn a daemon thread for one job."""
        stop_event = threading.Event()
        self._stop_events[job.job_id] = stop_event

        t = threading.Thread(
            target=self._job_loop,
            args=(job, stop_event, run_immediately),
            name=f"ctm-sak-feed-{job.job_id}",
            daemon=True,
        )
        self._threads[job.job_id] = t
        t.start()

    def _job_loop(
        self,
        job: FeedJob,
        stop_event: threading.Event,
        run_immediately: bool,
    ) -> None:
        """
        Main loop for one job thread.

        Sleeps until the next trigger time, fires ``job.execute()``,
        then sleeps again.  Uses drift-corrected timing: computes the
        *wall-clock time* of the next trigger so interval accuracy is
        maintained across variable-length runs.
        """
        import random as _random

        # Optional startup jitter
        if self._jitter > 0:
            jitter = _random.uniform(0, self._jitter)
            if stop_event.wait(jitter):
                return

        if run_immediately and job.enabled:
            try:
                job.execute(scheduled_at=_utcnow())
            except Exception as exc:  # noqa: BLE001
                logger.error("FeedScheduler job %r startup run failed: %s",
                             job.job_id, exc)
                if self._on_job_error:
                    self._on_job_error(job.job_id, exc)

        while not stop_event.is_set():
            # Compute next trigger
            next_trigger = self._next_trigger(job)
            if next_trigger is None:
                logger.warning(
                    "FeedScheduler: cannot determine next trigger for %r — stopping thread",
                    job.job_id,
                )
                break

            # Sleep in 1-second increments so we can respond to stop_event promptly
            now = time.monotonic()
            wake = now + max(0.0, (next_trigger - _utcnow()).total_seconds())
            while time.monotonic() < wake:
                if stop_event.wait(timeout=1.0):
                    return

            if stop_event.is_set():
                return

            if not job.enabled:
                logger.debug("FeedScheduler: job %r disabled, sleeping", job.job_id)
                continue

            try:
                job.execute(scheduled_at=next_trigger)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "FeedScheduler: unhandled exception in job %r: %s",
                    job.job_id, exc,
                )
                if self._on_job_error:
                    try:
                        self._on_job_error(job.job_id, exc)
                    except Exception:  # noqa: BLE001
                        pass

    def _next_trigger(self, job: FeedJob) -> Optional[datetime]:
        """
        Compute the *next* wall-clock trigger time for a job.

        For interval jobs: last run start + interval (or now if never run).
        For cron jobs: next fire time after now per the expression.
        """
        now = _utcnow()

        if job.interval_seconds:
            if job.history:
                # Drift-correct from last scheduled start, not actual start
                last_sched = job.history[-1].scheduled_at
                from datetime import timedelta
                candidate = last_sched + timedelta(seconds=job.interval_seconds)
                # If we're already past the candidate (e.g. after a long run), fire now
                return candidate if candidate > now else now
            return now  # first run: fire immediately

        if job.cron:
            try:
                from croniter import croniter  # type: ignore
                return croniter(job.cron, now).get_next(datetime)
            except ImportError:
                logger.error(
                    "FeedScheduler: cron job %r requires croniter: "
                    "pip install 'ctm-sak[schedule]'",
                    job.job_id,
                )
                return None

        return None

    def _signal_stop(self, job_id: str, join_timeout: float = 5.0) -> None:
        """Signal a job thread to stop and wait for it to finish."""
        event = self._stop_events.pop(job_id, None)
        if event:
            event.set()
        thread = self._threads.pop(job_id, None)
        if thread and thread.is_alive():
            thread.join(timeout=join_timeout)

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"FeedScheduler(jobs={sorted(self._jobs.keys())}, "
            f"running={self.running})"
        )
