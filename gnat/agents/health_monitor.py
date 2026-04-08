# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.health_monitor
===========================

Periodic connector health-checking and API schema drift detection.

:class:`ConnectorHealthJob` is a :class:`~gnat.schedule.job.FeedJob` subclass
that can be registered with :class:`~gnat.schedule.scheduler.FeedScheduler` to
run health checks on a recurring schedule.

Each run:

1. Calls ``health_check()`` on every registered connector.
2. For reachable connectors, optionally samples one object via
   ``list_objects()`` to fingerprint the API's response schema.
3. Compares the fingerprint against a stored baseline
   (:class:`SchemaSnapshot`) persisted as JSON in ``~/.gnat/snapshots/``.
4. If the fraction of changed fields exceeds ``drift_threshold`` (default
   20%), a :class:`DriftReport` is emitted and an optional Slack webhook
   alert is POSTed.

Quick start::

    from gnat.agents.health_monitor import ConnectorHealthJob
    from gnat.connectors.threatq.client import ThreatQClient
    from gnat.schedule import FeedScheduler

    health_job = ConnectorHealthJob(
        connectors={"threatq": ThreatQClient(...)},
        interval_minutes=60,
        alert_webhook="https://hooks.slack.com/services/...",
        drift_threshold=0.2,
    )
    scheduler = FeedScheduler()
    scheduler.add(health_job)
    scheduler.start()

Or using :meth:`ConnectorHealthJob.from_config` to auto-discover connectors::

    job = ConnectorHealthJob.from_config("~/.gnat/config.ini")
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import urllib3

from gnat.schedule.job import FeedJob, RunRecord, _utcnow

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Null reader / mapper stubs (satisfy FeedJob.__init__ without being called)
# ---------------------------------------------------------------------------


class _NullReader:
    """_NullReader implementation."""
    def read(self):
        """Read and yield records from the source."""
        return iter([])


class _NullMapper:
    """STIX translation helper for null objects."""
    def map(self, record):  # noqa: PLR0201
        """Map the input record to the output schema."""
        return None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DriftReport:
    """
    Schema drift detected between the current API response and the stored baseline.

    Attributes
    ----------
    connector : str
        Connector name.
    detected_at : str
        ISO 8601 timestamp when drift was detected.
    added_fields : list of str
        Dot-path field names present in the current schema but absent from baseline.
    removed_fields : list of str
        Dot-path field names present in baseline but absent from current schema.
    type_changes : dict
        ``{field: (old_type, new_type)}`` for fields whose Python type changed.
    drift_ratio : float
        Fraction of baseline fields that changed (added + removed + retyped).
    baseline_captured_at : str, optional
        ISO 8601 timestamp when the baseline snapshot was captured.
    """

    connector: str
    detected_at: str
    added_fields: list[str]
    removed_fields: list[str]
    type_changes: dict[str, tuple[str, str]]
    drift_ratio: float
    baseline_captured_at: str | None = None

    @property
    def is_significant(self) -> bool:
        """``True`` if any field was added, removed, or retyped."""
        return bool(self.added_fields or self.removed_fields or self.type_changes)

    def summary(self) -> str:
        """One-line human-readable drift summary."""
        parts = []
        if self.added_fields:
            parts.append(f"{len(self.added_fields)} added")
        if self.removed_fields:
            parts.append(f"{len(self.removed_fields)} removed")
        if self.type_changes:
            parts.append(f"{len(self.type_changes)} type changed")
        return f"Drift {self.drift_ratio:.0%}: " + (", ".join(parts) or "no changes")


@dataclass
class SchemaSnapshot:
    """
    Persisted baseline schema for one connector.

    Attributes
    ----------
    connector : str
        Connector name.
    captured_at : str
        ISO 8601 timestamp.
    fields : dict
        ``{dotted.field.path: python_type_name}`` fingerprint.
    sample_count : int
        Number of objects sampled to build the fingerprint.
    """

    connector: str
    captured_at: str
    fields: dict[str, str]
    sample_count: int = 1

    def to_dict(self) -> dict:
        """Convert this object to DICT format."""
        return {
            "connector": self.connector,
            "captured_at": self.captured_at,
            "fields": self.fields,
            "sample_count": self.sample_count,
        }

    @classmethod
    def from_dict(cls, d: dict) -> SchemaSnapshot:
        """Create an instance from DICT data."""
        return cls(
            connector=d["connector"],
            captured_at=d["captured_at"],
            fields=d.get("fields", {}),
            sample_count=d.get("sample_count", 1),
        )


@dataclass
class HealthCheckResult:
    """
    Outcome of a single connector health check within one :class:`HealthRun`.

    Attributes
    ----------
    connector : str
    reachable : bool
    response_ms : float
        Round-trip time of ``health_check()`` in milliseconds.
    error : str, optional
        Exception message when ``health_check()`` raised.
    drift : DriftReport, optional
        Schema drift detected this run, or ``None``.
    schema_sampled : bool
        Whether a schema sample was obtained this run.
    """

    connector: str
    reachable: bool
    response_ms: float
    error: str | None = None
    drift: DriftReport | None = None
    schema_sampled: bool = False

    @property
    def status(self) -> str:
        """``"ok"`` | ``"unreachable"`` | ``"drift"``."""
        if not self.reachable:
            return "unreachable"
        if self.drift and self.drift.is_significant:
            return "drift"
        return "ok"


@dataclass
class HealthRun:
    """
    Aggregated results from one :meth:`ConnectorHealthJob.execute` call.

    Attributes
    ----------
    run_at : str
        ISO 8601 start timestamp.
    checks : list of HealthCheckResult
    alerts_sent : int
        Number of webhook alerts successfully delivered.
    """

    run_at: str
    checks: list[HealthCheckResult] = field(default_factory=list)
    alerts_sent: int = 0

    @property
    def healthy_count(self) -> int:
        """Number of connectors that responded successfully this run."""
        return sum(1 for c in self.checks if c.reachable)

    @property
    def unhealthy_count(self) -> int:
        """Number of connectors that failed to respond this run."""
        return sum(1 for c in self.checks if not c.reachable)

    @property
    def drift_count(self) -> int:
        """Number of connectors with significant schema drift this run."""
        return sum(1 for c in self.checks if c.drift and c.drift.is_significant)


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class HealthMonitorConfig:
    """
    Runtime configuration for :class:`ConnectorHealthJob`.

    Read from the ``[health_monitor]`` INI section via :meth:`from_ini`.
    """

    enabled: bool = True
    interval_minutes: int = 60
    alert_webhook: str | None = None
    drift_threshold: float = 0.2
    snapshot_dir: str | None = None
    platforms: list[str] | None = None  # None = all configured

    @classmethod
    def from_ini(cls, config_path: str) -> HealthMonitorConfig:
        """Read ``[health_monitor]`` from an INI file."""
        import configparser

        cp = configparser.ConfigParser()
        cp.read(config_path)
        if "health_monitor" not in cp:
            return cls()
        sec = cp["health_monitor"]
        platforms_raw = (sec.get("platforms", fallback="") or "").strip()
        platforms: list[str] | None = None
        if platforms_raw and platforms_raw != "*":
            platforms = [p.strip() for p in platforms_raw.split(",") if p.strip()]
        return cls(
            enabled=sec.getboolean("enabled", fallback=True),
            interval_minutes=sec.getint("interval_minutes", fallback=60),
            alert_webhook=sec.get("alert_webhook", fallback=None) or None,
            drift_threshold=float(sec.get("drift_threshold", fallback="0.2")),
            snapshot_dir=sec.get("snapshot_dir", fallback=None) or None,
            platforms=platforms,
        )


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------


def _fingerprint_dict(
    obj: Any,
    prefix: str = "",
    max_depth: int = 4,
) -> dict[str, str]:
    """
    Flatten a nested dict to ``{dotted.path: python_type_name}``.

    Parameters
    ----------
    obj : any
        Object to fingerprint (usually a dict from an API response).
    prefix : str
        Dot-path prefix for recursive calls.
    max_depth : int
        Maximum recursion depth.  Default ``4``.

    Returns
    -------
    dict
        ``{field_path: type_name}`` mapping.
    """
    if not isinstance(obj, dict) or max_depth == 0:
        return {prefix: type(obj).__name__} if prefix else {}
    result: dict[str, str] = {}
    for k, v in obj.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict):
            result.update(_fingerprint_dict(v, key, max_depth - 1))
        elif isinstance(v, list):
            result[key] = "list"
            if v and isinstance(v[0], dict):
                result.update(_fingerprint_dict(v[0], f"{key}[]", max_depth - 1))
        else:
            result[key] = type(v).__name__
    return result


def _compute_drift(
    connector: str,
    baseline: SchemaSnapshot,
    current_fields: dict[str, str],
) -> DriftReport:
    """
    Compare *current_fields* against the stored *baseline* snapshot.

    Parameters
    ----------
    connector : str
    baseline : SchemaSnapshot
    current_fields : dict
        Latest ``{field: type}`` fingerprint.

    Returns
    -------
    DriftReport
    """
    old = set(baseline.fields.keys())
    new = set(current_fields.keys())
    added = sorted(new - old)
    removed = sorted(old - new)
    type_changes: dict[str, tuple[str, str]] = {
        k: (baseline.fields[k], current_fields[k])
        for k in (old & new)
        if baseline.fields[k] != current_fields[k]
    }
    total = max(len(old), 1)
    drift_ratio = (len(added) + len(removed) + len(type_changes)) / total
    return DriftReport(
        connector=connector,
        detected_at=_utcnow().isoformat(),
        added_fields=added,
        removed_fields=removed,
        type_changes=type_changes,
        drift_ratio=drift_ratio,
        baseline_captured_at=baseline.captured_at,
    )


def _try_sample_schema(connector: Any) -> dict[str, str] | None:
    """
    Attempt to obtain a schema fingerprint by calling ``list_objects()``
    with ``limit=1`` on common STIX types.

    Returns a fingerprint dict on success, or ``None`` if every attempt
    raises or returns an empty list.
    """
    for stix_type in (
        "indicator",
        "observed-data",
        "malware",
        "vulnerability",
        "threat-actor",
    ):
        try:
            results = connector.list_objects(stix_type, limit=1)
            if results:
                obj = results[0]
                if hasattr(obj, "to_dict"):
                    obj = obj.to_dict()
                if isinstance(obj, dict):
                    return _fingerprint_dict(obj)
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# Snapshot persistence
# ---------------------------------------------------------------------------


def _default_snapshot_dir() -> Path:
    """Internal helper for default snapshot dir."""
    return Path.home() / ".gnat" / "snapshots"


def load_snapshot(
    connector: str,
    snapshot_dir: str | None = None,
) -> SchemaSnapshot | None:
    """
    Load a stored schema snapshot for *connector*.

    Returns ``None`` if no baseline exists yet or the file cannot be read.
    """
    d = Path(snapshot_dir) if snapshot_dir else _default_snapshot_dir()
    path = d / f"{connector}.json"
    if not path.exists():
        return None
    try:
        return SchemaSnapshot.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        logger.warning("health_monitor: could not load snapshot for %r: %s", connector, exc)
        return None


def save_snapshot(
    connector: str,
    fields: dict[str, str],
    snapshot_dir: str | None = None,
) -> None:
    """
    Persist a schema snapshot for *connector*.

    Creates the snapshot directory if it does not exist.
    """
    d = Path(snapshot_dir) if snapshot_dir else _default_snapshot_dir()
    d.mkdir(parents=True, exist_ok=True)
    snapshot = SchemaSnapshot(
        connector=connector,
        captured_at=_utcnow().isoformat(),
        fields=fields,
    )
    path = d / f"{connector}.json"
    path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Alert delivery
# ---------------------------------------------------------------------------


def _post_slack_webhook(
    webhook_url: str,
    text: str,
    timeout: float = 10.0,
) -> bool:
    """
    POST a message to a Slack-compatible incoming webhook.

    Parameters
    ----------
    webhook_url : str
        Incoming webhook URL.
    text : str
        Plain text message body.
    timeout : float
        Connection and read timeout in seconds.  Default ``10``.

    Returns
    -------
    bool
        ``True`` if the server responded with HTTP 200.
    """
    http = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=timeout, read=timeout),
    )
    try:
        resp = http.request(
            "POST",
            webhook_url,
            body=json.dumps({"text": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        return resp.status == 200
    except Exception as exc:
        logger.warning("health_monitor: Slack webhook POST failed: %s", exc)
        return False


def _format_alert(run: HealthRun, drift_threshold: float = 0.0) -> str:
    """Format a :class:`HealthRun` as a Slack alert message."""
    ts = run.run_at[:19].replace("T", " ")
    lines = [f"*GNAT Connector Health Alert* — {ts} UTC"]
    for c in run.checks:
        if not c.reachable:
            msg = f"  :x: *{c.connector}* unreachable"
            if c.error:
                msg += f" — {c.error}"
            lines.append(msg)
        elif c.drift and c.drift.drift_ratio >= drift_threshold and c.drift.is_significant:
            lines.append(f"  :warning: *{c.connector}* schema drift — {c.drift.summary()}")
    if len(lines) == 1:
        lines.append("  All connectors healthy.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ConnectorHealthJob
# ---------------------------------------------------------------------------


class ConnectorHealthJob(FeedJob):
    """
    :class:`~gnat.schedule.job.FeedJob` subclass for connector health monitoring
    and schema drift detection.

    Parameters
    ----------
    connectors : dict
        Mapping of ``{connector_name: instantiated_connector}``.
    interval_minutes : int
        Check interval in minutes.  Default ``60``.
    cron : str, optional
        Cron expression; mutually exclusive with *interval_minutes*.
    alert_webhook : str, optional
        Slack-compatible incoming webhook URL for drift/unreachable alerts.
    drift_threshold : float
        Fraction of baseline fields that must change before triggering an
        alert and halting baseline updates.  Default ``0.2`` (20%).
    snapshot_dir : str, optional
        Directory for JSON snapshot files.  Defaults to ``~/.gnat/snapshots``.
    sample_schema : bool
        Perform schema sampling via ``list_objects()``.  Default ``True``.
    job_id : str
        Scheduler job id.  Default ``"connector-health"``.
    enabled : bool
        Default ``True``.
    """

    def __init__(
        self,
        connectors: dict[str, Any],
        interval_minutes: int = 60,
        cron: str | None = None,
        alert_webhook: str | None = None,
        drift_threshold: float = 0.2,
        snapshot_dir: str | None = None,
        sample_schema: bool = True,
        job_id: str = "connector-health",
        enabled: bool = True,
    ) -> None:
        """Initialize ConnectorHealthJob."""
        _stub_reader = lambda ctx: _NullReader()  # noqa: E731
        _stub_mapper = lambda ctx: _NullMapper()  # noqa: E731

        if cron:
            super().__init__(
                job_id=job_id,
                reader_factory=_stub_reader,
                mapper_factory=_stub_mapper,
                cron=cron,
                enabled=enabled,
            )
        else:
            super().__init__(
                job_id=job_id,
                reader_factory=_stub_reader,
                mapper_factory=_stub_mapper,
                interval_seconds=interval_minutes * 60,
                enabled=enabled,
            )

        self._connectors = dict(connectors)
        self._alert_webhook = alert_webhook
        self._drift_threshold = drift_threshold
        self._snapshot_dir = snapshot_dir
        self._sample_schema = sample_schema

    # ── execute() override ─────────────────────────────────────────────────

    def execute(self, scheduled_at: datetime | None = None) -> RunRecord:
        """
        Execute one health-check run synchronously.

        Returns
        -------
        RunRecord
            ``"success"`` when all connectors are healthy and no significant
            drift detected; ``"partial"`` when issues were found; ``"failed"``
            on an unhandled exception; ``"skipped"`` if the job is disabled.
        """
        if not self.enabled:
            return RunRecord(
                run_number=self.run_count,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(),
                finished_at=_utcnow(),
                status="skipped",
            )

        acquired = self._running_lock.acquire(blocking=False)
        if not acquired:
            logger.warning(
                "ConnectorHealthJob %r: previous run still active, skipping",
                self.job_id,
            )
            return RunRecord(
                run_number=self.run_count,
                scheduled_at=scheduled_at or _utcnow(),
                started_at=_utcnow(),
                finished_at=_utcnow(),
                status="skipped",
                error="skipped: previous run still active",
            )

        self.run_count += 1
        started_at = _utcnow()
        record = RunRecord(
            run_number=self.run_count,
            scheduled_at=scheduled_at or started_at,
            started_at=started_at,
        )

        try:
            run = self._run_health_checks()
            record.result = run  # type: ignore[assignment]
            record.finished_at = _utcnow()
            record.duration_seconds = (record.finished_at - started_at).total_seconds()

            problems = run.unhealthy_count + run.drift_count
            if problems == 0:
                record.status = "success"
                self.last_success_at = record.finished_at
                logger.info(
                    "ConnectorHealthJob %r: all %d connector(s) healthy",
                    self.job_id,
                    len(self._connectors),
                )
            else:
                record.status = "partial"
                logger.warning(
                    "ConnectorHealthJob %r: %d unreachable, %d schema drift(s)",
                    self.job_id,
                    run.unhealthy_count,
                    run.drift_count,
                )

            if problems and self._alert_webhook:
                alert_text = _format_alert(run, drift_threshold=self._drift_threshold)
                sent = _post_slack_webhook(self._alert_webhook, alert_text)
                run.alerts_sent = 1 if sent else 0

        except Exception as exc:  # noqa: BLE001
            record.finished_at = _utcnow()
            record.duration_seconds = (record.finished_at - started_at).total_seconds()
            record.status = "failed"
            record.error = str(exc)
            logger.error("ConnectorHealthJob %r: FAILED — %s", self.job_id, exc)

        finally:
            self._running_lock.release()

        self._append_history(record)
        return record

    # ── Core logic ─────────────────────────────────────────────────────────

    def _run_health_checks(self) -> HealthRun:
        """Check every connector and return a :class:`HealthRun`."""
        run = HealthRun(run_at=_utcnow().isoformat())

        for name, connector in self._connectors.items():
            t0 = time.monotonic()
            reachable = False
            err: str | None = None

            try:
                reachable = bool(connector.health_check())
            except Exception as exc:
                err = str(exc)
                logger.debug("ConnectorHealthJob: %r health_check() raised: %s", name, exc)
            elapsed_ms = (time.monotonic() - t0) * 1000.0

            drift: DriftReport | None = None
            schema_sampled = False

            if reachable and self._sample_schema:
                fingerprint = _try_sample_schema(connector)
                if fingerprint is not None:
                    schema_sampled = True
                    baseline = load_snapshot(name, self._snapshot_dir)
                    if baseline is None:
                        # First run for this connector — store as baseline
                        save_snapshot(name, fingerprint, self._snapshot_dir)
                    else:
                        drift = _compute_drift(name, baseline, fingerprint)
                        if drift.drift_ratio < self._drift_threshold:
                            # Within tolerance — silently roll forward the baseline
                            save_snapshot(name, fingerprint, self._snapshot_dir)
                        else:
                            logger.warning(
                                "ConnectorHealthJob: schema drift on %r — %.0f%% changed "
                                "(threshold %.0f%%)",
                                name,
                                drift.drift_ratio * 100,
                                self._drift_threshold * 100,
                            )

            result = HealthCheckResult(
                connector=name,
                reachable=reachable,
                response_ms=round(elapsed_ms, 1),
                error=err,
                drift=drift,
                schema_sampled=schema_sampled,
            )
            run.checks.append(result)
            logger.debug(
                "ConnectorHealthJob: %r — %s (%.0f ms)",
                name,
                result.status,
                elapsed_ms,
            )

        return run

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        config_path: str,
        platforms: list[str] | None = None,
        **kwargs: Any,
    ) -> ConnectorHealthJob:
        """
        Build a :class:`ConnectorHealthJob` from a GNAT config file.

        Reads ``[health_monitor]`` for defaults, then instantiates every
        connector that has a matching section in the INI file.

        Parameters
        ----------
        config_path : str
            Path to ``config.ini`` / ``gnat.ini``.
        platforms : list of str, optional
            Restrict to specific platform names.  When ``None`` all sections
            matching a registered connector are attempted.
        **kwargs
            Override any :class:`ConnectorHealthJob` constructor parameter.

        Returns
        -------
        ConnectorHealthJob
        """
        from gnat.client import GNATClient
        from gnat.clients import CLIENT_REGISTRY
        from gnat.config import GNATConfig

        cfg_obj = GNATConfig(config_path)
        hm_cfg = HealthMonitorConfig.from_ini(config_path)

        platform_filter = set(platforms or hm_cfg.platforms or [])

        connectors: dict[str, Any] = {}
        for section in cfg_obj.sections:
            name = section.lower()
            if name not in CLIENT_REGISTRY:
                continue
            if platform_filter and name not in platform_filter:
                continue
            try:
                sak = GNATClient(config_path=config_path).connect(name)
                connectors[name] = sak.client
            except Exception as exc:
                logger.debug("ConnectorHealthJob.from_config: skipping %r — %s", name, exc)

        merged: dict[str, Any] = {
            "interval_minutes": hm_cfg.interval_minutes,
            "alert_webhook": hm_cfg.alert_webhook,
            "drift_threshold": hm_cfg.drift_threshold,
            "snapshot_dir": hm_cfg.snapshot_dir,
        }
        merged.update(kwargs)

        return cls(connectors=connectors, **merged)

    def __repr__(self) -> str:  # pragma: no cover
        """Return unambiguous string representation."""
        sched = (
            f"every {self.interval_seconds}s" if self.interval_seconds else f"cron={self.cron!r}"
        )
        return (
            f"ConnectorHealthJob(id={self.job_id!r}, {sched}, "
            f"connectors={sorted(self._connectors.keys())}, "
            f"runs={self.run_count})"
        )
