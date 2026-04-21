# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.schedule.loader
========================

Hybrid YAML + Python-module loader for :class:`FeedScheduler`.

Two loader flavors, freely mixable:

**1. Declarative YAML** (the 80% case — no Python code required)

    # gnat-jobs.yaml
    jobs:
      - id: urlhaus-hourly
        description: "Abuse.ch URLhaus malicious URL feed"
        reader:
          class: gnat.ingest.sources.readers.PlainTextReader
          args: { url: "https://urlhaus.abuse.ch/downloads/text/" }
        mapper:
          class: gnat.ingest.mappers.mappers.FlatIOCMapper
          args: { confidence: 80, tlp_marking: "white" }
        interval_seconds: 3600
        client: threatq
      - id: opencti-taxii
        reader:
          class: gnat.ingest.sources.readers.TAXIICollectionReader
          args:
            url: https://opencti.example.com/taxii2
            collection_id: apt-feed
        mapper:
          class: gnat.ingest.mappers.mappers.STIXPassthroughMapper
        cron: "0 */4 * * *"
        client: opencti

**2. Python module** (escape hatch for custom factory closures)

    # my_project/gnat_jobs.py
    from gnat.schedule import FeedJob
    from gnat.ingest.sources.readers import PlainTextReader

    def build_jobs(config) -> list[FeedJob]:
        return [
            FeedJob(
                job_id="secret-feed",
                reader_factory=lambda ctx: PlainTextReader(
                    url=get_secret_at_runtime(ctx),
                ),
                mapper_factory=lambda ctx: FlatIOCMapper(),
                interval_seconds=300,
            ),
        ]

    # Or for the simple case, expose a module-level ``jobs`` list / ``scheduler``.

**Hybrid** (both at once — jobs from both sources are merged):

    [schedule]
    jobs_file   = /etc/gnat/gnat-jobs.yaml
    jobs_module = my_project.gnat_jobs

The CLI (``gnat schedule list|run|crontab|validate|start``) resolves jobs
via :func:`load_scheduler` on every invocation so config changes take
effect on the next command.
"""

from __future__ import annotations

import configparser
import importlib
import logging
from pathlib import Path
from typing import Any, Callable

from gnat.schedule.job import FeedJob
from gnat.schedule.scheduler import FeedScheduler

logger = logging.getLogger(__name__)


class ScheduleLoaderError(Exception):
    """Raised when scheduler job definitions cannot be loaded."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def load_scheduler(
    config: configparser.ConfigParser | None = None,
    *,
    jobs_file: str | Path | None = None,
    jobs_module: str | None = None,
    skip_client_init: bool = False,
) -> FeedScheduler:
    """
    Build a :class:`FeedScheduler` from YAML and/or Python-module sources.

    Resolution order for each source:

    1. Explicit argument to this function (if not ``None``).
    2. ``[schedule] jobs_file`` / ``jobs_module`` key in ``config``.
    3. Omit that source entirely.

    At least one source must resolve to a non-empty list of jobs.

    Parameters
    ----------
    config : configparser.ConfigParser, optional
        Fully-parsed GNAT config. Used both to resolve the ``[schedule]``
        section and to construct :class:`~gnat.client.GNATClient`
        instances when a YAML job specifies ``client: <name>``.
    jobs_file : str | Path, optional
        Path to a YAML jobs file. Overrides the config value.
    jobs_module : str, optional
        Dotted Python module path (e.g. ``my_project.gnat_jobs``).
        Overrides the config value.
    skip_client_init : bool
        When ``True``, YAML jobs whose ``client:`` key references a
        connector will have ``client=None`` instead of a
        :class:`GNATClient` instance. Used by ``gnat schedule validate``
        to check YAML structure without touching credentials.

    Returns
    -------
    FeedScheduler
        A new scheduler with every parsed job added. The scheduler is
        **not** started; callers must invoke :meth:`FeedScheduler.start`.

    Raises
    ------
    ScheduleLoaderError
        If neither source is configured, the YAML file is missing or
        malformed, or a job entry has invalid fields.
    """
    scheduler = FeedScheduler()
    added = 0

    # Fall back to config-driven sources when the caller didn't pass them
    if config is not None and config.has_section("schedule"):
        section = config["schedule"]
        if jobs_file is None:
            jobs_file = section.get("jobs_file") or None
        if jobs_module is None:
            jobs_module = section.get("jobs_module") or None

    if not jobs_file and not jobs_module:
        raise ScheduleLoaderError(
            "No scheduler source configured. Set [schedule] jobs_file or "
            "jobs_module in gnat.ini, or pass --jobs-file / --jobs-module."
        )

    if jobs_file:
        path = Path(jobs_file).expanduser()
        if not path.exists():
            raise ScheduleLoaderError(f"Schedule YAML file not found: {path}")
        for job in _load_yaml_jobs(path, config=config, skip_client_init=skip_client_init):
            scheduler.add(job)
            added += 1

    if jobs_module:
        for job in _load_module_jobs(jobs_module, config=config):
            scheduler.add(job)
            added += 1

    if added == 0:
        logger.warning(
            "load_scheduler: loaded zero jobs from file=%r module=%r",
            jobs_file,
            jobs_module,
        )

    return scheduler


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def _load_yaml_jobs(
    path: Path,
    *,
    config: configparser.ConfigParser | None,
    skip_client_init: bool,
) -> list[FeedJob]:
    """Parse a YAML file into a list of :class:`FeedJob` instances."""
    try:
        import yaml
    except ImportError as exc:
        raise ScheduleLoaderError(
            "PyYAML is required to load YAML scheduler configs. "
            "Install with: pip install 'gnat[yaml]'"
        ) from exc

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScheduleLoaderError(f"Failed to parse {path}: {exc}") from exc

    if data is None:
        return []
    if not isinstance(data, dict) or "jobs" not in data:
        raise ScheduleLoaderError(f"{path}: expected a top-level 'jobs:' key mapping to a list")

    jobs_list = data.get("jobs") or []
    if not isinstance(jobs_list, list):
        raise ScheduleLoaderError(f"{path}: 'jobs' must be a list, got {type(jobs_list).__name__}")

    out: list[FeedJob] = []
    for idx, entry in enumerate(jobs_list):
        if not isinstance(entry, dict):
            raise ScheduleLoaderError(f"{path}: job #{idx} is not a mapping")
        try:
            out.append(
                _build_yaml_job(
                    entry,
                    config=config,
                    skip_client_init=skip_client_init,
                )
            )
        except ScheduleLoaderError:
            raise
        except Exception as exc:  # noqa: BLE001
            job_id = entry.get("id", "?")
            raise ScheduleLoaderError(f"{path}: job #{idx} ({job_id!r}): {exc}") from exc
    return out


def _build_yaml_job(
    entry: dict[str, Any],
    *,
    config: configparser.ConfigParser | None,
    skip_client_init: bool,
) -> FeedJob:
    """Build a single :class:`FeedJob` from one YAML job entry."""
    job_id = entry.get("id")
    if not job_id or not isinstance(job_id, str):
        raise ValueError("missing or invalid 'id' field")

    reader_spec = entry.get("reader")
    if not isinstance(reader_spec, dict) or "class" not in reader_spec:
        raise ValueError("missing or invalid 'reader' block (need 'class')")
    reader_class = _resolve_class(reader_spec["class"])
    reader_args = dict(reader_spec.get("args") or {})

    mapper_spec = entry.get("mapper")
    if not isinstance(mapper_spec, dict) or "class" not in mapper_spec:
        raise ValueError("missing or invalid 'mapper' block (need 'class')")
    mapper_class = _resolve_class(mapper_spec["class"])
    mapper_args = dict(mapper_spec.get("args") or {})

    interval_seconds = entry.get("interval_seconds")
    cron = entry.get("cron")
    if interval_seconds is None and not cron:
        raise ValueError("job must specify either 'interval_seconds' or 'cron'")
    if interval_seconds is not None and cron:
        raise ValueError("'interval_seconds' and 'cron' are mutually exclusive")

    # Optional GNATClient via [<name>] config section
    gnat_client = None
    client_name = entry.get("client")
    if client_name and not skip_client_init:
        gnat_client = _build_gnat_client(str(client_name), config=config)

    # Factories close over the already-resolved class objects so that
    # typos fail at load time, not at first execution.
    def reader_factory(ctx, _cls=reader_class, _args=reader_args):
        return _cls(**_args)

    def mapper_factory(ctx, _cls=mapper_class, _args=mapper_args):
        return _cls(**_args)

    # Filter kwargs the user might legitimately want on FeedJob
    kwargs: dict[str, Any] = {
        "job_id": job_id,
        "reader_factory": reader_factory,
        "mapper_factory": mapper_factory,
        "client": gnat_client,
    }
    if interval_seconds is not None:
        kwargs["interval_seconds"] = int(interval_seconds)
    if cron:
        kwargs["cron"] = str(cron)
    for optional in (
        "deduplicate",
        "confidence",
        "tlp_marking",
        "max_history",
        "overlap_policy",
        "enabled",
    ):
        if optional in entry:
            kwargs[optional] = entry[optional]
    if "dedup_key_fields" in entry:
        dkf = entry["dedup_key_fields"]
        if isinstance(dkf, list):
            kwargs["dedup_key_fields"] = list(dkf)

    return FeedJob(**kwargs)


def _resolve_class(dotted_path: str) -> type:
    """Import a class via its dotted module path (fails fast on typos)."""
    if not isinstance(dotted_path, str) or "." not in dotted_path:
        raise ValueError(
            f"'class' must be a dotted Python path like "
            f"'gnat.ingest.sources.readers.PlainTextReader'; "
            f"got {dotted_path!r}"
        )
    module_name, _, class_name = dotted_path.rpartition(".")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"cannot import module {module_name!r}: {exc}") from exc
    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        raise ValueError(f"{module_name!r} has no attribute {class_name!r}") from exc


def _build_gnat_client(
    target: str,
    *,
    config: configparser.ConfigParser | None,
) -> Any:
    """
    Build a :class:`~gnat.client.GNATClient` connected to ``target``.

    When a parsed ``config`` is provided, this function bypasses
    :class:`GNATConfig`'s file-based resolution and constructs the
    connector directly from the matching ``[<target>]`` section —
    keeping the loader consistent with whatever config the caller
    already resolved.

    Does **not** call ``authenticate()``; that happens lazily at first
    HTTP call via :class:`~gnat.clients.base.BaseClient`.
    """
    try:
        from gnat.client import GNATClient
        from gnat.clients import CLIENT_REGISTRY
    except ImportError as exc:
        raise ValueError(f"cannot import GNATClient to resolve client={target!r}: {exc}") from exc

    target_key = target.lower()

    # Fast path: build directly from a pre-parsed config to avoid
    # re-reading gnat.ini from disk (important for test isolation).
    if config is not None:
        if target_key not in CLIENT_REGISTRY:
            raise ValueError(f"client {target!r} is not registered in CLIENT_REGISTRY")
        if not config.has_section(target_key):
            raise ValueError(f"client {target!r}: no [{target_key}] section in the provided config")
        cfg_kwargs = dict(config[target_key])
        connector_cls = CLIENT_REGISTRY[target_key]
        # Mirror GNATClient.connect()'s construction path
        gcli = GNATClient.__new__(GNATClient)
        gcli.client = connector_cls(**cfg_kwargs)
        gcli.target = target_key
        return gcli

    # Slow path: let GNATClient resolve config from disk (GNAT_CONFIG
    # env var or ~/.gnat/config.ini). Useful for ad-hoc invocations
    # where the caller doesn't have a parsed config handy.
    try:
        gcli = GNATClient(config_path=None)
        gcli.connect(target=target_key)
    except KeyError as exc:
        raise ValueError(f"client {target!r} is not registered in CLIENT_REGISTRY: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"failed to build GNATClient for {target!r}: {exc}") from exc
    return gcli


# ---------------------------------------------------------------------------
# Python-module loader
# ---------------------------------------------------------------------------


def _load_module_jobs(
    module_name: str,
    *,
    config: configparser.ConfigParser | None,
) -> list[FeedJob]:
    """
    Import ``module_name`` and extract a list of :class:`FeedJob` objects.

    Resolution order (first match wins):

    1. Module-level ``build_jobs(config)`` callable returning
       ``list[FeedJob]`` or a single :class:`FeedScheduler`.
    2. Module-level ``scheduler: FeedScheduler`` attribute (its
       registered jobs are yielded).
    3. Module-level ``jobs: list[FeedJob]`` attribute.
    """
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ScheduleLoaderError(f"cannot import jobs module {module_name!r}: {exc}") from exc

    # Preference 1: build_jobs(config) factory function
    builder: Callable[..., Any] | None = getattr(module, "build_jobs", None)
    if callable(builder):
        try:
            try:
                result = builder(config)
            except TypeError:
                # builder() signature may not accept config
                result = builder()
        except Exception as exc:  # noqa: BLE001
            raise ScheduleLoaderError(f"{module_name}.build_jobs() raised: {exc}") from exc
        return _coerce_to_job_list(result, origin=f"{module_name}.build_jobs()")

    # Preference 2: module-level scheduler
    scheduler_attr = getattr(module, "scheduler", None)
    if isinstance(scheduler_attr, FeedScheduler):
        return list(iter(scheduler_attr))

    # Preference 3: module-level jobs list
    jobs_attr = getattr(module, "jobs", None)
    if jobs_attr is not None:
        return _coerce_to_job_list(jobs_attr, origin=f"{module_name}.jobs")

    raise ScheduleLoaderError(
        f"{module_name!r} must export one of: "
        f"build_jobs(config), scheduler: FeedScheduler, or jobs: list[FeedJob]"
    )


def _coerce_to_job_list(obj: Any, *, origin: str) -> list[FeedJob]:
    """Accept either a ``list[FeedJob]`` or a :class:`FeedScheduler`."""
    if isinstance(obj, FeedScheduler):
        return list(iter(obj))
    if isinstance(obj, list) and all(isinstance(j, FeedJob) for j in obj):
        return obj
    raise ScheduleLoaderError(
        f"{origin} must return list[FeedJob] or FeedScheduler; got {type(obj).__name__}"
    )
