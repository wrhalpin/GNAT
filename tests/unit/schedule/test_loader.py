# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/schedule/test_loader.py
======================================

Unit tests for :func:`gnat.schedule.loader.load_scheduler` — the hybrid
YAML + Python-module loader backing the ``gnat schedule`` CLI.

Coverage:
- YAML loader: happy path, interval vs cron, multiple jobs, optional fields
- YAML loader: error paths (missing file, bad YAML, wrong top-level key,
  missing reader/mapper, bad class path, both interval and cron, neither)
- Python module loader: build_jobs(), build_jobs(config), module.scheduler,
  module.jobs; error paths (missing module, wrong exports)
- Hybrid: both sources merged
- Client resolution: skip_client_init=True, eager from parsed config,
  unknown target
- Config fallback: reading jobs_file / jobs_module from [schedule] section
"""

from __future__ import annotations

import configparser
import sys
import textwrap
from pathlib import Path

import pytest

from gnat.schedule import ScheduleLoaderError, load_scheduler

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_yaml(tmp_path):
    """Return a helper that writes YAML text to a tmp file and returns its path."""
    def _write(text: str) -> Path:
        path = tmp_path / "jobs.yaml"
        path.write_text(textwrap.dedent(text))
        return path

    return _write


@pytest.fixture
def tmp_module(tmp_path, monkeypatch):
    """Return a helper that writes a Python module to sys.path."""
    monkeypatch.syspath_prepend(str(tmp_path))

    def _write(module_name: str, body: str) -> str:
        (tmp_path / f"{module_name}.py").write_text(textwrap.dedent(body))
        # Drop any cached version
        sys.modules.pop(module_name, None)
        return module_name

    return _write


# ---------------------------------------------------------------------------
# YAML — happy paths
# ---------------------------------------------------------------------------


class TestYamlLoaderHappyPath:
    def test_single_interval_job(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: blocklist
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://example.com/ips.txt" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                  args: { confidence: 70 }
                interval_seconds: 3600
            """
        )
        sched = load_scheduler(jobs_file=path)
        assert len(sched) == 1
        job = sched.get("blocklist")
        assert job.job_id == "blocklist"
        assert job.interval_seconds == 3600
        assert job.cron is None
        assert job.enabled is True

    def test_single_cron_job(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: four-hourly
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                cron: "0 */4 * * *"
            """
        )
        sched = load_scheduler(jobs_file=path)
        job = sched.get("four-hourly")
        assert job.cron == "0 */4 * * *"
        assert job.interval_seconds is None

    def test_multiple_jobs(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: a
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/a" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
              - id: b
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/b" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 120
            """
        )
        sched = load_scheduler(jobs_file=path)
        assert len(sched) == 2
        assert {j.job_id for j in sched} == {"a", "b"}

    def test_optional_fields_passed_through(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: verbose
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
                enabled: false
                confidence: 85
                tlp_marking: green
                deduplicate: false
                overlap_policy: queue
                max_history: 500
            """
        )
        sched = load_scheduler(jobs_file=path)
        job = sched.get("verbose")
        assert job.enabled is False
        assert job.confidence == 85
        assert job.tlp_marking == "green"
        assert job.deduplicate is False
        assert job.overlap_policy == "queue"
        assert job.max_history == 500

    def test_empty_yaml_returns_empty_scheduler(self, tmp_yaml, caplog):
        # A YAML file with just a top-level 'jobs: []' is legal.
        path = tmp_yaml("jobs: []")
        sched = load_scheduler(jobs_file=path)
        assert len(sched) == 0

    def test_reader_factory_produces_real_reader(self, tmp_yaml):
        """Confirm the resolved class is actually instantiable from the factory."""
        path = tmp_yaml(
            """
            jobs:
              - id: t
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://example.com/x.txt" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                  args: { confidence: 70 }
                interval_seconds: 60
            """
        )
        sched = load_scheduler(jobs_file=path)
        job = sched.get("t")
        from gnat.ingest.mappers.mappers import FlatIOCMapper
        from gnat.ingest.sources.readers import PlainTextReader

        ctx = None  # factory doesn't use ctx for these classes
        reader = job.reader_factory(ctx)
        mapper = job.mapper_factory(ctx)
        assert isinstance(reader, PlainTextReader)
        assert isinstance(mapper, FlatIOCMapper)


# ---------------------------------------------------------------------------
# YAML — error paths
# ---------------------------------------------------------------------------


class TestYamlLoaderErrors:
    def test_missing_file_raises(self):
        with pytest.raises(ScheduleLoaderError, match="not found"):
            load_scheduler(jobs_file="/nope/does/not/exist.yaml")

    def test_wrong_top_level_key(self, tmp_yaml):
        path = tmp_yaml("not_jobs: []")
        with pytest.raises(ScheduleLoaderError, match="'jobs:' key"):
            load_scheduler(jobs_file=path)

    def test_jobs_not_a_list(self, tmp_yaml):
        path = tmp_yaml("jobs: 'string-not-list'")
        with pytest.raises(ScheduleLoaderError, match="'jobs' must be a list"):
            load_scheduler(jobs_file=path)

    def test_missing_reader_block(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                mapper: { class: gnat.ingest.mappers.mappers.FlatIOCMapper }
                interval_seconds: 60
            """
        )
        with pytest.raises(ScheduleLoaderError, match="reader"):
            load_scheduler(jobs_file=path)

    def test_missing_mapper_block(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                interval_seconds: 60
            """
        )
        with pytest.raises(ScheduleLoaderError, match="mapper"):
            load_scheduler(jobs_file=path)

    def test_missing_id(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
            """
        )
        with pytest.raises(ScheduleLoaderError, match="id"):
            load_scheduler(jobs_file=path)

    def test_bad_class_path(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                reader:
                  class: gnat.does.not.exist.ReaderClass
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
            """
        )
        with pytest.raises(ScheduleLoaderError, match="cannot import"):
            load_scheduler(jobs_file=path)

    def test_class_not_in_module(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                reader:
                  class: gnat.ingest.sources.readers.NonExistentReader
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
            """
        )
        with pytest.raises(ScheduleLoaderError, match="no attribute"):
            load_scheduler(jobs_file=path)

    def test_neither_interval_nor_cron(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
            """
        )
        with pytest.raises(ScheduleLoaderError, match="interval_seconds.*cron"):
            load_scheduler(jobs_file=path)

    def test_both_interval_and_cron(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
                cron: "* * * * *"
            """
        )
        with pytest.raises(ScheduleLoaderError, match="mutually exclusive"):
            load_scheduler(jobs_file=path)

    def test_malformed_yaml(self, tmp_yaml):
        path = tmp_yaml("jobs:\n  - id: [unclosed")
        with pytest.raises(ScheduleLoaderError, match="parse"):
            load_scheduler(jobs_file=path)

    def test_class_must_be_dotted_path(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad
                reader: { class: NotDotted }
                mapper: { class: gnat.ingest.mappers.mappers.FlatIOCMapper }
                interval_seconds: 60
            """
        )
        with pytest.raises(ScheduleLoaderError, match="dotted Python path"):
            load_scheduler(jobs_file=path)


# ---------------------------------------------------------------------------
# Python module loader
# ---------------------------------------------------------------------------


class TestModuleLoader:
    def test_build_jobs_with_config_arg(self, tmp_module):
        tmp_module(
            "gnat_test_mod_a",
            """
            from gnat.schedule import FeedJob
            from gnat.ingest.sources.readers import PlainTextReader
            from gnat.ingest.mappers.mappers import FlatIOCMapper

            def build_jobs(config):
                return [
                    FeedJob(
                        job_id="from-module",
                        reader_factory=lambda ctx: PlainTextReader(source="https://x/y"),
                        mapper_factory=lambda ctx: FlatIOCMapper(),
                        interval_seconds=60,
                    ),
                ]
            """,
        )
        sched = load_scheduler(jobs_module="gnat_test_mod_a")
        assert len(sched) == 1
        assert sched.get("from-module").job_id == "from-module"

    def test_build_jobs_no_args(self, tmp_module):
        tmp_module(
            "gnat_test_mod_b",
            """
            from gnat.schedule import FeedJob
            from gnat.ingest.sources.readers import PlainTextReader
            from gnat.ingest.mappers.mappers import FlatIOCMapper

            def build_jobs():
                return [
                    FeedJob(
                        job_id="no-args",
                        reader_factory=lambda ctx: PlainTextReader(source="https://x/y"),
                        mapper_factory=lambda ctx: FlatIOCMapper(),
                        interval_seconds=60,
                    ),
                ]
            """,
        )
        sched = load_scheduler(jobs_module="gnat_test_mod_b")
        assert len(sched) == 1

    def test_module_level_scheduler(self, tmp_module):
        tmp_module(
            "gnat_test_mod_c",
            """
            from gnat.schedule import FeedJob, FeedScheduler
            from gnat.ingest.sources.readers import PlainTextReader
            from gnat.ingest.mappers.mappers import FlatIOCMapper

            scheduler = FeedScheduler()
            scheduler.add(FeedJob(
                job_id="via-scheduler",
                reader_factory=lambda ctx: PlainTextReader(source="https://x/y"),
                mapper_factory=lambda ctx: FlatIOCMapper(),
                interval_seconds=60,
            ))
            """,
        )
        sched = load_scheduler(jobs_module="gnat_test_mod_c")
        assert len(sched) == 1
        assert sched.get("via-scheduler") is not None

    def test_module_level_jobs_list(self, tmp_module):
        tmp_module(
            "gnat_test_mod_d",
            """
            from gnat.schedule import FeedJob
            from gnat.ingest.sources.readers import PlainTextReader
            from gnat.ingest.mappers.mappers import FlatIOCMapper

            jobs = [
                FeedJob(
                    job_id="via-jobs-list",
                    reader_factory=lambda ctx: PlainTextReader(source="https://x/y"),
                    mapper_factory=lambda ctx: FlatIOCMapper(),
                    interval_seconds=60,
                ),
            ]
            """,
        )
        sched = load_scheduler(jobs_module="gnat_test_mod_d")
        assert sched.get("via-jobs-list") is not None

    def test_missing_module_raises(self):
        with pytest.raises(ScheduleLoaderError, match="cannot import"):
            load_scheduler(jobs_module="definitely_not_installed_xyz")

    def test_module_with_no_exports_raises(self, tmp_module):
        tmp_module("gnat_test_mod_empty", "# no exports\n")
        with pytest.raises(ScheduleLoaderError, match="must export"):
            load_scheduler(jobs_module="gnat_test_mod_empty")

    def test_build_jobs_returns_wrong_type(self, tmp_module):
        tmp_module(
            "gnat_test_mod_wrong",
            """
            def build_jobs(config):
                return "not a list"
            """,
        )
        with pytest.raises(ScheduleLoaderError, match="list\\[FeedJob\\]"):
            load_scheduler(jobs_module="gnat_test_mod_wrong")

    def test_build_jobs_raises_wraps_cleanly(self, tmp_module):
        tmp_module(
            "gnat_test_mod_raises",
            """
            def build_jobs(config):
                raise RuntimeError("oops")
            """,
        )
        with pytest.raises(ScheduleLoaderError, match="oops"):
            load_scheduler(jobs_module="gnat_test_mod_raises")


# ---------------------------------------------------------------------------
# Hybrid + config fallback
# ---------------------------------------------------------------------------


class TestHybridAndConfig:
    def test_both_sources_merge(self, tmp_yaml, tmp_module):
        tmp_module(
            "gnat_test_hybrid",
            """
            from gnat.schedule import FeedJob
            from gnat.ingest.sources.readers import PlainTextReader
            from gnat.ingest.mappers.mappers import FlatIOCMapper

            def build_jobs(config):
                return [
                    FeedJob(
                        job_id="from-module",
                        reader_factory=lambda ctx: PlainTextReader(source="https://x/m"),
                        mapper_factory=lambda ctx: FlatIOCMapper(),
                        interval_seconds=60,
                    ),
                ]
            """,
        )
        path = tmp_yaml(
            """
            jobs:
              - id: from-yaml
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
            """
        )
        sched = load_scheduler(
            jobs_file=path, jobs_module="gnat_test_hybrid"
        )
        assert len(sched) == 2
        assert {j.job_id for j in sched} == {"from-module", "from-yaml"}

    def test_no_source_raises(self):
        with pytest.raises(ScheduleLoaderError, match="No scheduler source"):
            load_scheduler()

    def test_no_source_with_empty_config_raises(self):
        cfg = configparser.ConfigParser()
        cfg.read_string("[DEFAULT]\n")
        with pytest.raises(ScheduleLoaderError, match="No scheduler source"):
            load_scheduler(config=cfg)

    def test_config_supplies_jobs_file(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: from-config
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
            """
        )
        cfg = configparser.ConfigParser()
        cfg["schedule"] = {"jobs_file": str(path)}
        sched = load_scheduler(config=cfg)
        assert sched.get("from-config") is not None

    def test_explicit_args_override_config(self, tmp_yaml, tmp_path):
        path_a = tmp_yaml(
            """
            jobs:
              - id: from-override
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/a" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
            """
        )
        # Config says a different non-existent file; explicit arg should win
        cfg = configparser.ConfigParser()
        cfg["schedule"] = {"jobs_file": "/does/not/exist.yaml"}
        sched = load_scheduler(config=cfg, jobs_file=path_a)
        assert sched.get("from-override") is not None


# ---------------------------------------------------------------------------
# Client resolution
# ---------------------------------------------------------------------------


class TestClientResolution:
    def test_skip_client_init_ignores_client_key(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: with-client
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
                client: threatq
            """
        )
        sched = load_scheduler(jobs_file=path, skip_client_init=True)
        job = sched.get("with-client")
        assert job.client is None

    def test_eager_client_from_parsed_config(self, tmp_yaml):
        """
        With a ConfigParser that has a [cisa] section, the loader should
        build a GNATClient without touching the network. CISA is a
        public-feed connector with no required credentials.
        """
        path = tmp_yaml(
            """
            jobs:
              - id: with-cisa
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
                client: cisa
            """
        )
        cfg = configparser.ConfigParser()
        cfg["cisa"] = {"host": "https://cisa.example.com"}
        sched = load_scheduler(jobs_file=path, config=cfg)
        job = sched.get("with-cisa")
        assert job.client is not None
        # It's a GNATClient-like wrapper; the underlying connector is at .client
        assert hasattr(job.client, "client")

    def test_unknown_client_target_raises(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: bad-client
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
                client: made_up_vendor_zzz
            """
        )
        cfg = configparser.ConfigParser()
        cfg["made_up_vendor_zzz"] = {"host": "https://x"}
        with pytest.raises(ScheduleLoaderError, match="CLIENT_REGISTRY"):
            load_scheduler(jobs_file=path, config=cfg)

    def test_client_without_config_section_raises(self, tmp_yaml):
        path = tmp_yaml(
            """
            jobs:
              - id: missing-section
                reader:
                  class: gnat.ingest.sources.readers.PlainTextReader
                  args: { source: "https://x/y" }
                mapper:
                  class: gnat.ingest.mappers.mappers.FlatIOCMapper
                interval_seconds: 60
                client: cisa
            """
        )
        cfg = configparser.ConfigParser()  # no [cisa] section
        with pytest.raises(ScheduleLoaderError, match="no \\[cisa\\] section"):
            load_scheduler(jobs_file=path, config=cfg)
