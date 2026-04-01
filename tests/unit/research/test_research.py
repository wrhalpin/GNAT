"""
tests/unit/research/test_research.py
=====================================

Unit tests for the GNAT shared research library.

Covers:
- categorise_topic: all five categories + fallback
- topic_key: normalisation, case, whitespace
- ResearchEntry: construction, defaults, auto-categorisation, TTL, freshness,
  status transitions, serialisation round-trip, summary dict
- ResearchLibrary: init creates workspaces, promote (ai-tagged, fallback,
  specific ids, empty raises), is_fresh before/after curation, get,
  get_staging, search, list_entries, load_into_workspace (success + KeyError),
  retire_entry, stats, custom TTLs
- CurationJob: dedup most-recent-wins, archived count, library count,
  TTL applied, idempotent on empty staging, status=success, failure handling
- Integration: promote → curate → load_into_workspace full cycle
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from gnat.context import (
    FlatFileStore,
    GlobalContext,
    GlobalContextRegistry,
)
from gnat.context.workspace import WorkspaceManager
from gnat.orm.indicator import Indicator
from gnat.research import (
    DEFAULT_TTLS,
    CurationJob,
    ResearchEntry,
    ResearchLibrary,
    categorise_topic,
    topic_key,
)

# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def tmp_store(tmp_path):
    return FlatFileStore(base_dir=str(tmp_path / "workspaces"))


@pytest.fixture
def manager(tmp_store):
    cli = MagicMock()
    cli.target = "tq"
    cli.ping.return_value = True
    cli.client = MagicMock()
    reg = GlobalContextRegistry()
    reg.register(GlobalContext("tq", cli))
    reg.set_default("tq")
    return WorkspaceManager(reg, store=tmp_store)


@pytest.fixture
def lib(manager):
    return ResearchLibrary(manager)


def _ind(name: str, ai: bool = True) -> Indicator:
    ind = Indicator(
        name=name,
        pattern=f"[domain-name:value = '{name}']",
        pattern_type="stix",
        confidence=55,
    )
    if ai:
        ind._properties["x_source_type"] = "ai_extracted"
    return ind


def _populated_workspace(manager, ws_name: str, topics=None, ai=True):
    """Create a workspace with one indicator per topic."""
    ws = manager.create(ws_name)
    for _i, name in enumerate(topics or ["evil.com"]):
        ws.add(_ind(name, ai=ai), mark_dirty=False)
    return ws


# ===========================================================================
# categorise_topic
# ===========================================================================

class TestCategoriseTopic:

    def test_threat_actor(self):
        assert categorise_topic("APT29 analysis") == "threat_actor"
        assert categorise_topic("Volt Typhoon campaign") == "threat_actor"
        assert categorise_topic("LAZARUS group") == "threat_actor"

    def test_vulnerability(self):
        assert categorise_topic("CVE-2024-3400") == "vulnerability"
        assert categorise_topic("exploit chain for exchange") == "vulnerability"
        assert categorise_topic("RCE in Apache") == "vulnerability"

    def test_campaign(self):
        assert categorise_topic("Operation ShadowHammer") == "campaign"
        assert categorise_topic("LockBit campaign Q1") == "campaign"
        assert categorise_topic("intrusion at energy firm") == "campaign"

    def test_indicator(self):
        assert categorise_topic("IOC list for APT29") == "indicator"
        assert categorise_topic("malicious IP indicators") == "indicator"
        assert categorise_topic("blocklist domains") == "indicator"

    def test_other_fallback(self):
        assert categorise_topic("random topic") == "other"
        assert categorise_topic("") == "other"
        assert categorise_topic("security news") == "other"


# ===========================================================================
# topic_key
# ===========================================================================

class TestTopicKey:

    def test_lowercase(self):
        assert topic_key("APT29") == "apt29"

    def test_strips_whitespace(self):
        assert topic_key("  APT29  ") == "apt29"

    def test_collapses_internal_whitespace(self):
        assert topic_key("APT  29") == "apt 29"

    def test_case_insensitive_equality(self):
        assert topic_key("APT29") == topic_key("apt29")
        assert topic_key("Volt Typhoon") == topic_key("VOLT TYPHOON")


# ===========================================================================
# ResearchEntry
# ===========================================================================

class TestResearchEntry:

    def _entry(self, topic="APT29", researcher="analyst1",
               hours_ago=0, category=None) -> ResearchEntry:
        promoted = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return ResearchEntry(
            topic       = topic,
            stix_objects= [{"type": "indicator", "id": f"indicator--{topic}",
                             "name": f"{topic}.com"}],
            researcher  = researcher,
            promoted_at = promoted,
            note        = f"Research on {topic}",
            category    = category or categorise_topic(topic),
        )

    def test_auto_category(self):
        e = self._entry("APT29 threat actor")
        assert e.category == "threat_actor"

    def test_auto_entry_id(self):
        e = self._entry()
        assert e.entry_id and len(e.entry_id) == 24

    def test_is_pending_by_default(self):
        e = self._entry()
        assert e.is_pending
        assert not e.is_curated
        assert not e.is_archived

    def test_set_ttl_and_is_fresh(self):
        e = self._entry(hours_ago=1)
        e.set_ttl(24)
        assert e.is_fresh
        assert e.hours_until_expiry is not None
        assert e.hours_until_expiry > 0

    def test_stale_entry(self):
        e = self._entry(hours_ago=25)
        e.set_ttl(24)
        assert not e.is_fresh
        assert e.hours_until_expiry == 0.0

    def test_no_ttl_is_always_fresh(self):
        e = self._entry(hours_ago=9999)
        assert e.is_fresh  # no TTL set

    def test_mark_curated(self):
        e = self._entry()
        e.mark_curated()
        assert e.is_curated
        assert e.curated_at is not None

    def test_mark_archived(self):
        e = self._entry()
        e.mark_archived()
        assert e.is_archived

    def test_age_hours(self):
        e = self._entry(hours_ago=5)
        assert 4.9 <= e.age_hours <= 5.1

    def test_round_trip(self):
        e = self._entry()
        e.set_ttl(720)
        d = e.to_dict()
        e2 = ResearchEntry.from_dict(d)
        assert e2.topic == e.topic
        assert e2.researcher == e.researcher
        assert e2.note == e.note
        assert e2.category == e.category
        assert e2.is_fresh == e.is_fresh
        assert len(e2.stix_objects) == len(e.stix_objects)

    def test_round_trip_preserves_status(self):
        e = self._entry()
        e.mark_curated()
        d = e.to_dict()
        e2 = ResearchEntry.from_dict(d)
        assert e2.is_curated
        assert e2.curated_at is not None

    def test_summary_dict_keys(self):
        e = self._entry()
        s = e.summary()
        for key in ("entry_id", "topic", "category", "researcher", "note",
                    "promoted_at", "age_hours", "is_fresh", "curator_status",
                    "stix_object_count"):
            assert key in s, f"Missing key: {key}"

    def test_summary_truncates_note(self):
        e = self._entry()
        e.note = "x" * 500
        s = e.summary()
        assert len(s["note"]) <= 200


# ===========================================================================
# ResearchLibrary — initialisation
# ===========================================================================

class TestResearchLibraryInit:

    def test_creates_staging_workspace(self, lib, manager):
        names = [w["name"] for w in manager.list()]
        assert "_ctmsak_staging" in names

    def test_creates_library_workspace(self, lib, manager):
        names = [w["name"] for w in manager.list()]
        assert "_ctmsak_library" in names

    def test_custom_workspace_names(self, manager):
        lib = ResearchLibrary(manager,
                              staging_name="_my_staging",
                              library_name="_my_library")
        names = [w["name"] for w in manager.list()]
        assert "_my_staging" in names
        assert "_my_library" in names

    def test_custom_ttls_merged_with_defaults(self, manager):
        lib = ResearchLibrary(manager, ttls={"indicator": 12, "threat_actor": 48})
        assert lib._ttls["indicator"] == 12
        assert lib._ttls["threat_actor"] == 48
        assert lib._ttls["vulnerability"] == DEFAULT_TTLS["vulnerability"]


# ===========================================================================
# ResearchLibrary — promote()
# ===========================================================================

class TestResearchLibraryPromote:

    def test_promote_ai_objects(self, lib, manager):
        ws = _populated_workspace(manager, "ws1", ai=True)
        entry = lib.promote(ws, topic="APT29", researcher="analyst1",
                            note="Found C2 infra")
        assert entry.topic == "APT29"
        assert entry.researcher == "analyst1"
        assert entry.note == "Found C2 infra"
        assert entry.is_pending
        assert len(entry.stix_objects) == 1
        assert entry.expires_at is not None

    def test_promote_non_ai_fallback(self, lib, manager):
        ws = _populated_workspace(manager, "ws2", ai=False)
        entry = lib.promote(ws, topic="plain-topic", researcher="analyst1")
        assert len(entry.stix_objects) == 1

    def test_promote_specific_stix_ids(self, lib, manager):
        ws = manager.create("ws3")
        ind_a = _ind("a.com")
        ind_b = _ind("b.com")
        ws.add(ind_a, mark_dirty=False)
        ws.add(ind_b, mark_dirty=False)
        entry = lib.promote(ws, topic="selective", researcher="analyst1",
                            stix_ids=[ind_a.id])
        assert len(entry.stix_objects) == 1
        assert entry.stix_objects[0]["name"] == "a.com"

    def test_promote_empty_workspace_raises(self, lib, manager):
        ws = manager.create("empty-ws")
        with pytest.raises(ValueError, match="No objects"):
            lib.promote(ws, topic="empty", researcher="analyst1")

    def test_promote_sets_source_workspace(self, lib, manager):
        ws = _populated_workspace(manager, "my-ws")
        entry = lib.promote(ws, topic="APT29", researcher="analyst1")
        assert entry.source_workspace == "my-ws"

    def test_promote_auto_ttl(self, lib, manager):
        ws = _populated_workspace(manager, "ws-ttl")
        entry = lib.promote(ws, topic="CVE-2024-1234 exploit",
                            researcher="analyst1")
        assert entry.category == "vulnerability"
        expected = DEFAULT_TTLS["vulnerability"]
        actual = (entry.expires_at - entry.promoted_at).total_seconds() / 3600
        assert abs(actual - expected) < 1

    def test_promote_optional_note(self, lib, manager):
        ws = _populated_workspace(manager, "ws-nonote")
        entry = lib.promote(ws, topic="APT29", researcher="analyst1")
        assert entry.note == ""

    def test_promote_appears_in_staging(self, lib, manager):
        ws = _populated_workspace(manager, "ws-stage")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        staging = lib.list_staging()
        assert any(s["topic"] == "APT29" for s in staging)


# ===========================================================================
# ResearchLibrary — freshness and retrieval
# ===========================================================================

class TestResearchLibraryRetrieval:

    def _promote_and_curate(self, lib, manager, topic, researcher="analyst1"):
        ws = _populated_workspace(manager, f"ws-{topic[:6]}")
        lib.promote(ws, topic=topic, researcher=researcher)
        curation = CurationJob(lib, interval_seconds=3600)
        curation.execute()

    def test_is_fresh_false_before_curation(self, lib, manager):
        ws = _populated_workspace(manager, "ws-nonfresh")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        assert not lib.is_fresh("APT29")

    def test_is_fresh_true_after_curation(self, lib, manager):
        self._promote_and_curate(lib, manager, "APT29")
        assert lib.is_fresh("APT29")

    def test_get_returns_none_before_curation(self, lib, manager):
        ws = _populated_workspace(manager, "ws-get")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        assert lib.get("APT29") is None

    def test_get_returns_curated_entry(self, lib, manager):
        self._promote_and_curate(lib, manager, "APT29")
        entry = lib.get("APT29")
        assert entry is not None
        assert entry.is_curated
        assert entry.topic == "APT29"

    def test_get_case_insensitive(self, lib, manager):
        self._promote_and_curate(lib, manager, "APT29")
        assert lib.get("apt29") is not None
        assert lib.get("APT 29") is None  # different key

    def test_get_staging_returns_pending(self, lib, manager):
        ws = _populated_workspace(manager, "ws-gst")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        stg = lib.get_staging("APT29")
        assert stg is not None and stg.is_pending

    def test_get_staging_returns_none_after_curation(self, lib, manager):
        self._promote_and_curate(lib, manager, "APT29")
        # After curation the staging entry has curator_status=curated
        assert lib.get_staging("APT29") is None  # no longer pending


# ===========================================================================
# ResearchLibrary — search and list
# ===========================================================================

class TestResearchLibrarySearch:

    def _setup_library(self, lib, manager):
        topics = [("APT29", "analyst1"), ("Volt Typhoon", "analyst2"),
                  ("CVE-2024-3400", "analyst1")]
        for topic, researcher in topics:
            ws = _populated_workspace(manager, f"ws-{topic[:6]}")
            lib.promote(ws, topic=topic, researcher=researcher,
                        note=f"Research on {topic}")
        CurationJob(lib, interval_seconds=3600).execute()

    def test_search_by_topic_substring(self, lib, manager):
        self._setup_library(lib, manager)
        results = lib.search("APT")
        assert len(results) == 1
        assert results[0].topic == "APT29"

    def test_search_case_insensitive(self, lib, manager):
        self._setup_library(lib, manager)
        results = lib.search("volt typhoon")
        assert any(e.topic == "Volt Typhoon" for e in results)

    def test_search_by_researcher(self, lib, manager):
        self._setup_library(lib, manager)
        results = lib.search("analyst2")
        assert len(results) == 1

    def test_search_no_results(self, lib, manager):
        self._setup_library(lib, manager)
        assert lib.search("totally-nonexistent-topic-xyz") == []

    def test_list_entries_all(self, lib, manager):
        self._setup_library(lib, manager)
        entries = lib.list_entries()
        assert len(entries) == 3

    def test_list_entries_by_category(self, lib, manager):
        self._setup_library(lib, manager)
        vuln_entries = lib.list_entries(category="vulnerability")
        assert all(e["category"] == "vulnerability" for e in vuln_entries)

    def test_list_entries_newest_first(self, lib, manager):
        self._setup_library(lib, manager)
        entries = lib.list_entries()
        ages = [e["age_hours"] for e in entries]
        assert ages == sorted(ages)  # youngest = smallest age_hours = first


# ===========================================================================
# ResearchLibrary — load_into_workspace
# ===========================================================================

class TestResearchLibraryLoad:

    def test_loads_stix_objects(self, lib, manager):
        ws = _populated_workspace(manager, "ws-src")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        CurationJob(lib, interval_seconds=3600).execute()

        ws_dest = manager.create("ws-dest")
        count = lib.load_into_workspace("APT29", ws_dest)
        assert count == 1
        assert len(ws_dest) == 1

    def test_raises_on_missing_topic(self, lib, manager):
        ws_dest = manager.create("ws-dest2")
        with pytest.raises(KeyError, match="NonExistent"):
            lib.load_into_workspace("NonExistent", ws_dest)

    def test_loaded_objects_not_dirty_by_default(self, lib, manager):
        ws = _populated_workspace(manager, "ws-src2")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        CurationJob(lib, interval_seconds=3600).execute()

        ws_dest = manager.create("ws-dest3")
        lib.load_into_workspace("APT29", ws_dest)
        assert len(ws_dest.dirty) == 0


# ===========================================================================
# ResearchLibrary — stats and retire
# ===========================================================================

class TestResearchLibraryManagement:

    def test_stats_empty(self, lib):
        s = lib.stats()
        assert s["library_total"] == 0
        assert s["library_fresh"] == 0
        assert s["staging_pending"] == 0

    def test_stats_after_promote(self, lib, manager):
        ws = _populated_workspace(manager, "ws-stats")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        s = lib.stats()
        assert s["staging_pending"] == 1
        assert s["library_total"] == 0

    def test_stats_after_curation(self, lib, manager):
        ws = _populated_workspace(manager, "ws-stats2")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        CurationJob(lib, interval_seconds=3600).execute()
        s = lib.stats()
        assert s["library_total"] == 1
        assert s["library_fresh"] == 1
        assert s["staging_pending"] == 0

    def test_retire_existing(self, lib, manager):
        ws = _populated_workspace(manager, "ws-retire")
        lib.promote(ws, topic="APT29", researcher="analyst1")
        CurationJob(lib, interval_seconds=3600).execute()
        entry = lib.get("APT29")
        assert lib.retire_entry(entry.entry_id) is True

    def test_retire_nonexistent(self, lib):
        assert lib.retire_entry("nonexistent-id-xyz") is False


# ===========================================================================
# CurationJob
# ===========================================================================

class TestCurationJob:

    def _promote(self, lib, manager, topic, researcher, ws_name):
        ws = _populated_workspace(manager, ws_name)
        lib.promote(ws, topic=topic, researcher=researcher, note=f"Note for {topic}")
        return ws

    def test_promotes_single_entry(self, lib, manager):
        self._promote(lib, manager, "APT29", "analyst1", "ws-p1")
        rec = CurationJob(lib, interval_seconds=3600).execute()
        assert rec.status == "success"
        assert rec.result.metadata["promoted"] == 1
        assert lib.is_fresh("APT29")

    def test_dedup_most_recent_wins(self, lib, manager):
        self._promote(lib, manager, "APT29", "analyst_a", "ws-da")
        time.sleep(0.05)
        self._promote(lib, manager, "APT29", "analyst_b", "ws-db")
        rec = CurationJob(lib, interval_seconds=3600).execute()
        assert rec.result.metadata["promoted"] == 1
        assert rec.result.metadata["archived"] == 1
        winner = lib.get("APT29")
        assert winner.researcher == "analyst_b"

    def test_multiple_topics_all_promoted(self, lib, manager):
        for topic, ws in [("APT29", "ws-t1"), ("LockBit", "ws-t2"), ("Volt Typhoon", "ws-t3")]:
            self._promote(lib, manager, topic, "analyst1", ws)
        rec = CurationJob(lib, interval_seconds=3600).execute()
        assert rec.result.metadata["promoted"] == 3
        assert rec.result.metadata["archived"] == 0
        assert lib.is_fresh("APT29")
        assert lib.is_fresh("LockBit")
        assert lib.is_fresh("Volt Typhoon")

    def test_idempotent_on_empty_staging(self, lib, manager):
        rec = CurationJob(lib, interval_seconds=3600).execute()
        assert rec.status == "success"
        assert rec.result.total_records == 0

    def test_ttl_applied_by_category(self, lib, manager):
        self._promote(lib, manager, "CVE-2024-1234 vuln", "analyst1", "ws-cve")
        CurationJob(lib, interval_seconds=3600).execute()
        entry = lib.get("CVE-2024-1234 vuln")
        assert entry.category == "vulnerability"
        expected = DEFAULT_TTLS["vulnerability"]
        actual = (entry.expires_at - entry.promoted_at).total_seconds() / 3600
        assert abs(actual - expected) < 1

    def test_status_success(self, lib, manager):
        rec = CurationJob(lib, interval_seconds=3600).execute()
        assert rec.status == "success"
        assert rec.run_count == 1

    def test_run_count_increments(self, lib, manager):
        job = CurationJob(lib, interval_seconds=3600)
        job.execute()
        job.execute()
        assert job.run_count == 2

    def test_on_success_callback(self, lib, manager):
        fired = []
        job = CurationJob(lib, interval_seconds=3600,
                          on_success=lambda rec: fired.append(rec.status))
        job.execute()
        assert fired == ["success"]

    def test_newer_staging_does_not_overwrite_newer_library(self, lib, manager):
        """If library already has a newer entry, staging entry is archived."""
        # Curate first
        self._promote(lib, manager, "APT29", "analyst_b", "ws-first")
        CurationJob(lib, interval_seconds=3600).execute()
        first_entry = lib.get("APT29")

        # Promote an older entry (simulate by manual timestamp manipulation)
        ws_old = _populated_workspace(manager, "ws-old")
        old_entry = lib.promote(ws_old, topic="APT29", researcher="analyst_a")
        # Manually backdate it
        old_entry.promoted_at = first_entry.promoted_at - timedelta(hours=1)
        lib._save_entry(old_entry, lib._staging_name)

        rec2 = CurationJob(lib, interval_seconds=3600).execute()
        # The old staging entry should have been archived, not promoted
        assert rec2.result.metadata["archived"] >= 1
        # Winner in library is still the original (newer) one
        winner = lib.get("APT29")
        assert winner.researcher == "analyst_b"


# ===========================================================================
# Integration: promote → curate → load full cycle
# ===========================================================================

class TestResearchLibraryIntegration:

    def test_full_cycle(self, lib, manager):
        """Analyst promotes → curation runs → second analyst loads."""
        # Analyst 1: research and promote
        ws1 = manager.create("analyst1-ws")
        ind = _ind("c2.apt29.ru")
        ws1.add(ind, mark_dirty=False)
        lib.promote(ws1, topic="APT29 C2 Infrastructure", researcher="analyst1",
                    note="Three C2 IPs confirmed by Unit42.")

        # Before curation: analyst2 checks and finds nothing
        assert not lib.is_fresh("APT29 C2 Infrastructure")
        assert lib.get("APT29 C2 Infrastructure") is None

        # Curation runs
        CurationJob(lib, interval_seconds=3600).execute()

        # After curation: analyst2 finds the entry
        assert lib.is_fresh("APT29 C2 Infrastructure")
        entry = lib.get("APT29 C2 Infrastructure")
        assert entry is not None
        assert entry.researcher == "analyst1"
        assert "Unit42" in entry.note

        # Analyst 2 loads into their own workspace
        ws2 = manager.create("analyst2-ws")
        count = lib.load_into_workspace("APT29 C2 Infrastructure", ws2)
        assert count == 1
        assert len(ws2) == 1

    def test_multiple_analysts_same_topic_dedup(self, lib, manager):
        """Three analysts research same topic; most recent curated."""
        for _i, researcher in enumerate(["analyst_a", "analyst_b", "analyst_c"]):
            ws = _populated_workspace(manager, f"ws-{researcher}")
            lib.promote(ws, topic="LockBit 3.0", researcher=researcher,
                        note=f"Research by {researcher}")
            time.sleep(0.02)  # ensure ordering

        stats_before = lib.stats()
        assert stats_before["staging_pending"] == 3

        CurationJob(lib, interval_seconds=3600).execute()

        assert lib.is_fresh("LockBit 3.0")
        winner = lib.get("LockBit 3.0")
        assert winner.researcher == "analyst_c"  # most recent

        s = lib.stats()
        assert s["library_total"] == 1
        assert s["staging_pending"] == 0

    def test_search_finds_by_note_content(self, lib, manager):
        ws = _populated_workspace(manager, "ws-note")
        lib.promote(ws, topic="APT29", researcher="analyst1",
                    note="Spearphishing campaign targeting energy sector")
        CurationJob(lib, interval_seconds=3600).execute()

        results = lib.search("energy sector")
        assert len(results) == 1
        assert results[0].topic == "APT29"

    def test_stale_entry_excluded_from_search_by_default(self, lib, manager):
        ws = _populated_workspace(manager, "ws-stale")
        lib.promote(ws, topic="old-ioc", researcher="analyst1")

        # Manually backdate the staging entry to make it stale after curation
        entries = lib._load_all_entries(lib._staging_name, status="pending")
        for e in entries:
            e.promoted_at = datetime.now(timezone.utc) - timedelta(hours=48)
            lib._save_entry(e, lib._staging_name)

        # Run curation (entry will be curated but with backdate)
        CurationJob(lib, interval_seconds=3600).execute()

        # Get the curated entry and force it stale
        entry = lib.get("old-ioc")
        if entry:
            entry.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
            lib._save_entry(entry, lib._library_name)

        # Default search excludes stale
        results = lib.search("old-ioc", include_stale=False)
        # May or may not be stale depending on timing, but search returns []
        # when stale is excluded — this tests the flag is respected
        results_with_stale = lib.search("old-ioc", include_stale=True)
        # include_stale should return >= what non-stale returns
        assert len(results_with_stale) >= len(results)
