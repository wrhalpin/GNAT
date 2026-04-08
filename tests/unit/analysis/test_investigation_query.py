"""Unit tests for gnat.analysis.query (InvestigationQuery DSL)."""

from __future__ import annotations

import pytest
from gnat.analysis.query import InvestigationQuery


def test_defaults():
    q = InvestigationQuery()
    assert q.status     is None
    assert q.page       == 1
    assert q.page_size  == 50
    assert q.sort_by    == "updated_at"
    assert q.sort_desc  is True


def test_offset_and_limit():
    q = InvestigationQuery(page=2, page_size=25)
    assert q.offset == 25
    assert q.limit  == 25


def test_limit_clamped():
    assert InvestigationQuery(page_size=0).limit   == 1
    assert InvestigationQuery(page_size=600).limit == 500


def test_status_values_none_when_not_set():
    assert InvestigationQuery().status_values is None


def test_status_values_extracts_enum_value():
    from gnat.analysis.investigations.models import InvestigationStatus

    q = InvestigationQuery(status=[InvestigationStatus.OPEN, InvestigationStatus.IN_PROGRESS])
    sv = q.status_values
    assert sv is not None
    assert "open"        in sv
    assert "in_progress" in sv


def test_classification_values_none_when_not_set():
    assert InvestigationQuery().classification_values is None


def test_classification_values_extracts_tlp():
    from gnat.analysis.tlp import TLPLevel
    q = InvestigationQuery(classification=[TLPLevel.AMBER, TLPLevel.RED])
    cv = q.classification_values
    assert "amber" in cv
    assert "red"   in cv


def test_safe_sort_by_valid():
    assert InvestigationQuery(sort_by="title").safe_sort_by    == "title"
    assert InvestigationQuery(sort_by="created_at").safe_sort_by == "created_at"


def test_safe_sort_by_invalid_falls_back():
    assert InvestigationQuery(sort_by="DROP TABLE").safe_sort_by == "updated_at"


# ── Integration with InvestigationStore ───────────────────────────────────────

@pytest.fixture
def inv_store():
    pytest.importorskip("sqlalchemy")
    from gnat.analysis.investigations.storage import InvestigationStore
    store = InvestigationStore("sqlite:///:memory:")
    store.create_all()
    return store


@pytest.fixture
def populated_store(inv_store):
    from gnat.analysis.investigations.service import InvestigationService
    from gnat.analysis.tlp import TLPLevel

    svc = InvestigationService(inv_store)
    svc.create("Ransomware April",     "alice", tags=["ransomware"],   classification=TLPLevel.AMBER)
    svc.create("Phishing Campaign",    "bob",   tags=["phishing"],    classification=TLPLevel.GREEN)
    svc.create("OPSEC Investigation",  "alice", tags=["opsec"],       classification=TLPLevel.RED)
    return inv_store


def test_query_list_all(populated_store):
    q       = InvestigationQuery(page_size=100)
    results = populated_store.list(query=q)
    assert len(results) == 3


def test_query_filter_by_created_by(populated_store):
    q       = InvestigationQuery(created_by="alice", page_size=100)
    results = populated_store.list(query=q)
    assert len(results) == 2
    assert all(r.created_by == "alice" for r in results)


def test_query_filter_by_tag(populated_store):
    q       = InvestigationQuery(tags=["ransomware"], page_size=100)
    results = populated_store.list(query=q)
    assert len(results) == 1
    assert "ransomware" in results[0].tags


def test_query_filter_by_status(populated_store):
    from gnat.analysis.investigations.models import InvestigationStatus

    q       = InvestigationQuery(status=[InvestigationStatus.OPEN], page_size=100)
    results = populated_store.list(query=q)
    assert len(results) == 3  # all are OPEN by default


def test_query_filter_by_tlp(populated_store):
    from gnat.analysis.tlp import TLPLevel

    q       = InvestigationQuery(classification=[TLPLevel.AMBER], page_size=100)
    results = populated_store.list(query=q)
    assert len(results) == 1
    assert results[0].title == "Ransomware April"


def test_query_text_search(populated_store):
    q       = InvestigationQuery(text="Phishing", page_size=100)
    results = populated_store.list(query=q)
    assert len(results) == 1
    assert "Phishing" in results[0].title


def test_query_pagination(populated_store):
    page1 = populated_store.list(query=InvestigationQuery(page=1, page_size=2))
    page2 = populated_store.list(query=InvestigationQuery(page=2, page_size=2))
    assert len(page1) == 2
    assert len(page2) == 1


def test_query_legacy_kwargs_still_work(populated_store):
    """Backward-compat: old-style kwargs still work."""
    results = populated_store.list(created_by="bob", limit=10)
    assert len(results) == 1
    assert results[0].created_by == "bob"
