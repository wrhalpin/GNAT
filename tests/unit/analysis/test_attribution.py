# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_attribution.py
==========================================

Unit tests for the campaign attribution foundation layer (Phase 1):
Campaign ORM, CampaignProfile model, CampaignStore CRUD, CampaignService
lifecycle, CampaignQuery filtering.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from gnat.analysis.attribution.models import CampaignProfile, CampaignStatus
from gnat.analysis.attribution.query import CampaignQuery
from gnat.analysis.attribution.service import CampaignService, CampaignServiceError
from gnat.analysis.attribution.storage import CampaignStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store():
    pytest.importorskip("sqlalchemy", reason="gnat[persist] extras not installed")
    s = CampaignStore("sqlite:///:memory:")
    s.create_all()
    return s


@pytest.fixture
def service(store):
    return CampaignService(store)


# ===========================================================================
# Campaign ORM
# ===========================================================================


class TestCampaignORM:
    def test_campaign_stix_type(self):
        from gnat.orm.campaign import Campaign

        c = Campaign(name="Test")
        assert c.stix_type == "campaign"
        assert c.id.startswith("campaign--")

    def test_campaign_defaults(self):
        from gnat.orm.campaign import Campaign

        c = Campaign()
        assert c.aliases == []
        assert c.first_seen is None
        assert c.last_seen is None
        assert c.objective == ""

    def test_campaign_to_dict(self):
        from gnat.orm.campaign import Campaign

        c = Campaign(name="Op Aurora", objective="Espionage")
        d = c.to_dict()
        assert d["type"] == "campaign"
        assert d["name"] == "Op Aurora"
        assert d["objective"] == "Espionage"

    def test_campaign_registered_in_orm(self):
        from gnat.orm import Campaign

        assert Campaign.stix_type == "campaign"


# ===========================================================================
# CampaignProfile model
# ===========================================================================


class TestCampaignProfile:
    def test_defaults(self):
        p = CampaignProfile(name="Test")
        assert p.status == CampaignStatus.SUSPECTED
        assert p.id.startswith("campaign--")
        assert p.aliases == []
        assert p.indicator_ids == []
        assert p.classification == "amber"

    def test_to_dict_from_dict_roundtrip(self):
        p = CampaignProfile(
            name="Op Sunrise",
            status=CampaignStatus.ACTIVE,
            aliases=["Sunrise", "Dawn"],
            tags=["apt", "espionage"],
            threat_actor_id="threat-actor--abc",
            first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
            classification="red",
        )
        d = p.to_dict()
        p2 = CampaignProfile.from_dict(d)
        assert p2.name == "Op Sunrise"
        assert p2.status == CampaignStatus.ACTIVE
        assert p2.aliases == ["Sunrise", "Dawn"]
        assert p2.tags == ["apt", "espionage"]
        assert p2.threat_actor_id == "threat-actor--abc"
        assert p2.first_seen == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert p2.classification == "red"

    def test_from_dict_defaults(self):
        p = CampaignProfile.from_dict({"name": "Minimal"})
        assert p.name == "Minimal"
        assert p.status == CampaignStatus.SUSPECTED
        assert p.id.startswith("campaign--")

    def test_status_enum_values(self):
        assert CampaignStatus("suspected") == CampaignStatus.SUSPECTED
        assert CampaignStatus("active") == CampaignStatus.ACTIVE
        assert CampaignStatus("dormant") == CampaignStatus.DORMANT
        assert CampaignStatus("concluded") == CampaignStatus.CONCLUDED


# ===========================================================================
# CampaignQuery
# ===========================================================================


class TestCampaignQuery:
    def test_from_dict_with_status_string(self):
        q = CampaignQuery.from_dict({"status": "active"})
        assert q.status == [CampaignStatus.ACTIVE]

    def test_from_dict_with_status_list(self):
        q = CampaignQuery.from_dict({"status": ["active", "dormant"]})
        assert q.status == [CampaignStatus.ACTIVE, CampaignStatus.DORMANT]

    def test_from_dict_with_no_filters(self):
        q = CampaignQuery.from_dict({})
        assert q.status is None
        assert q.tags is None
        assert q.page == 1
        assert q.page_size == 25


# ===========================================================================
# CampaignStore CRUD
# ===========================================================================


class TestCampaignStore:
    def test_save_and_get(self, store):
        p = CampaignProfile(name="Store Test")
        store.save(p)
        loaded = store.get(p.id)
        assert loaded is not None
        assert loaded.name == "Store Test"

    def test_get_nonexistent_returns_none(self, store):
        assert store.get("campaign--doesnotexist") is None

    def test_save_update(self, store):
        p = CampaignProfile(name="Original")
        store.save(p)
        p.name = "Updated"
        store.save(p)
        loaded = store.get(p.id)
        assert loaded.name == "Updated"

    def test_delete_soft(self, store):
        p = CampaignProfile(name="To Delete")
        store.save(p)
        assert store.delete(p.id) is True
        assert store.get(p.id) is None

    def test_delete_nonexistent(self, store):
        assert store.delete("campaign--nope") is False

    def test_list_all(self, store):
        store.save(CampaignProfile(name="A"))
        store.save(CampaignProfile(name="B"))
        store.save(CampaignProfile(name="C"))
        results = store.list()
        assert len(results) == 3

    def test_list_by_status(self, store):
        store.save(CampaignProfile(name="Active1", status=CampaignStatus.ACTIVE))
        store.save(CampaignProfile(name="Active2", status=CampaignStatus.ACTIVE))
        store.save(CampaignProfile(name="Dormant", status=CampaignStatus.DORMANT))
        q = CampaignQuery(status=[CampaignStatus.ACTIVE])
        results = store.list(q)
        assert len(results) == 2
        assert all(r.status == CampaignStatus.ACTIVE for r in results)

    def test_list_by_text_search(self, store):
        store.save(CampaignProfile(name="Operation Sunrise"))
        store.save(CampaignProfile(name="Operation Moonlight"))
        q = CampaignQuery(text_search="Sunrise")
        results = store.list(q)
        assert len(results) == 1
        assert results[0].name == "Operation Sunrise"

    def test_list_by_threat_actor(self, store):
        store.save(
            CampaignProfile(name="A", threat_actor_id="threat-actor--x")
        )
        store.save(CampaignProfile(name="B", threat_actor_id="threat-actor--y"))
        q = CampaignQuery(threat_actor_id="threat-actor--x")
        results = store.list(q)
        assert len(results) == 1

    def test_count(self, store):
        store.save(CampaignProfile(name="A", status=CampaignStatus.ACTIVE))
        store.save(CampaignProfile(name="B", status=CampaignStatus.DORMANT))
        assert store.count() == 2
        assert store.count(CampaignQuery(status=[CampaignStatus.ACTIVE])) == 1

    def test_list_pagination(self, store):
        for i in range(10):
            store.save(CampaignProfile(name=f"Campaign {i}"))
        page1 = store.list(CampaignQuery(page=1, page_size=3))
        page2 = store.list(CampaignQuery(page=2, page_size=3))
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0].id != page2[0].id


# ===========================================================================
# CampaignService
# ===========================================================================


class TestCampaignService:
    def test_create_basic(self, service):
        c = service.create(name="Service Test")
        assert c.name == "Service Test"
        assert c.status == CampaignStatus.SUSPECTED

    def test_create_requires_name(self, service):
        with pytest.raises(CampaignServiceError, match="name is required"):
            service.create(name="")

    def test_get_existing(self, service):
        c = service.create(name="Findable")
        loaded = service.get(c.id)
        assert loaded.name == "Findable"

    def test_get_nonexistent_raises(self, service):
        with pytest.raises(CampaignServiceError, match="not found"):
            service.get("campaign--nope")

    def test_transition_suspected_to_active(self, service):
        c = service.create(name="Transition")
        c = service.transition(c.id, CampaignStatus.ACTIVE)
        assert c.status == CampaignStatus.ACTIVE

    def test_transition_active_to_dormant(self, service):
        c = service.create(name="Transition")
        service.transition(c.id, CampaignStatus.ACTIVE)
        c = service.transition(c.id, CampaignStatus.DORMANT)
        assert c.status == CampaignStatus.DORMANT

    def test_transition_dormant_to_active(self, service):
        c = service.create(name="Transition")
        service.transition(c.id, CampaignStatus.ACTIVE)
        service.transition(c.id, CampaignStatus.DORMANT)
        c = service.transition(c.id, CampaignStatus.ACTIVE)
        assert c.status == CampaignStatus.ACTIVE

    def test_transition_to_concluded_is_terminal(self, service):
        c = service.create(name="Terminal")
        service.transition(c.id, CampaignStatus.ACTIVE)
        service.transition(c.id, CampaignStatus.CONCLUDED)
        with pytest.raises(CampaignServiceError, match="invalid transition"):
            service.transition(c.id, CampaignStatus.ACTIVE)

    def test_invalid_transition_raises(self, service):
        c = service.create(name="Invalid")
        with pytest.raises(CampaignServiceError, match="invalid transition"):
            service.transition(c.id, CampaignStatus.DORMANT)

    def test_link_indicator(self, service):
        c = service.create(name="Link Test")
        c = service.link_indicator(c.id, "indicator--abc")
        assert "indicator--abc" in c.indicator_ids
        # Deduplicated
        c = service.link_indicator(c.id, "indicator--abc")
        assert c.indicator_ids.count("indicator--abc") == 1

    def test_unlink_indicator(self, service):
        c = service.create(name="Unlink Test")
        service.link_indicator(c.id, "indicator--abc")
        c = service.unlink_indicator(c.id, "indicator--abc")
        assert "indicator--abc" not in c.indicator_ids

    def test_link_investigation(self, service):
        c = service.create(name="Inv Link")
        c = service.link_investigation(c.id, "inv-123")
        assert "inv-123" in c.investigation_ids

    def test_link_cluster(self, service):
        c = service.create(name="Cluster Link")
        c = service.link_cluster(c.id, "cluster-456")
        assert "cluster-456" in c.cluster_ids

    def test_set_threat_actor(self, service):
        c = service.create(name="Actor Test")
        c = service.set_threat_actor(c.id, "threat-actor--sandworm")
        assert c.threat_actor_id == "threat-actor--sandworm"

    def test_add_tag(self, service):
        c = service.create(name="Tag Test")
        c = service.add_tag(c.id, "apt")
        c = service.add_tag(c.id, "espionage")
        c = service.add_tag(c.id, "apt")  # dedup
        assert c.tags == ["apt", "espionage"]

    def test_delete(self, service):
        c = service.create(name="Delete Me")
        assert service.delete(c.id) is True
        with pytest.raises(CampaignServiceError, match="not found"):
            service.get(c.id)

    def test_sub_campaign_hierarchy(self, service):
        parent = service.create(name="Parent Campaign")
        child = service.create(
            name="Sub Campaign", parent_campaign_id=parent.id
        )
        assert child.parent_campaign_id == parent.id
        parent = service.get(parent.id)
        assert child.id in parent.sub_campaign_ids
        subs = service.get_sub_campaigns(parent.id)
        assert len(subs) == 1
        assert subs[0].id == child.id

    def test_sub_campaign_invalid_parent_raises(self, service):
        with pytest.raises(CampaignServiceError, match="not found"):
            service.create(name="Orphan", parent_campaign_id="campaign--nope")

    def test_summary(self, service):
        service.create(name="A")
        service.create(name="B")
        c = service.create(name="C")
        service.transition(c.id, CampaignStatus.ACTIVE)
        s = service.summary()
        assert s["total"] == 3
        assert s["by_status"]["suspected"] == 2
        assert s["by_status"]["active"] == 1

    def test_update_arbitrary_fields(self, service):
        c = service.create(name="Original")
        c = service.update(c.id, name="Updated", description="New desc")
        assert c.name == "Updated"
        assert c.description == "New desc"

    def test_list_with_query(self, service):
        service.create(name="Alpha", tags=["apt"])
        service.create(name="Beta", tags=["criminal"])
        results = service.list(CampaignQuery(tags=["apt"]))
        assert len(results) == 1
        assert results[0].name == "Alpha"
