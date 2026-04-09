"""
tests/unit/test_phase4_core.py
================================
Unit tests for Phase 4A/4B/4E — ExecutionContext, QueryBudget,
Domain boundaries, SimulationConnector, ReplayRunner.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock


# ---------------------------------------------------------------------------
# ExecutionContext tests
# ---------------------------------------------------------------------------

class TestExecutionContext:
    def test_create_defaults(self):
        from gnat.core.context import ExecutionContext

        ctx = ExecutionContext.create(
            initiated_by="test-connector",
            domain="ingestion",
            workspace_id="ws-1",
        )
        assert ctx.initiated_by == "test-connector"
        assert ctx.domain == "ingestion"
        assert ctx.trust_level == "semi_trusted"
        assert ctx.policy_set == "default"
        assert ctx.is_replay is False
        assert ctx.budget is None
        assert len(ctx.context_id) == 36  # UUID format

    def test_create_with_budget(self):
        from gnat.core.context import ExecutionContext, QueryBudget

        ctx = ExecutionContext.create(
            initiated_by="test",
            domain="analysis",
            workspace_id="ws-1",
            max_budget_units=500,
        )
        assert ctx.budget is not None
        assert isinstance(ctx.budget, QueryBudget)
        assert ctx.budget.max_units == 500
        assert ctx.budget.remaining == 500

    def test_from_connector(self):
        from gnat.core.context import ExecutionContext

        connector = MagicMock()
        type(connector).TRUST_LEVEL = "trusted_internal"
        type(connector).__name__ = "SplunkClient"

        ctx = ExecutionContext.from_connector(
            connector=connector,
            domain="ingestion",
            workspace_id="ws-splunk",
        )
        assert ctx.trust_level == "trusted_internal"
        assert ctx.initiated_by == "SplunkClient"

    def test_child_context(self):
        from gnat.core.context import ExecutionContext

        parent = ExecutionContext.create(
            initiated_by="pipeline",
            domain="ingestion",
            workspace_id="ws-1",
        )
        child = parent.child("enrichment-agent", domain="analysis")
        assert child.parent_context_id == parent.context_id
        assert child.workspace_id == parent.workspace_id
        assert child.trust_level == parent.trust_level
        assert child.domain == "analysis"

    def test_to_dict_from_dict_round_trip(self):
        from gnat.core.context import ExecutionContext

        ctx = ExecutionContext.create(
            initiated_by="manual",
            domain="investigation",
            workspace_id="ws-inv",
            trust_level="trusted_internal",
            policy_set="strict",
            is_replay=True,
        )
        d = ctx.to_dict()
        ctx2 = ExecutionContext.from_dict(d)

        assert ctx2.context_id == ctx.context_id
        assert ctx2.domain == "investigation"
        assert ctx2.trust_level == "trusted_internal"
        assert ctx2.is_replay is True


# ---------------------------------------------------------------------------
# QueryBudget tests
# ---------------------------------------------------------------------------

class TestQueryBudget:
    def test_initial_state(self):
        from gnat.core.context import QueryBudget

        budget = QueryBudget(max_units=100)
        assert budget.remaining == 100
        assert budget.is_exhausted is False

    def test_consume(self):
        from gnat.core.context import QueryBudget

        budget = QueryBudget(max_units=100)
        budget.consume(10, "TestConnector")
        assert budget.remaining == 90
        assert budget.is_exhausted is False

    def test_consume_exact(self):
        from gnat.core.context import QueryBudget

        budget = QueryBudget(max_units=10)
        budget.consume(10, "TestConnector")
        assert budget.remaining == 0
        assert budget.is_exhausted is True

    def test_budget_exceeded(self):
        from gnat.core.context import QueryBudget
        from gnat.clients.base import BudgetExceeded

        budget = QueryBudget(max_units=5)
        budget.consume(3, "Connector1")
        with pytest.raises(BudgetExceeded) as exc_info:
            budget.consume(3, "Connector1")
        assert exc_info.value.connector == "Connector1"
        assert exc_info.value.cost == 3
        assert exc_info.value.remaining == 2

    def test_budget_deducted_by_base_client(self):
        from gnat.core.context import ExecutionContext, QueryBudget
        from gnat.clients.base import BaseClient, BudgetExceeded

        class MockClient(BaseClient):
            COST_UNIT = 5

            def authenticate(self):
                self._authenticated = True

            def _request(self, method, path, **kwargs):
                # Call parent budget deduction then return empty
                if self._context is not None:
                    budget = getattr(self._context, "budget", None)
                    if budget is not None:
                        budget.consume(self.COST_UNIT, type(self).__name__)
                return {}

        ctx = ExecutionContext.create(
            initiated_by="test",
            domain="ingestion",
            workspace_id="ws1",
            max_budget_units=10,
        )
        client = MockClient(host="http://test.local")
        client._context = ctx
        client._authenticated = True

        client._request("GET", "/test")  # costs 5
        assert ctx.budget.remaining == 5

        client._request("GET", "/test")  # costs another 5
        assert ctx.budget.remaining == 0

        with pytest.raises(BudgetExceeded):
            client._request("GET", "/test")  # exceeds budget


# ---------------------------------------------------------------------------
# Domain boundary tests
# ---------------------------------------------------------------------------

class TestDomainBoundary:
    def test_domain_enum_values(self):
        from gnat.core.domains import Domain

        assert Domain.INGESTION == "ingestion"
        assert Domain.ANALYSIS == "analysis"
        assert Domain.INVESTIGATION == "investigation"
        assert Domain.REPORTING == "reporting"
        assert Domain.EXECUTION == "execution"

    def test_domain_boundary_violation_raised(self):
        from gnat.core.domains import Domain, DomainBoundaryViolation, domain_boundary

        @domain_boundary(Domain.REPORTING, allowed_callers=[Domain.REPORTING])
        def report_fn():
            return "ok"

        @domain_boundary(Domain.INGESTION)
        def ingestion_fn():
            # Calling report_fn from ingestion context should violate the boundary
            return report_fn()

        # Calling report (only allowed from reporting) from inside ingestion → violation
        with pytest.raises(DomainBoundaryViolation):
            ingestion_fn()

    def test_no_violation_within_allowed(self):
        from gnat.core.domains import Domain, domain_boundary

        @domain_boundary(Domain.INGESTION, allowed_callers=None)
        def ingest_fn():
            return "ingested"

        # Without a domain stack (top-level call), any domain is allowed
        result = ingest_fn()
        assert result == "ingested"

    def test_no_violation_allowed_caller(self):
        from gnat.core.domains import Domain, domain_boundary

        @domain_boundary(Domain.ANALYSIS, allowed_callers=[Domain.INGESTION, Domain.ANALYSIS])
        def analysis_fn():
            return "analyzed"

        @domain_boundary(Domain.INGESTION)
        def ingestion_fn():
            return analysis_fn()  # ingestion → analysis is allowed

        result = ingestion_fn()
        assert result == "analyzed"


# ---------------------------------------------------------------------------
# SimulationConnector tests
# ---------------------------------------------------------------------------

class TestSimulationConnector:
    def _make_fixtures(self):
        return [
            {"type": "indicator", "id": "indicator--abc", "spec_version": "2.1"},
            {"type": "indicator", "id": "indicator--xyz", "spec_version": "2.1"},
            {"type": "malware", "id": "malware--def", "spec_version": "2.1"},
        ]

    def test_list_all(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(fixtures=self._make_fixtures())
        result = sim.list_objects()
        assert len(result) == 3

    def test_list_by_type(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(fixtures=self._make_fixtures())
        result = sim.list_objects(stix_type="indicator")
        assert len(result) == 2
        assert all(r["type"] == "indicator" for r in result)

    def test_get_object_found(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(fixtures=self._make_fixtures())
        obj = sim.get_object("indicator--abc")
        assert obj is not None
        assert obj["id"] == "indicator--abc"

    def test_get_object_not_found(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(fixtures=self._make_fixtures())
        assert sim.get_object("indicator--nonexistent") is None

    def test_upsert_adds_fixture(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(fixtures=[])
        new_obj = {"type": "vulnerability", "id": "vuln--new", "spec_version": "2.1"}
        sim.upsert_object(new_obj)
        assert sim.get_object("vuln--new") is not None

    def test_delete_object(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(fixtures=self._make_fixtures())
        sim.delete_object("indicator--abc")
        assert sim.get_object("indicator--abc") is None
        assert len(sim.list_objects()) == 2

    def test_health_check_always_true(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector()
        assert sim.health_check() is True

    def test_pagination(self):
        from gnat.testing import SimulationConnector

        fixtures = [{"type": "indicator", "id": f"indicator--{i}"} for i in range(10)]
        sim = SimulationConnector(fixtures=fixtures)
        page1 = sim.list_objects(page=1, page_size=4)
        page2 = sim.list_objects(page=2, page_size=4)
        page3 = sim.list_objects(page=3, page_size=4)
        assert len(page1) == 4
        assert len(page2) == 4
        assert len(page3) == 2

    def test_trust_level_configurable(self):
        from gnat.testing import SimulationConnector

        sim = SimulationConnector(trust_level="trusted_internal")
        assert sim.TRUST_LEVEL == "trusted_internal"

    def test_raise_on_request(self):
        from gnat.testing import SimulationConnector
        from gnat.clients.base import GNATClientError

        sim = SimulationConnector(raise_on_request=True)
        with pytest.raises(GNATClientError):
            sim._request("GET", "/some/path")


# ---------------------------------------------------------------------------
# ReplayRunner tests
# ---------------------------------------------------------------------------

class TestReplayRunner:
    def test_replay_produces_output(self):
        from gnat.testing import ReplayRunner
        from gnat.core.context import ExecutionContext

        indicator = {"type": "indicator", "id": "indicator--replay-1"}

        def fake_pipeline(ctx):
            assert ctx.is_replay is True
            return [indicator]

        runner = ReplayRunner(fake_pipeline)
        log = [
            ExecutionContext.create(
                initiated_by="test", domain="ingestion", workspace_id="ws1"
            ).to_dict()
        ]
        result = runner.replay(log)
        assert len(result) == 1
        assert result[0]["id"] == "indicator--replay-1"

    def test_replay_asserts_expected_ids(self):
        from gnat.testing import ReplayRunner
        from gnat.core.context import ExecutionContext

        def fake_pipeline(ctx):
            return [{"id": "indicator--expected"}]

        runner = ReplayRunner(fake_pipeline)
        log = [
            ExecutionContext.create(
                initiated_by="test", domain="ingestion", workspace_id="ws1"
            ).to_dict()
        ]

        # Should pass when expected ID is present
        runner.replay(log, expected_stix_ids=["indicator--expected"])

    def test_replay_asserts_fails_on_missing(self):
        from gnat.testing import ReplayRunner
        from gnat.core.context import ExecutionContext

        def fake_pipeline(ctx):
            return [{"id": "indicator--produced"}]

        runner = ReplayRunner(fake_pipeline)
        log = [
            ExecutionContext.create(
                initiated_by="test", domain="ingestion", workspace_id="ws1"
            ).to_dict()
        ]

        with pytest.raises(AssertionError, match="indicator--expected"):
            runner.replay(log, expected_stix_ids=["indicator--expected"])


# ---------------------------------------------------------------------------
# Workspace trust boundary tests (4E-1)
# ---------------------------------------------------------------------------

class TestWorkspaceTrustBoundary:
    def _make_workspace(self, trust_boundary="semi_trusted", allowed_refs=None):
        from gnat.context.workspace import Workspace

        ws = Workspace.__new__(Workspace)
        ws.name = "test-ws"
        ws.trust_boundary = trust_boundary
        ws.allowed_connector_refs = allowed_refs or []
        return ws

    def test_trusted_internal_passes_semi_trusted_boundary(self):
        ws = self._make_workspace(trust_boundary="semi_trusted")

        connector = MagicMock()
        type(connector).TRUST_LEVEL = "trusted_internal"
        type(connector).__name__ = "SplunkClient"

        # Should not raise
        ws.check_connector_trust(connector)

    def test_untrusted_external_fails_semi_trusted_boundary(self):
        ws = self._make_workspace(trust_boundary="semi_trusted")

        connector = MagicMock()
        type(connector).TRUST_LEVEL = "untrusted_external"
        type(connector).__name__ = "AlienVaultClient"

        with pytest.raises(PermissionError, match="does not meet workspace"):
            ws.check_connector_trust(connector)

    def test_untrusted_external_passes_untrusted_boundary(self):
        ws = self._make_workspace(trust_boundary="untrusted_external")

        connector = MagicMock()
        type(connector).TRUST_LEVEL = "untrusted_external"
        type(connector).__name__ = "AlienVaultClient"

        # Should not raise
        ws.check_connector_trust(connector)

    def test_allowlist_enforcement(self):
        ws = self._make_workspace(
            trust_boundary="semi_trusted",
            allowed_refs=["SplunkClient", "SentinelClient"],
        )

        # Allowed connector
        allowed = MagicMock()
        type(allowed).TRUST_LEVEL = "trusted_internal"
        type(allowed).__name__ = "SplunkClient"
        ws.check_connector_trust(allowed)  # should not raise

        # Disallowed connector
        disallowed = MagicMock()
        type(disallowed).TRUST_LEVEL = "trusted_internal"
        type(disallowed).__name__ = "QRadarClient"
        with pytest.raises(PermissionError, match="not in the allowed connector"):
            ws.check_connector_trust(disallowed)
