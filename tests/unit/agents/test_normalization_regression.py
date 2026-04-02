"""Unit tests for the normalization regression agent."""

from __future__ import annotations

from pathlib import Path

from gnat.agents.quality.normalization_regression import (
    GoldenFixture,
    NormalizationRegressionAgent,
    RegressionPolicy,
    render_regression_report,
)


DATA_DIR = Path(__file__).parent / "data"


class TestGoldenFixture:
    def test_loads_fixture_from_path(self):
        fixture = GoldenFixture.from_path(DATA_DIR / "cribl_normalization_fixture.json")
        assert fixture.name == "cribl_event_to_observed_data"
        assert fixture.connector == "cribl"
        assert fixture.method == "event_to_observed_data"
        assert "created" in fixture.policy.ignore_fields


class TestNormalizationRegressionAgent:
    def test_run_passes_for_known_good_fixture(self):
        agent = NormalizationRegressionAgent(fixture_root=DATA_DIR)
        run = agent.run(connector="cribl")
        assert run.passed is True
        assert len(run.results) == 1
        assert run.results[0].passed is True

    def test_run_fixture_detects_missing_expected_field(self):
        agent = NormalizationRegressionAgent(fixture_root=DATA_DIR)
        fixture = GoldenFixture(
            name="cribl_missing_field",
            connector="cribl",
            mapper="gnat.connectors.cribl.stix_mapper:CriblSTIXMapper",
            method="event_to_observed_data",
            input={"_raw": "hello", "ip": "1.2.3.4"},
            expected={"type": "observed-data", "x_cribl_raw": "hello", "bogus": "missing"},
            policy=RegressionPolicy(ignore_fields={"created", "modified", "first_observed", "last_observed", "id", "object_refs"}, allow_additional_fields=True),
        )

        result = agent.run_fixture(fixture)
        assert result.passed is False
        assert any("bogus" in diff for diff in result.differences)

    def test_list_order_is_normalized_during_comparison(self):
        agent = NormalizationRegressionAgent(fixture_root=DATA_DIR)
        fixture = GoldenFixture(
            name="list_order_fixture",
            connector="cribl",
            mapper="gnat.connectors.cribl.stix_mapper:CriblSTIXMapper",
            method="_extract_scos_from_event",
            input={"url": "https://evil.example", "ip": "1.2.3.4", "domain": "evil.example"},
            expected=[
                {"type": "url", "value": "https://evil.example"},
                {"type": "domain-name", "value": "evil.example"},
                {"type": "ipv4-addr", "value": "1.2.3.4"},
            ],
            policy=RegressionPolicy(ignore_fields={"id"}, allow_additional_fields=True),
        )

        result = agent.run_fixture(fixture)
        assert result.passed is True

    def test_report_includes_failed_fixture_name(self):
        agent = NormalizationRegressionAgent(fixture_root=DATA_DIR)
        fixture = GoldenFixture(
            name="failing_fixture",
            connector="cribl",
            mapper="gnat.connectors.cribl.stix_mapper:CriblSTIXMapper",
            method="event_to_observed_data",
            input={"_raw": "hello"},
            expected={"type": "indicator"},
            policy=RegressionPolicy(ignore_fields={"created", "modified", "first_observed", "last_observed", "id", "object_refs"}, allow_additional_fields=True),
        )

        run = agent.run()
        run.results.append(agent.run_fixture(fixture))
        report = render_regression_report(run)
        assert "failing_fixture" in report
        assert "expected 'indicator'" in report
