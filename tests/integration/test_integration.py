"""
tests/integration/test_integration.py
=======================================

Integration tests for GNAT — these tests issue REAL HTTP requests and
require live credentials in a ``gnat_integration.ini`` file or the
``GNAT_CONFIG`` environment variable.

Run with::

    GNAT_CONFIG=/path/to/real.ini pytest tests/integration/ -v -m integration

All tests are marked ``@pytest.mark.integration`` and skipped by default in
CI unless the ``--run-integration`` flag is passed.

Prerequisites (per target):
    - ThreatQ: valid host, client_id, client_secret
    - CrowdStrike: valid client_id, client_secret
    - Proofpoint: valid service_principal, secret
    - Netskope: valid api_token
    - XSOAR: valid api_key (+ auth_id for MSSP)
    - Recorded Future: valid api_token
"""

import os

import pytest

from gnat.client import GNATClient
from gnat.orm.indicator import Indicator

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def cli():
    """Return a GNATClient using the real integration config."""
    config_path = os.environ.get("GNAT_CONFIG")
    return GNATClient(config_path=config_path)


# ---------------------------------------------------------------------------
# ThreatQ Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestThreatQIntegration:
    def test_ping(self, cli):
        cli.connect("threatq")
        assert cli.ping() is True

    def test_list_indicators(self, cli):
        cli.connect("threatq")
        results = cli.client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)

    def test_create_and_delete_indicator(self, cli):
        cli.connect("threatq")
        ind = Indicator(
            client=cli,
            name="gnat-integration-test",
            pattern="[ipv4-addr:value = '198.51.100.1']",
            indicator_types=["malicious-activity"],
        )
        ind.save()
        assert ind.id is not None

        # Clean up
        ind.delete()


# ---------------------------------------------------------------------------
# CrowdStrike Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCrowdStrikeIntegration:
    def test_ping(self, cli):
        cli.connect("crowdstrike")
        assert cli.ping() is True

    def test_list_iocs(self, cli):
        cli.connect("crowdstrike")
        results = cli.client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# Proofpoint Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestProofpointIntegration:
    def test_ping(self, cli):
        cli.connect("proofpoint")
        assert cli.ping() is True

    def test_list_messages(self, cli):
        cli.connect("proofpoint")
        results = cli.client.list_objects("indicator")
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# Netskope Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestNetskopeIntegration:
    def test_ping(self, cli):
        cli.connect("netskope")
        assert cli.ping() is True

    def test_list_urllists(self, cli):
        cli.connect("netskope")
        results = cli.client.list_objects("indicator")
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# XSOAR Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestXSOARIntegration:
    def test_ping(self, cli):
        cli.connect("xsoar")
        assert cli.ping() is True

    def test_search_indicators(self, cli):
        cli.connect("xsoar")
        results = cli.client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)


# ---------------------------------------------------------------------------
# Recorded Future Integration
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRecordedFutureIntegration:
    def test_ping(self, cli):
        cli.connect("recordedfuture")
        assert cli.ping() is True

    def test_list_indicators(self, cli):
        cli.connect("recordedfuture")
        results = cli.client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)
