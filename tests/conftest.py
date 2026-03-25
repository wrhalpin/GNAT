"""
conftest.py — shared pytest fixtures for CTM-SAK test suite.
"""

import pytest
from unittest.mock import MagicMock, patch
from ctm_sak.client import SAKClient


# ---------------------------------------------------------------------------
# Mock HTTP layer
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_http_response():
    """Factory fixture: returns a callable that builds fake urllib3 responses."""
    def _make(status=200, body=b'{"data": []}'):
        resp = MagicMock()
        resp.status = status
        resp.data = body
        return resp
    return _make


@pytest.fixture
def mock_pool_manager(mock_http_response):
    """Patch urllib3.PoolManager so no real HTTP is issued in unit tests."""
    with patch("urllib3.PoolManager") as MockPM:
        instance = MockPM.return_value
        instance.request.return_value = mock_http_response()
        yield instance


# ---------------------------------------------------------------------------
# Client fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def minimal_config(tmp_path):
    """Write a minimal INI config to a temp file and return its path."""
    cfg = tmp_path / "config.ini"
    cfg.write_text(
        "[DEFAULT]\n"
        "timeout = 10\n"
        "verify_ssl = false\n\n"
        "[threatq]\n"
        "host = https://fake-threatq.example.com\n"
        "client_id = test-id\n"
        "client_secret = test-secret\n"
        "auth_type = oauth2\n\n"
        "[crowdstrike]\n"
        "host = https://fake-cs.example.com\n"
        "client_id = cs-id\n"
        "client_secret = cs-secret\n"
        "auth_type = oauth2\n\n"
        "[proofpoint]\n"
        "host = https://fake-pp.example.com\n"
        "service_principal = pp-sp\n"
        "secret = pp-secret\n"
        "auth_type = basic\n\n"
        "[netskope]\n"
        "host = https://fake-ns.example.com\n"
        "api_token = ns-token\n"
        "auth_type = token\n\n"
        "[xsoar]\n"
        "host = https://fake-xsoar.example.com\n"
        "api_key = xsoar-key\n"
        "auth_type = api_key\n\n"
        "[recordedfuture]\n"
        "host = https://fake-rf.example.com\n"
        "api_token = rf-token\n"
        "auth_type = token\n"
    )
    return str(cfg)


@pytest.fixture
def sak_client(minimal_config):
    """Return a SAKClient loaded from the minimal test config."""
    return SAKClient(config_path=minimal_config)
