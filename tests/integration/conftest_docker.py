"""
tests/integration/conftest_docker.py
======================================

Session-scoped fixtures for the Docker integration test harness.

These fixtures manage the lifecycle of:
  - External Docker containers (Elasticsearch, Solr) via docker-compose.test.yml
  - An in-process subprocess GNAT TAXII server on a free ephemeral port

Usage::

    pytest tests/integration/ --run-docker -v

All Docker tests are marked ``@pytest.mark.docker`` and skipped by default
unless the ``--run-docker`` flag is passed.  The ``--run-docker`` flag also
implicitly enables ``--run-integration`` so that Docker tests can share
helpers from conftest.py / test_integration.py if needed.

No third-party ``testcontainers`` or ``pytest-docker`` package is required —
lifecycle is managed with plain ``subprocess`` and ``urllib.request``.
"""

from __future__ import annotations

import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).parent.parent.parent
_COMPOSE_FILE = _REPO_ROOT / "docker" / "test" / "docker-compose.test.yml"
_TEST_INI = _REPO_ROOT / "docker" / "test" / "gnat.test.ini"

# ---------------------------------------------------------------------------
# pytest hooks
# ---------------------------------------------------------------------------


def pytest_addoption(parser):
    parser.addoption(
        "--run-docker",
        action="store_true",
        default=False,
        help="Run Docker-based integration tests (requires Docker and docker compose).",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "docker: Docker-based integration tests — require running Docker daemon",
    )


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--run-docker"):
        skip = pytest.mark.skip(reason="Pass --run-docker to run Docker integration tests")
        for item in items:
            if "docker" in item.keywords:
                item.add_marker(skip)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_http(url: str, timeout: int = 120, interval: float = 2.0) -> bool:
    """Poll *url* with HTTP GET until a non-5xx response arrives or *timeout* expires.

    Returns ``True`` on success, ``False`` on timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def _docker_compose(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run ``docker compose -f <compose-file> <args>``."""
    cmd = [
        "docker", "compose",
        "-f", str(_COMPOSE_FILE),
        *args,
    ]
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# Docker compose lifecycle (session-scoped)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def docker_services(request):
    """Start all test containers and yield; tear down at session end.

    Skips automatically when ``--run-docker`` was not passed.
    """
    if not request.config.getoption("--run-docker"):
        pytest.skip("--run-docker not set")

    # Pull + start containers in detached mode
    _docker_compose(["up", "-d", "--pull", "missing"])

    yield  # tests run here

    # Tear down and remove volumes after all Docker tests finish
    _docker_compose(["down", "-v"], check=False)


@pytest.fixture(scope="session")
def elasticsearch_url(docker_services):
    """Return the Elasticsearch base URL, waiting until it is healthy."""
    url = "http://localhost:19200"
    assert _wait_for_http(f"{url}/_cluster/health", timeout=120), (
        "Elasticsearch did not become healthy within 120 s — check `docker compose logs elasticsearch`"
    )
    return url


@pytest.fixture(scope="session")
def solr_url(docker_services):
    """Return the Solr base URL, waiting until the gnat core is healthy."""
    url = "http://localhost:18983"
    assert _wait_for_http(f"{url}/solr/gnat/admin/ping", timeout=180), (
        "Solr gnat core did not become healthy within 180 s — check `docker compose logs solr`"
    )
    return url


# ---------------------------------------------------------------------------
# GNAT TAXII server (subprocess, no Docker)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def gnat_taxii_server(request, tmp_path_factory):
    """Spawn a GNAT TAXII server subprocess on a free port.

    Yields a dict with ``base_url`` and ``api_key``.
    The process is terminated when the session ends.

    Does NOT require ``--run-docker``; usable with just ``--run-integration``.
    """
    port = _free_port()
    api_key = "test-docker-api-key-1234"

    workspace_dir = tmp_path_factory.mktemp("taxii_ws")
    ini_content = f"""[gnat]
workspace_dir = {workspace_dir}
"""
    ini_path = workspace_dir / "gnat.ini"
    ini_path.write_text(ini_content)

    cmd = [
        sys.executable, "-m", "gnat.cli.main",
        "taxii",
        "--host", "127.0.0.1",
        "--port", str(port),
        "--api-key", api_key,
    ]

    env = os.environ.copy()
    env["GNAT_CONFIG"] = str(ini_path)

    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    base_url = f"http://127.0.0.1:{port}"

    # Wait for the server to be ready
    ready = _wait_for_http(f"{base_url}/taxii2/", timeout=30, interval=0.5)
    if not ready:
        proc.terminate()
        stdout = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
        stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        pytest.fail(
            f"TAXII server did not start within 30 s\n"
            f"stdout: {stdout}\nstderr: {stderr}"
        )

    yield {"base_url": base_url, "api_key": api_key, "port": port}

    # Graceful shutdown
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
