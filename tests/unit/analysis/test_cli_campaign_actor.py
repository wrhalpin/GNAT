# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/analysis/test_cli_campaign_actor.py
=================================================

Unit tests for the ``gnat campaign`` and ``gnat actor`` CLI subcommands
(Phase 5 of the attribution & campaign tracking extension).

Campaign tests require SQLAlchemy (gnat[persist]) and skip cleanly
when it's missing. Actor tests use file-based storage and always run.
"""

from __future__ import annotations

import json

import pytest

from gnat.cli.main import main as gnat_main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def run_cli(capsys, monkeypatch, tmp_path):
    """Invoke gnat_main() with an ephemeral DB + actor dir."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GNAT_DB_URL", f"sqlite:///{db_path}")
    actor_dir = tmp_path / "actors"
    actor_dir.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))

    def _run(*argv: str) -> tuple[int, str, str]:
        exit_code = gnat_main(list(argv))
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return _run


# ===========================================================================
# gnat actor (file-based — always runs)
# ===========================================================================


class TestActorCLI:
    def test_create(self, run_cli):
        exit_code, out, _ = run_cli(
            "actor", "create", "--name", "SANDWORM", "--type", "nation-state"
        )
        assert exit_code == 0
        assert "SANDWORM" in out

    def test_create_json(self, run_cli):
        exit_code, out, _ = run_cli(
            "--output", "json", "actor", "create", "--name", "APT28", "--mitre-group", "G0007"
        )
        assert exit_code == 0
        data = json.loads(out)
        assert data["name"] == "APT28"
        assert data["mitre_group_id"] == "G0007"

    def test_list_empty(self, run_cli):
        exit_code, out, _ = run_cli("actor", "list")
        assert exit_code == 0
        assert "no actor" in out

    def test_create_then_list(self, run_cli):
        run_cli("actor", "create", "--name", "TestActor")
        exit_code, out, _ = run_cli("actor", "list")
        assert exit_code == 0
        assert "TestActor" in out

    def test_show(self, run_cli):
        _, out, _ = run_cli("--output", "json", "actor", "create", "--name", "ShowMe")
        actor_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli("actor", "show", actor_id)
        assert exit_code == 0
        assert "ShowMe" in out2

    def test_show_not_found(self, run_cli):
        exit_code, _, _ = run_cli("actor", "show", "threat-actor--nope")
        assert exit_code == 2

    def test_alias(self, run_cli):
        _, out, _ = run_cli("--output", "json", "actor", "create", "--name", "SANDWORM")
        actor_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli(
            "actor", "alias", actor_id, "--add", "Voodoo Bear", "--source", "CrowdStrike"
        )
        assert exit_code == 0
        assert "Voodoo Bear" in out2

    def test_capability(self, run_cli):
        _, out, _ = run_cli("--output", "json", "actor", "create", "--name", "APT28")
        actor_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli(
            "actor",
            "capability",
            actor_id,
            "--technique",
            "T1059.003",
            "--proficiency",
            "expert",
        )
        assert exit_code == 0
        assert "T1059.003" in out2


# ===========================================================================
# gnat campaign (SQLAlchemy-gated)
# ===========================================================================


class TestCampaignCLI:
    @pytest.fixture(autouse=True)
    def _require_sqlalchemy(self):
        pytest.importorskip("sqlalchemy", reason="gnat[persist] not installed")

    def test_list_empty(self, run_cli):
        exit_code, out, _ = run_cli("campaign", "list")
        assert exit_code == 0
        assert "no campaigns" in out

    def test_create(self, run_cli):
        exit_code, out, _ = run_cli("campaign", "create", "--name", "Operation Sunrise")
        assert exit_code == 0
        assert "Operation Sunrise" in out

    def test_create_json(self, run_cli):
        exit_code, out, _ = run_cli(
            "--output",
            "json",
            "campaign",
            "create",
            "--name",
            "Op Test",
        )
        assert exit_code == 0
        data = json.loads(out)
        assert data["name"] == "Op Test"
        assert data["status"] == "suspected"

    def test_create_then_list(self, run_cli):
        run_cli("campaign", "create", "--name", "Visible Campaign")
        exit_code, out, _ = run_cli("campaign", "list")
        assert exit_code == 0
        assert "Visible" in out

    def test_show(self, run_cli):
        _, out, _ = run_cli("--output", "json", "campaign", "create", "--name", "ShowMe")
        camp_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli("campaign", "show", camp_id)
        assert exit_code == 0
        assert "ShowMe" in out2

    def test_show_not_found(self, run_cli):
        exit_code, _, _ = run_cli("campaign", "show", "campaign--nope")
        assert exit_code == 2

    def test_transition(self, run_cli):
        _, out, _ = run_cli("--output", "json", "campaign", "create", "--name", "Trans")
        camp_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli("campaign", "transition", camp_id, "active")
        assert exit_code == 0
        assert "active" in out2

    def test_link_indicator(self, run_cli):
        _, out, _ = run_cli("--output", "json", "campaign", "create", "--name", "LinkTest")
        camp_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli("campaign", "link", camp_id, "--indicator", "indicator--abc")
        assert exit_code == 0
        assert "indicator--abc" in out2

    def test_attribute(self, run_cli):
        _, out, _ = run_cli("--output", "json", "campaign", "create", "--name", "AttrTest")
        camp_id = json.loads(out)["id"]
        exit_code, out2, _ = run_cli(
            "campaign",
            "attribute",
            camp_id,
            "--actor",
            "threat-actor--apt28",
            "--rationale",
            "TTP overlap",
        )
        assert exit_code == 0
        assert "apt28" in out2

    def test_promote_cluster(self, run_cli, tmp_path):
        cluster = {
            "id": "cluster-test",
            "label": "Test Cluster",
            "member_ids": ["ioc-1", "ioc-2"],
            "signals": ["subnet_overlap"],
            "confidence": {"stix_confidence": 70},
            "suggested_campaign": "Promoted Op",
            "suggested_actor": None,
        }
        cluster_file = tmp_path / "cluster.json"
        cluster_file.write_text(json.dumps(cluster))
        exit_code, out, _ = run_cli("campaign", "promote-cluster", str(cluster_file))
        assert exit_code == 0
        assert "Promoted" in out
