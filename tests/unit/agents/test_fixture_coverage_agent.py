from pathlib import Path

from gnat.agents.quality.fixture_coverage import FixtureCoverageAgent


def test_fixture_coverage_agent_scores_fixture_depth(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "data"
    fixtures.mkdir(parents=True)
    (fixtures / "cribl_happy_fixture.json").write_text("{}", encoding="utf-8")
    (fixtures / "cribl_error_fixture.json").write_text("{}", encoding="utf-8")
    (fixtures / "cribl_v1_fixture.json").write_text("{}", encoding="utf-8")

    agent = FixtureCoverageAgent(repo_root=str(tmp_path))
    result = agent.evaluate_connector("cribl", ["tests/data/cribl_*fixture.json"])

    assert result.fixture_count == 3
    assert result.has_error_fixture is True
    assert result.has_backward_fixture is True
    assert result.score == 100


def test_fixture_coverage_agent_warns_on_missing_depth(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "data"
    fixtures.mkdir(parents=True)
    (fixtures / "alienvault_fixture.json").write_text("{}", encoding="utf-8")

    agent = FixtureCoverageAgent(repo_root=str(tmp_path))
    result = agent.evaluate_connector("alienvault", ["tests/data/alienvault*"])

    assert result.fixture_count == 1
    assert "low fixture count" in result.warnings
    assert "no error-path fixture detected" in result.warnings
