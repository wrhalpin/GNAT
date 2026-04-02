from pathlib import Path

from gnat.agents.quality.contract import ContractAgent, ConnectorContractProfile


def test_contract_agent_flags_missing_required_file(tmp_path: Path) -> None:
    connector_dir = tmp_path / "gnat" / "connectors" / "demo"
    connector_dir.mkdir(parents=True)
    (connector_dir / "__init__.py").write_text("class DemoConnector: pass", encoding="utf-8")

    agent = ContractAgent(repo_root=str(tmp_path))
    profile = ConnectorContractProfile(
        connector_name="demo",
        connector_path="gnat/connectors/demo",
        required_files=["__init__.py", "client.py"],
        required_symbols=["DemoConnector"],
    )

    result = agent.evaluate(profile)

    assert result.passed is False
    assert any("required file missing: client.py" in item for item in result.errors)


def test_contract_agent_passes_when_structure_is_present(tmp_path: Path) -> None:
    connector_dir = tmp_path / "gnat" / "connectors" / "demo"
    connector_dir.mkdir(parents=True)
    (connector_dir / "__init__.py").write_text("", encoding="utf-8")
    (connector_dir / "client.py").write_text("class DemoConnector: pass", encoding="utf-8")

    agent = ContractAgent(repo_root=str(tmp_path))
    profile = ConnectorContractProfile(
        connector_name="demo",
        connector_path="gnat/connectors/demo",
        required_files=["__init__.py", "client.py"],
        required_symbols=["DemoConnector"],
    )

    result = agent.evaluate(profile)

    assert result.passed is True
    assert result.errors == []
