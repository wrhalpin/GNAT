from gnat.agents.quality.normalization_regression import (
    NormalizationRegressionAgent,
    RegressionFixture,
    RegressionPolicy,
)


def test_normalization_regression_allows_ignored_paths() -> None:
    agent = NormalizationRegressionAgent({
        "cribl": lambda payload: {
            "type": "indicator",
            "id": "generated-runtime-id",
            "value": payload["value"],
        }
    })

    fixture = RegressionFixture(
        connector_name="cribl",
        fixture_name="stable-output",
        input_payload={"value": "1.2.3.4"},
        expected_output={
            "type": "indicator",
            "id": "golden-id",
            "value": "1.2.3.4",
        },
        policy=RegressionPolicy(ignored_paths=["$.id"]),
    )

    result = agent.run_fixture(fixture)

    assert result.passed is True
    assert result.differences == []


def test_normalization_regression_detects_semantic_drift() -> None:
    agent = NormalizationRegressionAgent({
        "cribl": lambda payload: {
            "type": "malware",
            "value": payload["value"],
        }
    })

    fixture = RegressionFixture(
        connector_name="cribl",
        fixture_name="semantic-drift",
        input_payload={"value": "1.2.3.4"},
        expected_output={"type": "indicator", "value": "1.2.3.4"},
    )

    result = agent.run_fixture(fixture)

    assert result.passed is False
    assert any(diff.path == "$.type" for diff in result.differences)
