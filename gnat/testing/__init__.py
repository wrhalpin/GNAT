# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.testing
============

Phase 4E-3 testing framework for GNAT.

Provides simulation and replay primitives that allow full pipeline tests
without network access:

* :class:`SimulationConnector` — a ``BaseClient`` subclass that returns
  canned STIX fixtures for any query; no real HTTP calls.
* :class:`ReplayRunner` — replays a recorded ``execution_log`` sequence
  through the current pipeline, asserting output matches.
* :class:`AgentTestHarness` — wraps :class:`~gnat.agents.governor.AgentGovernor`
  and :class:`~gnat.agents.hitl.HITLGateway` with mock approval responses
  for deterministic agent action tests.

Usage
-----
::

    from gnat.testing import SimulationConnector, AgentTestHarness

    connector = SimulationConnector(fixtures=[indicator_dict])
    harness = AgentTestHarness()
    harness.governor.can_act("agent-1", AgentActionType.ENRICH, "semi_trusted")
"""

from gnat.testing.simulation import AgentTestHarness, ReplayRunner, SimulationConnector

__all__ = ["SimulationConnector", "ReplayRunner", "AgentTestHarness"]
