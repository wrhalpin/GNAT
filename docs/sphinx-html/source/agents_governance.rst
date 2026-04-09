Agent Governance
================

Phase 4D introduces a governance layer that controls, audits, and rate-limits every
AI agent action.  High-impact actions require human approval before execution.

.. contents:: On this page
   :local:
   :depth: 2

Overview
--------

The governance layer has two components:

* :class:`~gnat.agents.governor.AgentGovernor` — checks permissions against a
  trust-level matrix, enforces per-agent rate limits, and maintains an audit log of
  all agent actions.
* :class:`~gnat.agents.hitl.HITLGateway` — bridges ``AgentGovernor`` to the existing
  :class:`~gnat.review.service.ReviewService`; low/medium-impact actions are
  auto-approved, high-impact actions block until a human reviewer approves, and
  critical actions also trigger XSOAR notifications.

Quick Start
-----------

.. code-block:: python

   from gnat.agents.governor import AgentGovernor, AgentAction
   from gnat.agents.hitl import HITLGateway
   from gnat.policy.models import AgentActionType
   from gnat.review.service import ReviewService
   from gnat.review.store import ReviewQueueStore

   # Set up
   governor = AgentGovernor(max_calls_per_window=100, window_seconds=60)
   store = ReviewQueueStore(db_url="sqlite:///~/.gnat/gnat.db")
   store.create_all()
   gateway = HITLGateway(review_service=ReviewService(store=store))

   # Check permission
   if governor.can_act("agent-1", AgentActionType.ENRICH, "semi_trusted"):
       governor.rate_limit_check("agent-1")

       action = AgentAction(
           agent_id="agent-1",
           action_type=AgentActionType.ENRICH,
           target_ref="indicator--abc",
           impact_level="low",
       )
       approved, review_item = gateway.evaluate(action)
       governor.record_action(action)

Permission Matrix
-----------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Trust Level
     - Permitted Actions
   * - ``trusted_internal``
     - All actions (read_stix, write_stix, delete_stix, enrich, ingest, export,
       trigger_playbook, manage_workspace, escalate, hypothesize)
   * - ``semi_trusted``
     - read_stix, write_stix, enrich, ingest, hypothesize, escalate
   * - ``untrusted_external``
     - read_stix, enrich, hypothesize

Impact Tiers
------------

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Level
     - Behaviour
   * - ``low``
     - Auto-approved, logged only
   * - ``medium``
     - Auto-approved, logged only
   * - ``high``
     - Submitted to ``ReviewService`` as PENDING; blocks until approved/rejected/timed-out
   * - ``critical``
     - PENDING + XSOAR notification via ``XSOARClient.upsert_object()``

API Reference
-------------

AgentGovernor
~~~~~~~~~~~~~

.. autoclass:: gnat.agents.governor.AgentGovernor
   :members:
   :undoc-members:
   :show-inheritance:

AgentAction
~~~~~~~~~~~

.. autoclass:: gnat.agents.governor.AgentAction
   :members:
   :undoc-members:
   :show-inheritance:

HITLGateway
~~~~~~~~~~~

.. autoclass:: gnat.agents.hitl.HITLGateway
   :members:
   :undoc-members:
   :show-inheritance:

AgentActionType
~~~~~~~~~~~~~~~

.. autoclass:: gnat.policy.models.AgentActionType
   :members:
   :undoc-members:
   :show-inheritance:

Exceptions
~~~~~~~~~~

.. autoclass:: gnat.agents.governor.AgentPermissionDenied
   :show-inheritance:

.. autoclass:: gnat.agents.governor.RateLimitExceeded
   :show-inheritance:

Testing
-------

Use :class:`~gnat.testing.simulation.AgentTestHarness` for deterministic agent tests:

.. code-block:: python

   from gnat.testing import AgentTestHarness
   from gnat.policy.models import AgentActionType

   harness = AgentTestHarness()
   approved, action = harness.run_action(
       agent_id="test-agent",
       action_type=AgentActionType.ENRICH,
       impact_level="low",
       trust_level="semi_trusted",
   )
   assert approved is True
   assert len(harness.recorded_actions) == 1

See Also
--------

* :doc:`/api/core` — ExecutionContext
* :doc:`/reasoning` — Hypothesis and reasoning engine
* ADR-0045: Agent Governance
* ADR-0046: HITL Gateway
* ADR-0049: Testing Framework
