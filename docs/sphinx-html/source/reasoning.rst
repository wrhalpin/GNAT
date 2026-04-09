Reasoning Layer
===============

Phase 4C introduces a structured reasoning layer for observable prioritisation and
hypothesis lifecycle management.

.. contents:: On this page
   :local:
   :depth: 2

Overview
--------

The reasoning layer consists of three interconnected components:

* :class:`~gnat.reasoning.engine.ReasoningEngine` — scores and ranks STIX observables
  using a composite of connector trust, object age, Solr corroboration, and negative
  evidence signals.
* :class:`~gnat.reasoning.hypothesis.HypothesisEngine` — manages the
  ``propose → evaluate → close`` lifecycle for analyst hypotheses stored as custom
  STIX SDOs.
* :class:`~gnat.stix.sdos.negative_evidence.NegativeEvidenceRecord` — suppresses
  redundant connector re-queries within a configurable TTL window.

Quick Start
-----------

.. code-block:: python

   from gnat.reasoning.engine import ReasoningEngine
   from gnat.reasoning.hypothesis import HypothesisEngine
   from gnat.core.context import ExecutionContext
   from gnat.context.workspace import WorkspaceManager

   manager = WorkspaceManager.default()
   ctx = ExecutionContext.create(
       initiated_by="analyst",
       domain="analysis",
       workspace_id="my-ws",
   )

   # Score observables
   engine = ReasoningEngine(manager=manager, workspace_name="my-ws")
   ws = manager.open("my-ws")
   results = engine.prioritize(list(ws.objects.values()), context=ctx)
   for obs, score, explanation in results:
       print(f"{score:.2f}  {explanation['summary']}")

   # Propose hypothesis
   h_engine = HypothesisEngine(manager=manager, workspace_name="my-ws")
   h = h_engine.propose("APT29 behind Q1 campaign", confidence=0.2)
   h = h_engine.evaluate(h.id)
   h = h_engine.close(h.id, verdict="confirmed")

API Reference
-------------

ReasoningEngine
~~~~~~~~~~~~~~~

.. autoclass:: gnat.reasoning.engine.ReasoningEngine
   :members:
   :undoc-members:
   :show-inheritance:

HypothesisEngine
~~~~~~~~~~~~~~~~

.. autoclass:: gnat.reasoning.hypothesis.HypothesisEngine
   :members:
   :undoc-members:
   :show-inheritance:

STIXHypothesis SDO
~~~~~~~~~~~~~~~~~~

.. autoclass:: gnat.stix.sdos.hypothesis.STIXHypothesis
   :members:
   :undoc-members:
   :show-inheritance:

NegativeEvidenceRecord SDO
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: gnat.stix.sdos.negative_evidence.NegativeEvidenceRecord
   :members:
   :undoc-members:
   :show-inheritance:

Scoring Formula
---------------

The composite score is computed as:

.. code-block:: text

   score = trust_weight × 0.4
         + age_factor    × 0.3
         + corroboration × 0.3
         - neg_penalty   × 0.5

   clamped to [0.0, 1.0]

Where:

* **trust_weight** — ``trusted_internal``→0.9, ``semi_trusted``→0.6, ``untrusted_external``→0.3
* **age_factor** — 1.0 decaying by 5% per day from ``modified`` timestamp (floor 0.0)
* **corroboration** — Solr hit count × 0.05, capped at 0.25
* **neg_penalty** — min(0.3 × fresh NegativeEvidenceRecord count, 0.6)

See Also
--------

* :doc:`/api/core` — ExecutionContext and QueryBudget
* ADR-0042: Hypothesis Engine
* ADR-0043: Negative Evidence
* ADR-0044: Reasoning Engine
