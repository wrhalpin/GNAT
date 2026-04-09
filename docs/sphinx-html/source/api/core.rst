gnat.core — Execution Context & Domain Boundaries
===================================================

Phase 4A cross-cutting infrastructure: execution tracing, domain boundary
enforcement, connector trust, and query budget management.

.. automodule:: gnat.core
   :members:
   :undoc-members:

ExecutionContext
---------------

.. autoclass:: gnat.core.context.ExecutionContext
   :members:
   :undoc-members:
   :show-inheritance:

QueryBudget
-----------

.. autoclass:: gnat.core.context.QueryBudget
   :members:
   :undoc-members:
   :show-inheritance:

Domain Boundary Enforcement
---------------------------

.. automodule:: gnat.core.domains
   :members:
   :undoc-members:

.. autoclass:: gnat.core.domains.Domain
   :members:
   :undoc-members:

.. autoclass:: gnat.core.domains.DomainBoundaryViolation
   :show-inheritance:

.. autoclass:: gnat.core.domains.TrustLevelViolation
   :show-inheritance:

.. autofunction:: gnat.core.domains.domain_boundary

.. autofunction:: gnat.core.domains.require_trust_level
