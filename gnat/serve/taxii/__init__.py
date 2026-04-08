# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.taxii
================
TAXII 2.1 server — exposes GNAT workspaces as TAXII collections.

Each workspace becomes a TAXII collection under a single API root.
The server implements the mandatory TAXII 2.1 endpoints:

* ``GET  /taxii2/``                                      — Discovery
* ``GET  /taxii2/roots/gnat/``                           — API Root info
* ``GET  /taxii2/roots/gnat/collections/``               — List collections
* ``GET  /taxii2/roots/gnat/collections/{id}/``          — Collection info
* ``GET  /taxii2/roots/gnat/collections/{id}/objects/``  — Get objects (bundle)
* ``POST /taxii2/roots/gnat/collections/{id}/objects/``  — Add objects
* ``GET  /taxii2/roots/gnat/collections/{id}/manifest/`` — Object manifest
* ``GET  /taxii2/roots/gnat/collections/{id}/objects/{object_id}/``  — Single obj

Usage::

    from gnat.serve.taxii import build_taxii_app
    from gnat.context import WorkspaceManager

    manager = WorkspaceManager.default()
    app = build_taxii_app(manager, api_key="s3cr3t")

    # Or via CLI:
    # gnat serve taxii --api-key s3cr3t --port 8090
"""

from gnat.serve.taxii.app import build_taxii_app, run_taxii_server

__all__ = ["build_taxii_app", "run_taxii_server"]
