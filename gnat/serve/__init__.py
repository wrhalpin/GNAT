"""
gnat.serve
==========
FastAPI web dashboard for GNAT.

Provides a browser-based interface for the Research Library, Reports,
and Scheduler — secured by ``X-Api-Key`` header authentication.

Quick start::

    from gnat.serve.app import run
    run(api_key="my-secret-key", port=8088)

Or via CLI::

    gnat serve --api-key my-secret-key --port 8088
"""

from .app import create_app, run

__all__ = ["create_app", "run"]
