# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.jobs.decorators
=======================

Re-export of the :func:`~gnat.jobs.registry.job` decorator for convenience.

The decorator is defined in :mod:`gnat.jobs.registry` alongside the
:class:`~gnat.jobs.registry.JobRegistry` class to keep the registry dict
and registration logic co-located.  This module provides a conventional
import path::

    from gnat.jobs.decorators import job

    @job("my_analysis")
    def run_my_analysis(request_payload, progress_callback, cancel_event):
        ...
"""

from gnat.jobs.registry import job

__all__ = ["job"]
