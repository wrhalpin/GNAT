# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules
=======================

Declarative rule engine for hypothesis evaluation. Rules are authored
as ``.hy`` files, loaded dynamically, and return status transition
decisions without mutating state directly.

Install Hy dependency with ``pip install "gnat[rules]"``.
"""
