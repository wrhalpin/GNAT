# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.gitguardian
===============================

GitGuardian connector for real-time secret incident telemetry across
GitHub, GitLab, Bitbucket, Slack, Jira, Confluence, and ~550+ other
secret types.  Consumes the v1 REST API at ``https://api.gitguardian.com``.
"""

from .client import GitGuardianClient

__all__ = ["GitGuardianClient"]
