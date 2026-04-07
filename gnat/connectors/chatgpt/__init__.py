# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
# gnat/connectors/chatgpt/__init__.py
"""
gnat.connectors.chatgpt
===========================

Public API surface for the ``gnat.gnat.connectors.chatgpt`` package.

Exports: ``ChatGPTClient``.
"""
from .client import ChatGPTClient

__all__ = ["ChatGPTClient"]
