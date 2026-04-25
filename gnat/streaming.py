# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.streaming
==============

Streaming event types for live progress reporting on long-running GNAT
operations.

These lightweight dataclasses are used **both** by the job framework and
directly by consumers that want incremental output from operations such as
investigation building, gap detection, report drafting, and LLM streaming.

Event hierarchy::

    StreamEvent           # base (abstract-ish)
    +-- ProgressEvent     # fractional progress + human message
    +-- TokenEvent        # incremental LLM token
    +-- ResultEvent       # final structured result
    +-- ErrorEvent        # non-fatal error description

Usage::

    from gnat.streaming import ProgressEvent

    def my_callback(progress: float, message: str) -> None:
        print(f"[{progress:.0%}] {message}")

    graph = builder.build_with_progress(seeds, progress_callback=my_callback)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class StreamEvent:
    """
    Base class for all streaming events.

    Subclasses carry payload specific to the event kind (progress fraction,
    LLM token text, structured result, or error description).
    """


@dataclass
class ProgressEvent(StreamEvent):
    """
    Fractional progress update.

    Parameters
    ----------
    progress : float
        Completion fraction in the range ``0.0`` -- ``1.0``.
    message : str
        Human-readable status message.
    """

    progress: float
    message: str = ""


@dataclass
class TokenEvent(StreamEvent):
    """
    Incremental LLM token.

    Parameters
    ----------
    text : str
        The token text received from the LLM stream.
    """

    text: str


@dataclass
class ResultEvent(StreamEvent):
    """
    Final structured result of a streaming operation.

    Parameters
    ----------
    result : dict
        Arbitrary result payload.
    """

    result: dict


@dataclass
class ErrorEvent(StreamEvent):
    """
    Non-fatal error encountered during a streaming operation.

    Parameters
    ----------
    error : str
        Human-readable error description.
    """

    error: str
