# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.cli
========================================

CLIBackend for interactive prompt at the terminal.
"""

import json
import queue
import sys
import threading
from typing import Optional

from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationOutcome,
    ConfirmationRequest,
    ConfirmationTimeout,
    PromptResult,
)


class CLIBackend(ConfirmationBackend):
    """
    Interactive CLI backend.

    Renders the request to stderr, reads the decision from stdin.
    Responses (case-sensitive):

    - ``a`` — approve
    - ``d`` — deny
    - ``n`` — approve with a note
    - ``N`` — deny with a note

    Enforces ``request.timeout_seconds``: if the analyst does not answer
    in time, raises :class:`ConfirmationTimeout` (the broker translates
    this per the matched policy).
    """

    def prompt(self, request: ConfirmationRequest) -> PromptResult:
        """Prompt the analyst at the terminal."""
        self._render_request(request)

        while True:
            response = self._input_with_timeout(
                "\n[a]pprove / [d]eny / [n]ote-and-approve / [N]ote-and-deny: ",
                request,
            )
            if response is None:  # EOF / interrupt: fail closed
                return PromptResult(ConfirmationOutcome.DENIED, note="input closed")

            response = response.strip()
            if response == "a":
                return PromptResult(ConfirmationOutcome.APPROVED)
            if response == "d":
                return PromptResult(ConfirmationOutcome.DENIED)
            if response == "n":
                note = self._input_with_timeout("Note: ", request)
                return PromptResult(
                    ConfirmationOutcome.APPROVED,
                    note=(note or "").strip() or None,
                )
            if response == "N":
                note = self._input_with_timeout("Note: ", request)
                return PromptResult(
                    ConfirmationOutcome.DENIED,
                    note=(note or "").strip() or None,
                )
            print("Invalid response. Use a / d / n / N.", file=sys.stderr)

    def _input_with_timeout(self, prompt_text: str, request: ConfirmationRequest) -> Optional[str]:
        """
        Read a line from stdin, enforcing the request timeout.

        Returns None on EOF or KeyboardInterrupt (caller fails closed).
        Raises ConfirmationTimeout if nothing is entered in time.
        """
        result_queue: queue.Queue[Optional[str]] = queue.Queue()

        def _reader() -> None:
            try:
                result_queue.put(input(prompt_text))
            except (EOFError, KeyboardInterrupt):
                result_queue.put(None)

        thread = threading.Thread(target=_reader, daemon=True)
        thread.start()
        try:
            return result_queue.get(timeout=request.timeout_seconds)
        except queue.Empty:
            print("\n[timeout]", file=sys.stderr)
            raise ConfirmationTimeout(request) from None

    @staticmethod
    def _render_request(request: ConfirmationRequest) -> None:
        """Pretty-print a confirmation request to stderr."""
        lines = [
            "=" * 70,
            f"[CONFIRM] {request.agent} wants to: {request.action}",
            f"  Workspace:  {request.workspace}",
            f"  Scope:      {request.scope}",
            f"  Risk:       {request.risk}",
            f"  Reason:     {request.reason}",
            f"  Timeout:    {request.timeout_seconds}s",
            "  Subject:",
        ]
        try:
            subject_str = json.dumps(request.subject, indent=4, default=str)
            lines.extend(f"    {line}" for line in subject_str.splitlines())
        except (TypeError, ValueError):
            lines.append(f"    {request.subject}")
        lines.append("=" * 70)
        print("\n" + "\n".join(lines), file=sys.stderr)
