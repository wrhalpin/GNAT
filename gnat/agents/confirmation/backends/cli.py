# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.backends.cli
========================================

CLIBackend for interactive prompt at the terminal.
"""

import sys
import json
from gnat.agents.confirmation.backends.base import ConfirmationBackend
from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationOutcome,
    ConfirmationTimeout,
)


class CLIBackend(ConfirmationBackend):
    """
    Interactive CLI backend.

    Renders request to stdout, reads y/n/note decision from stdin.
    """

    def prompt(self, request: ConfirmationRequest) -> ConfirmationOutcome:
        """
        Prompt the analyst at the terminal.

        Args:
            request: The confirmation request

        Returns:
            ConfirmationOutcome (APPROVED or DENIED)

        Raises:
            ConfirmationTimeout: If timeout elapses (not implemented yet)
        """
        # Render request
        self._render_request(request)

        # Read decision
        while True:
            try:
                response = input(
                    "\n[a]pprove / [d]eny / [n]ote-and-approve / [N]ote-and-deny: "
                ).strip().lower()
            except (EOFError, KeyboardInterrupt):
                return ConfirmationOutcome.DENIED

            if response == "a":
                return ConfirmationOutcome.APPROVED
            elif response == "d":
                return ConfirmationOutcome.DENIED
            elif response == "n":
                # Approve with note
                try:
                    note = input("Note: ").strip()
                    # TODO: Store note somewhere for audit
                except (EOFError, KeyboardInterrupt):
                    return ConfirmationOutcome.DENIED
                return ConfirmationOutcome.APPROVED
            elif response == "n":  # Capital N
                # Deny with note
                try:
                    note = input("Note: ").strip()
                    # TODO: Store note somewhere for audit
                except (EOFError, KeyboardInterrupt):
                    return ConfirmationOutcome.DENIED
                return ConfirmationOutcome.DENIED
            else:
                print("Invalid response. Try again.")

    def _render_request(self, request: ConfirmationRequest) -> None:
        """Pretty-print a confirmation request."""
        print("\n" + "=" * 70, file=sys.stderr)
        print(f"[CONFIRM] {request.agent} wants to: {request.action}", file=sys.stderr)
        print(f"  Workspace:  {request.workspace}", file=sys.stderr)
        print(f"  Scope:      {request.scope}", file=sys.stderr)
        print(f"  Risk:       {request.risk}", file=sys.stderr)
        print(f"  Reason:     {request.reason}", file=sys.stderr)
        print(f"  Timeout:    {request.timeout_seconds}s", file=sys.stderr)
        print(f"  Subject:", file=sys.stderr)

        # Pretty-print subject
        try:
            subject_str = json.dumps(request.subject, indent=4)
            for line in subject_str.split("\n"):
                print(f"    {line}", file=sys.stderr)
        except Exception:
            print(f"    {request.subject}", file=sys.stderr)

        print("=" * 70, file=sys.stderr)
