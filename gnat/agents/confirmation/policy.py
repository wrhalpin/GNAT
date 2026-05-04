# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.confirmation.policy
==================================

Policy engine for confirmation broker decisions.
"""

from typing import Dict, Optional, Literal
import re

from gnat.agents.confirmation.models import (
    ConfirmationRequest,
    ConfirmationOutcome,
)


class PolicyEngine:
    """
    Evaluates policies against confirmation requests.

    Policies are specified as a dict mapping scope patterns to actions.
    Scopes are dotted strings (e.g., "library.promote", "connector.delete.*").
    Patterns use prefix matching with .* wildcard.

    Actions are:
    - auto_approve: Always approve
    - auto_deny: Always deny
    - prompt: Wait for human decision
    - prompt_timeout_approve: Timeout = approval
    - prompt_timeout_deny: Timeout = denial (safe default)
    """

    def __init__(
        self,
        policies: Dict[str, str],
        default_action: str = "prompt_timeout_deny",
    ):
        """
        Initialize policy engine.

        Args:
            policies: Dict mapping scope patterns to actions
            default_action: Action for scopes matching no policy
        """
        self.policies = policies
        self.default_action = default_action
        self._validate_actions()

    def _validate_actions(self) -> None:
        """Validate all actions are known."""
        valid_actions = {
            "auto_approve",
            "auto_deny",
            "prompt",
            "prompt_timeout_approve",
            "prompt_timeout_deny",
        }

        for pattern, action in self.policies.items():
            if action not in valid_actions:
                raise ValueError(f"Unknown action '{action}' for pattern '{pattern}'")

        if self.default_action not in valid_actions:
            raise ValueError(f"Unknown default action '{self.default_action}'")

    def decide(self, request: ConfirmationRequest) -> Optional[ConfirmationOutcome]:
        """
        Evaluate policies and return immediate outcome, or None to prompt.

        Args:
            request: The confirmation request

        Returns:
            ConfirmationOutcome if policy short-circuits, None if human decision needed
        """
        # Find first matching policy
        matched_action = self._find_matching_action(request.scope)

        if matched_action == "auto_approve":
            return ConfirmationOutcome.AUTO_APPROVED
        elif matched_action == "auto_deny":
            return ConfirmationOutcome.AUTO_DENIED
        elif matched_action == "prompt":
            return None
        elif matched_action == "prompt_timeout_approve":
            # Return None now; timeout handling happens in broker
            return None
        elif matched_action == "prompt_timeout_deny":
            # Return None now; timeout handling happens in broker
            return None

    def get_action_and_timeout_behavior(self, request: ConfirmationRequest) -> tuple:
        """
        Get the matched action and how to handle timeouts.

        Returns:
            (action, timeout_becomes_outcome or None)
        """
        matched_action = self._find_matching_action(request.scope)

        if matched_action == "prompt_timeout_approve":
            return (matched_action, ConfirmationOutcome.APPROVED)
        elif matched_action == "prompt_timeout_deny":
            return (matched_action, ConfirmationOutcome.DENIED)
        else:
            return (matched_action, None)

    def _find_matching_action(self, scope: str) -> str:
        """
        Find the first matching action for a scope.

        Policies are evaluated in iteration order (dicts in Python 3.7+
        maintain insertion order). First match wins.

        Args:
            scope: The scope string to match (e.g., "library.promote")

        Returns:
            The matched action, or self.default_action if no match
        """
        for pattern, action in self.policies.items():
            if self._pattern_matches(scope, pattern):
                return action

        return self.default_action

    @staticmethod
    def _pattern_matches(scope: str, pattern: str) -> bool:
        """
        Check if a scope matches a pattern.

        Patterns can be:
        - Exact: "library.promote" matches exactly
        - Prefix with .*: "connector.delete.*" matches any scope starting with "connector.delete."

        Args:
            scope: The scope string
            pattern: The pattern string

        Returns:
            True if scope matches pattern
        """
        if pattern.endswith(".*"):
            # Prefix match: remove .* and check prefix
            prefix = pattern[:-2]
            return scope.startswith(prefix + ".")
        else:
            # Exact match
            return scope == pattern

    @classmethod
    def from_ini(cls, config_dict: Dict[str, str], section_name: str = "confirmation.policies") -> "PolicyEngine":
        """
        Load policies from an INI config section dict.

        Args:
            config_dict: Dict from a single INI section (e.g., dict(parser["confirmation.policies"]))
            section_name: Unused (for compatibility); policies come directly from config_dict

        Returns:
            Initialized PolicyEngine
        """
        return cls(config_dict)
