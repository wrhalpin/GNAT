# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.cli.copilot_cli
======================

CLI commands for Investigation Copilot and Live Analyst Assistant.
"""

import asyncio
import argparse
from typing import Optional

from gnat.agents import (
    InvestigationCopilotSession,
    LiveAnalystAssistantSession,
    ConversationStore,
    AgentConfig,
)
from gnat.agents.copilot_workflows import WorkflowFactory


def copilot_start(args):
    """Start a new copilot session for an investigation."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    session_ctx = store.create_session(
        analyst_id=args.analyst_id,
        investigation_id=args.investigation_id,
        agent_type="copilot",
    )

    print(f"✓ Copilot session started")
    print(f"  Conversation ID: {session_ctx.conversation_id}")
    print(f"  Investigation: {session_ctx.investigation_id}")
    print(f"  Phase: {session_ctx.state}")
    print()
    print("Start typing to begin investigation. Type /help for commands.")


def copilot_ask(args):
    """Ask copilot a question."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=args.conversation_id,
            config=config,
            conversation_store=store,
        )

        # Run async function
        response = asyncio.run(copilot.ask_clarifying_question(args.message))

        print(f"Copilot: {response}")

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def copilot_next(args):
    """Get next suggested investigation step."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=args.conversation_id,
            config=config,
            conversation_store=store,
        )

        suggestion = asyncio.run(copilot.suggest_next_step())

        print(f"Next step: {suggestion.text}")
        print(f"Confidence: {suggestion.confidence:.0%}")
        print(f"Type: {suggestion.action_type}")
        if suggestion.metadata:
            print(f"Details: {suggestion.metadata}")

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def copilot_workflow(args):
    """Run a guided workflow (phishing_triage, incident_response)."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=args.conversation_id,
            config=config,
            conversation_store=store,
        )

        workflow = WorkflowFactory.create(
            workflow_type=args.workflow_type,
            copilot_session=copilot,
        )

        result = asyncio.run(workflow.run())

        print(f"Workflow: {result['workflow']}")
        print(f"Status: {result['status']}")
        print(f"Steps executed: {len(result['steps_executed'])}")
        if result.get("recommendation"):
            print(f"Recommendation: {result['recommendation']}")

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def copilot_history(args):
    """Show conversation history."""
    store = ConversationStore()

    try:
        turns = store.get_turns(args.conversation_id, limit=args.limit)

        if not turns:
            print("No conversation history")
            return

        for turn in turns:
            role = turn.role.value.upper()
            print(f"[{turn.timestamp.strftime('%H:%M:%S')}] {role}: {turn.text[:100]}")
            if len(turn.text) > 100:
                print(f"{'':27} (truncated)")

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def copilot_audit(args):
    """Show audit trail for investigation."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=args.conversation_id,
            config=config,
            conversation_store=store,
        )

        summary = copilot.audit_log.get_investigation_summary(
            investigation_id=args.investigation_id,
        )

        print(f"Investigation: {summary['investigation_id']}")
        print(f"  Operations: {summary['operation_count']}")
        print(f"  Questions: {summary['copilot_questions']}")
        print(f"  Suggestions: {summary['copilot_suggestions']}")
        print(f"  Assistant queries: {summary['assistant_queries']}")
        print(f"  Total tokens: {summary['total_tokens']}")
        print(f"  Avg latency: {summary['avg_latency_ms']:.0f}ms")
        print(f"  Avg confidence: {summary['avg_confidence']:.0%}")
        print(f"  Reviews required: {summary['reviews_required']}")

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def assistant_enrich(args):
    """Get enrichment suggestions for an object."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    try:
        assistant = LiveAnalystAssistantSession(
            conversation_id=args.conversation_id,
            config=config,
            conversation_store=store,
        )

        from gnat.orm import Indicator

        # Create indicator from argument
        indicator = Indicator(
            pattern=f"[{args.stix_type}:value = '{args.stix_value}']",
            pattern_type="stix",
        )

        print(f"Suggested enrichment for {args.stix_type}:{args.stix_value}\n")

        async def show_suggestions():
            async for suggestion in assistant.suggest_enrichment(indicator):
                print(f"• {suggestion.connector_name}")
                print(f"  {suggestion.reason}")
                print(f"  Est. {suggestion.estimated_duration_sec}s\n")

        asyncio.run(show_suggestions())

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def assistant_explain(args):
    """Explain a STIX object."""
    config = AgentConfig.from_ini()
    store = ConversationStore()

    try:
        assistant = LiveAnalystAssistantSession(
            conversation_id=args.conversation_id,
            config=config,
            conversation_store=store,
        )

        from gnat.orm import Indicator

        indicator = Indicator(
            pattern=f"[{args.stix_type}:value = '{args.stix_value}']",
            pattern_type="stix",
        )

        print(f"Explanation for {args.stix_type}:{args.stix_value}\n")

        async def show_explanation():
            async for token in assistant.explain_finding(indicator, context={}):
                print(token, end="", flush=True)
            print()

        asyncio.run(show_explanation())

    except Exception as e:
        print(f"Error: {e}", file=__import__("sys").stderr)
        return 1


def add_copilot_subparsers(subparsers):
    """Add copilot subcommands to argparse."""
    copilot_parser = subparsers.add_parser("copilot", help="Investigation Copilot commands")
    copilot_subparsers = copilot_parser.add_subparsers(dest="copilot_command", required=True)

    # copilot start
    start_parser = copilot_subparsers.add_parser("start", help="Start a copilot session")
    start_parser.add_argument("investigation_id", help="Investigation ID")
    start_parser.add_argument("--analyst-id", default="current_user", help="Analyst email/ID")
    start_parser.set_defaults(func=copilot_start)

    # copilot ask
    ask_parser = copilot_subparsers.add_parser("ask", help="Ask copilot a question")
    ask_parser.add_argument("conversation_id", help="Conversation ID")
    ask_parser.add_argument("message", help="Question or response")
    ask_parser.set_defaults(func=copilot_ask)

    # copilot next
    next_parser = copilot_subparsers.add_parser("next", help="Get next investigation step")
    next_parser.add_argument("conversation_id", help="Conversation ID")
    next_parser.set_defaults(func=copilot_next)

    # copilot workflow
    workflow_parser = copilot_subparsers.add_parser("workflow", help="Run a guided workflow")
    workflow_parser.add_argument("conversation_id", help="Conversation ID")
    workflow_parser.add_argument("workflow_type", help="Workflow type (phishing_triage, incident_response)")
    workflow_parser.set_defaults(func=copilot_workflow)

    # copilot history
    history_parser = copilot_subparsers.add_parser("history", help="Show conversation history")
    history_parser.add_argument("conversation_id", help="Conversation ID")
    history_parser.add_argument("--limit", type=int, default=20, help="Max entries to show")
    history_parser.set_defaults(func=copilot_history)

    # copilot audit
    audit_parser = copilot_subparsers.add_parser("audit", help="Show investigation audit trail")
    audit_parser.add_argument("conversation_id", help="Conversation ID")
    audit_parser.add_argument("investigation_id", help="Investigation ID")
    audit_parser.set_defaults(func=copilot_audit)


def add_assistant_subparsers(subparsers):
    """Add assistant subcommands to argparse."""
    assistant_parser = subparsers.add_parser("assistant", help="Live Analyst Assistant commands")
    assistant_subparsers = assistant_parser.add_subparsers(dest="assistant_command", required=True)

    # assistant enrich
    enrich_parser = assistant_subparsers.add_parser("enrich", help="Get enrichment suggestions")
    enrich_parser.add_argument("conversation_id", help="Conversation ID")
    enrich_parser.add_argument("stix_type", help="STIX type (ipv4-addr, domain-name, etc.)")
    enrich_parser.add_argument("stix_value", help="STIX value (1.2.3.4, example.com, etc.)")
    enrich_parser.set_defaults(func=assistant_enrich)

    # assistant explain
    explain_parser = assistant_subparsers.add_parser("explain", help="Explain a STIX object")
    explain_parser.add_argument("conversation_id", help="Conversation ID")
    explain_parser.add_argument("stix_type", help="STIX type")
    explain_parser.add_argument("stix_value", help="STIX value")
    explain_parser.set_defaults(func=assistant_explain)
