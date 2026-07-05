# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.routers.chat
===========================

FastAPI routes for Investigation Copilot and Live Analyst Assistant.
Streaming responses via Server-Sent Events (SSE).

Authentication is applied at router registration in :mod:`gnat.serve.app`
via ``Depends(APIKeyAuth)``, matching the other routers; analyst identity
is passed explicitly per request.
"""

import json
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from gnat.agents import (
    AgentConfig,
    ConversationStore,
    InvestigationCopilotSession,
    LiveAnalystAssistantSession,
)

router = APIRouter(prefix="/api/chat", tags=["chat"])

# Created lazily so importing this module has no side effects (no SQLite
# file creation, no config-file requirement at import time).
_conversation_store: Optional[ConversationStore] = None
_agent_config: Optional[AgentConfig] = None


def _store() -> ConversationStore:
    global _conversation_store
    if _conversation_store is None:
        _conversation_store = ConversationStore()
    return _conversation_store


def _config() -> AgentConfig:
    global _agent_config
    if _agent_config is None:
        _agent_config = AgentConfig.from_ini()
    return _agent_config


def _get_session_or_403(conversation_id: str, investigation_id: str):
    """Fetch a session, enforcing that it belongs to the investigation."""
    session = _store().get_session(conversation_id)
    if not session:
        raise HTTPException(status_code=404, detail="Conversation not found")
    if session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")
    return session


# ─── Copilot Routes ───


@router.post("/investigations/{investigation_id}/copilot/start")
async def start_copilot(
    investigation_id: str,
    analyst_id: str = Query("analyst"),
):
    """Start a new copilot session for an investigation."""
    try:
        session = _store().create_session(
            analyst_id=analyst_id,
            investigation_id=investigation_id,
            agent_type="copilot",
        )
        return {
            "conversation_id": session.conversation_id,
            "status": "ready",
            "phase": session.state,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/copilot/ask")
async def copilot_ask(
    investigation_id: str,
    conversation_id: str = Query(...),
    message: str = Query(...),
):
    """
    Send message to copilot and get streaming response.
    Returns Server-Sent Events stream.
    """
    _get_session_or_403(conversation_id, investigation_id)

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=conversation_id,
            config=_config(),
            conversation_store=_store(),
        )

        async def event_generator() -> AsyncGenerator[str, None]:
            """Stream copilot response as SSE events."""
            # ask_clarifying_question returns the complete response text;
            # emit it as a single SSE data event.
            response = await copilot.ask_clarifying_question(message)
            yield f"data: {json.dumps({'text': response})}\n\n"
            yield f"data: {json.dumps({'status': 'complete'})}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/copilot/suggest-step")
async def copilot_suggest_step(
    investigation_id: str,
    conversation_id: str = Query(...),
):
    """Get copilot's suggested next investigation step."""
    _get_session_or_403(conversation_id, investigation_id)

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=conversation_id,
            config=_config(),
            conversation_store=_store(),
        )
        suggestion = await copilot.suggest_next_step()

        return {
            "action_type": suggestion.action_type,
            "text": suggestion.text,
            "confidence": suggestion.confidence,
            "metadata": suggestion.metadata,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Assistant Routes ───


@router.post("/investigations/{investigation_id}/assistant/start")
async def start_assistant(
    investigation_id: str,
    analyst_id: str = Query("analyst"),
):
    """Start a new assistant session for an investigation."""
    try:
        session = _store().create_session(
            analyst_id=analyst_id,
            investigation_id=investigation_id,
            agent_type="assistant",
        )
        return {
            "conversation_id": session.conversation_id,
            "status": "ready",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/assistant/search-help")
async def assistant_search_help(
    investigation_id: str,
    conversation_id: str = Query(...),
    query: str = Query(...),
):
    """
    Get search help from assistant.
    Returns Server-Sent Events stream with routing suggestions.
    """
    _get_session_or_403(conversation_id, investigation_id)

    try:
        assistant = LiveAnalystAssistantSession(
            conversation_id=conversation_id,
            config=_config(),
            conversation_store=_store(),
        )

        async def event_generator() -> AsyncGenerator[str, None]:
            """Stream assistant response as SSE events."""
            async for token in assistant.search_help(query):
                yield f"data: {json.dumps({'token': token})}\n\n"

            yield f"data: {json.dumps({'status': 'complete'})}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/assistant/explain")
async def assistant_explain(
    investigation_id: str,
    conversation_id: str = Query(...),
    stix_type: str = Query(...),
    stix_value: str = Query(...),
):
    """
    Get explanation of a STIX finding from assistant.
    Returns Server-Sent Events stream with plain-language explanation.
    """
    _get_session_or_403(conversation_id, investigation_id)

    try:
        assistant = LiveAnalystAssistantSession(
            conversation_id=conversation_id,
            config=_config(),
            conversation_store=_store(),
        )

        # TODO: Fetch actual STIX object from workspace
        # For now, create a minimal one for testing
        from gnat.orm import Indicator

        stix_obj = Indicator(
            pattern=f"[{stix_type}:value = '{stix_value}']",
            pattern_type="stix",
        )

        async def event_generator() -> AsyncGenerator[str, None]:
            """Stream explanation as SSE events."""
            async for token in assistant.explain_finding(stix_obj, {}):
                yield f"data: {json.dumps({'token': token})}\n\n"

            yield f"data: {json.dumps({'status': 'complete'})}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── History Routes ───


@router.get("/investigations/{investigation_id}/history")
async def get_conversation_history(
    investigation_id: str,
    conversation_id: Optional[str] = Query(None),
):
    """Fetch conversation history for an investigation."""
    try:
        if conversation_id:
            _get_session_or_403(conversation_id, investigation_id)

            turns = _store().get_turns(conversation_id)
            return {
                "conversation_id": conversation_id,
                "turns": [t.to_dict() for t in turns],
            }
        else:
            # All conversations for investigation
            sessions = _store().get_investigation_conversations(investigation_id)
            result = {
                "investigation_id": investigation_id,
                "conversations": [],
            }

            for session in sessions:
                turns = _store().get_turns(session.conversation_id)
                result["conversations"].append(
                    {
                        "conversation_id": session.conversation_id,
                        "agent_type": session.agent_type,
                        "created_at": session.created_at.isoformat(),
                        "turn_count": len(turns),
                    }
                )

            return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Export Routes ───


@router.get("/investigations/{investigation_id}/export")
async def export_conversation(
    investigation_id: str,
    conversation_id: str = Query(...),
    format: str = Query("json", pattern="^(json|csv)$"),
):
    """
    Export conversation as JSON or CSV.

    Query parameters:
    - format: "json" or "csv"
    """
    _get_session_or_403(conversation_id, investigation_id)

    try:
        turns = _store().get_turns(conversation_id)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if format == "json":
            content = json.dumps([t.to_dict() for t in turns], indent=2)
            filename = f"conversation_{conversation_id}_{stamp}.json"

        else:  # csv
            import csv
            from io import StringIO

            output = StringIO()
            if turns:
                fieldnames = ["timestamp", "role", "text", "tokens_in", "tokens_out", "latency_ms"]
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()

                for turn in turns:
                    writer.writerow(
                        {
                            "timestamp": turn.timestamp.isoformat(),
                            "role": turn.role.value,
                            "text": turn.text,
                            "tokens_in": turn.tokens_in,
                            "tokens_out": turn.tokens_out,
                            "latency_ms": turn.latency_ms,
                        }
                    )

            content = output.getvalue()
            filename = f"conversation_{conversation_id}_{stamp}.csv"

        return {
            "filename": filename,
            "format": format,
            "content": content,
            "turn_count": len(turns),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/copy")
async def copy_suggestion(
    investigation_id: str,
    conversation_id: str = Query(...),
    text: str = Query(...),
):
    """
    Copy suggestion to clipboard (for Web UI).
    In production, use browser Clipboard API directly.
    This endpoint returns the text in a format ready for copying.
    """
    _get_session_or_403(conversation_id, investigation_id)

    return {
        "text": text,
        "copied": True,
        "message": "Text ready for clipboard (use browser Clipboard API to copy)",
    }


@router.get("/investigations/{investigation_id}/summary")
async def get_conversation_summary(
    investigation_id: str,
    conversation_id: str = Query(...),
):
    """Get summary stats for a conversation."""
    session = _get_session_or_403(conversation_id, investigation_id)

    try:
        turns = _store().get_turns(conversation_id)

        analyst_msgs = sum(1 for t in turns if "analyst" in t.role.value.lower())
        agent_msgs = sum(1 for t in turns if "analyst" not in t.role.value.lower())
        total_tokens = sum(t.tokens_in + t.tokens_out for t in turns)
        avg_latency = sum(t.latency_ms for t in turns) / len(turns) if turns else 0

        return {
            "conversation_id": conversation_id,
            "agent_type": session.agent_type,
            "turn_count": len(turns),
            "analyst_messages": analyst_msgs,
            "agent_messages": agent_msgs,
            "total_tokens": total_tokens,
            "avg_latency_ms": round(avg_latency, 2),
            "duration_seconds": (turns[-1].timestamp - turns[0].timestamp).total_seconds()
            if turns
            else 0,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
