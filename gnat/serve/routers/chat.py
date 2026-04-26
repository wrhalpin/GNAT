# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.serve.routers.chat
===========================

FastAPI routes for Investigation Copilot and Live Analyst Assistant.
Streaming responses via Server-Sent Events (SSE) and WebSocket.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, FileResponse
import json
from typing import Optional, AsyncGenerator
from datetime import datetime

from gnat.agents import (
    InvestigationCopilotSession,
    LiveAnalystAssistantSession,
    ConversationStore,
    SessionContext,
    AgentConfig,
)
from gnat.serve.auth import get_current_user


router = APIRouter(prefix="/api/chat", tags=["chat"])
conversation_store = ConversationStore()
agent_config = AgentConfig.from_ini()


# ─── Copilot Routes ───


@router.post("/investigations/{investigation_id}/copilot/start")
async def start_copilot(
    investigation_id: str,
    user=Depends(get_current_user),
):
    """Start a new copilot session for an investigation."""
    try:
        session = conversation_store.create_session(
            analyst_id=user.id,
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
    user=Depends(get_current_user),
):
    """
    Send message to copilot and get streaming response.
    Returns Server-Sent Events stream.
    """
    session = conversation_store.get_session(conversation_id)
    if not session:
        raise HTTPException(status_code=404, detail="Conversation not found")

    if session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=conversation_id,
            config=agent_config,
            conversation_store=conversation_store,
        )

        async def event_generator() -> AsyncGenerator[str, None]:
            """Stream copilot response as SSE events."""
            # Ask copilot (streaming internally)
            response = await copilot.ask_clarifying_question(message)

            # Yield tokens as SSE
            for token in response:
                yield f"data: {json.dumps({'token': token})}\n\n"

            yield f"data: {json.dumps({'status': 'complete'})}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/copilot/suggest-step")
async def copilot_suggest_step(
    investigation_id: str,
    conversation_id: str = Query(...),
    user=Depends(get_current_user),
):
    """Get copilot's suggested next investigation step."""
    session = conversation_store.get_session(conversation_id)
    if not session or session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        copilot = InvestigationCopilotSession(
            conversation_id=conversation_id,
            config=agent_config,
            conversation_store=conversation_store,
        )
        suggestion = await copilot.suggest_next_step()

        return {
            "action_type": suggestion.action_type,
            "text": suggestion.text,
            "confidence": suggestion.confidence,
            "metadata": suggestion.metadata,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── Assistant Routes ───


@router.post("/investigations/{investigation_id}/assistant/start")
async def start_assistant(
    investigation_id: str,
    user=Depends(get_current_user),
):
    """Start a new assistant session for an investigation."""
    try:
        session = conversation_store.create_session(
            analyst_id=user.id,
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
    user=Depends(get_current_user),
):
    """
    Get search help from assistant.
    Returns Server-Sent Events stream with routing suggestions.
    """
    session = conversation_store.get_session(conversation_id)
    if not session or session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        assistant = LiveAnalystAssistantSession(
            conversation_id=conversation_id,
            config=agent_config,
            conversation_store=conversation_store,
        )

        async def event_generator() -> AsyncGenerator[str, None]:
            """Stream assistant response as SSE events."""
            async for token in assistant.search_help(query):
                yield f"data: {json.dumps({'token': token})}\n\n"

            yield f"data: {json.dumps({'status': 'complete'})}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/assistant/explain")
async def assistant_explain(
    investigation_id: str,
    conversation_id: str = Query(...),
    stix_type: str = Query(...),
    stix_value: str = Query(...),
    user=Depends(get_current_user),
):
    """
    Get explanation of a STIX finding from assistant.
    Returns Server-Sent Events stream with plain-language explanation.
    """
    session = conversation_store.get_session(conversation_id)
    if not session or session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        assistant = LiveAnalystAssistantSession(
            conversation_id=conversation_id,
            config=agent_config,
            conversation_store=conversation_store,
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

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── History Routes ───


@router.get("/investigations/{investigation_id}/history")
async def get_conversation_history(
    investigation_id: str,
    conversation_id: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """Fetch conversation history for an investigation."""
    try:
        if conversation_id:
            # Single conversation
            session = conversation_store.get_session(conversation_id)
            if not session or session.investigation_id != investigation_id:
                raise HTTPException(status_code=403, detail="Unauthorized")

            turns = conversation_store.get_turns(conversation_id)
            return {
                "conversation_id": conversation_id,
                "turns": [t.to_dict() for t in turns],
            }
        else:
            # All conversations for investigation
            sessions = conversation_store.get_investigation_conversations(investigation_id)
            result = {
                "investigation_id": investigation_id,
                "conversations": [],
            }

            for session in sessions:
                turns = conversation_store.get_turns(session.conversation_id)
                result["conversations"].append({
                    "conversation_id": session.conversation_id,
                    "agent_type": session.agent_type,
                    "created_at": session.created_at.isoformat(),
                    "turn_count": len(turns),
                })

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
    format: str = Query("json", regex="^(json|csv)$"),
    user=Depends(get_current_user),
):
    """
    Export conversation as JSON or CSV.

    Query parameters:
    - format: "json" or "csv"
    """
    session = conversation_store.get_session(conversation_id)
    if not session or session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        turns = conversation_store.get_turns(conversation_id)

        if format == "json":
            content = json.dumps([t.to_dict() for t in turns], indent=2)
            filename = f"conversation_{conversation_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            media_type = "application/json"

        else:  # csv
            import csv
            from io import StringIO

            output = StringIO()
            if turns:
                fieldnames = ["timestamp", "role", "text", "tokens_in", "tokens_out", "latency_ms"]
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()

                for turn in turns:
                    writer.writerow({
                        "timestamp": turn.timestamp.isoformat(),
                        "role": turn.role.value,
                        "text": turn.text,
                        "tokens_in": turn.tokens_in,
                        "tokens_out": turn.tokens_out,
                        "latency_ms": turn.latency_ms,
                    })

            content = output.getvalue()
            filename = f"conversation_{conversation_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            media_type = "text/csv"

        return {
            "filename": filename,
            "format": format,
            "content": content,
            "turn_count": len(turns),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/investigations/{investigation_id}/copy")
async def copy_suggestion(
    investigation_id: str,
    conversation_id: str = Query(...),
    text: str = Query(...),
    user=Depends(get_current_user),
):
    """
    Copy suggestion to clipboard (for Web UI).
    In production, use browser Clipboard API directly.
    This endpoint returns the text in a format ready for copying.
    """
    session = conversation_store.get_session(conversation_id)
    if not session or session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    return {
        "text": text,
        "copied": True,
        "message": "Text ready for clipboard (use browser Clipboard API to copy)",
    }


@router.get("/investigations/{investigation_id}/summary")
async def get_conversation_summary(
    investigation_id: str,
    conversation_id: str = Query(...),
    user=Depends(get_current_user),
):
    """Get summary stats for a conversation."""
    session = conversation_store.get_session(conversation_id)
    if not session or session.investigation_id != investigation_id:
        raise HTTPException(status_code=403, detail="Unauthorized")

    try:
        turns = conversation_store.get_turns(conversation_id)

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
            "duration_seconds": (turns[-1].timestamp - turns[0].timestamp).total_seconds() if turns else 0,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
