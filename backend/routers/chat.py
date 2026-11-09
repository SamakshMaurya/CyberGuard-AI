"""
CyberGuard AI — Chat Router & WebSocket Handler

Provides real-time conversational streaming with the SecurityAgent and
REST fallback endpoints for message history and dispatch.
"""

from __future__ import annotations

import json
import logging
from typing import List, Dict, Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db, async_session_factory
from models import Assessment, ChatMessage
from schemas import ChatMessageCreate, ChatMessageResponse
from agent.engine import SecurityAgent

logger = logging.getLogger("cyberguard.chat")
router = APIRouter(tags=["Chat"])


@router.get("/api/chat/{assessment_id}/history", response_model=List[ChatMessageResponse])
async def get_chat_history(
    assessment_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Retrieve full chronological conversation transcript for an assessment."""
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    q = (
        select(ChatMessage)
        .where(ChatMessage.assessment_id == assessment_id)
        .order_by(ChatMessage.created_at.asc())
    )
    res = await db.execute(q)
    messages = res.scalars().all()

    return [
        ChatMessageResponse(
            id=m.id,
            assessment_id=m.assessment_id,
            role=m.role,
            content=m.content,
            metadata=m.msg_metadata,
            created_at=m.created_at,
        )
        for m in messages
    ]


@router.post("/api/chat/{assessment_id}/message", response_model=List[Dict[str, Any]])
async def send_rest_message(
    assessment_id: int,
    payload: ChatMessageCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    REST fallback endpoint to post a message to the agent and receive all
    generated reasoning, tool calls, and final responses.
    """
    assessment = await db.get(Assessment, assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")

    agent = SecurityAgent(db, assessment_id)
    frames: List[Dict[str, Any]] = []

    async for frame in agent.process_message(payload.content):
        frames.append(frame)

    await db.commit()
    return frames


# Maintain active agent instances across websocket turns to keep pending approvals
_active_agents: Dict[int, SecurityAgent] = {}


@router.websocket("/api/ws/chat/{assessment_id}")
async def websocket_chat_endpoint(
    websocket: WebSocket,
    assessment_id: int,
):
    """
    Real-time bidirectional WebSocket connection for CyberGuard AI conversational guidance.
    Streams reasoning blocks, scanner tool executions, human approval prompts, and answers.
    """
    await websocket.accept()
    logger.info("WebSocket connected for assessment_id=%s", assessment_id)

    # Use a dedicated async session for the lifespan of the WebSocket session
    async with async_session_factory() as db:
        # Validate assessment exists
        assessment = await db.get(Assessment, assessment_id)
        if not assessment:
            await websocket.send_json({"type": "error", "content": "Assessment not found"})
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        agent = _active_agents.get(assessment_id)
        if not agent:
            agent = SecurityAgent(db, assessment_id)
            _active_agents[assessment_id] = agent
        else:
            agent.db = db

        # Send initial confirmation
        await websocket.send_json({
            "type": "status",
            "content": f"Connected to CyberGuard AI agent for assessment #{assessment_id} ({assessment.name})",
        })

        try:
            while True:
                data_raw = await websocket.receive_text()
                if not data_raw.strip():
                    continue

                try:
                    data = json.loads(data_raw)
                except json.JSONDecodeError:
                    data = {"type": "message", "content": data_raw}

                msg_type = data.get("type", "message")

                if msg_type == "message":
                    user_text = data.get("content", "").strip()
                    if not user_text:
                        continue

                    async for frame in agent.process_message(user_text):
                        await websocket.send_json(frame)
                    await websocket.send_json({"type": "complete", "content": ""})

                elif msg_type == "approval":
                    action_id = data.get("action_id", "")
                    approved = bool(data.get("approved", False))
                    comment = data.get("comment", "")

                    async for frame in agent.handle_approval(action_id, approved, comment):
                        await websocket.send_json(frame)
                    await websocket.send_json({"type": "complete", "content": ""})

                elif msg_type == "ping":
                    await websocket.send_json({"type": "pong", "content": "ok"})

                else:
                    await websocket.send_json({
                        "type": "error",
                        "content": f"Unknown websocket message type '{msg_type}'",
                    })

        except WebSocketDisconnect:
            logger.info("WebSocket disconnected for assessment_id=%s", assessment_id)
        except Exception as exc:
            logger.exception("WebSocket exception encountered: %s", exc)
            try:
                await websocket.send_json({"type": "error", "content": f"Internal agent error: {exc}"})
            except Exception:
                pass
