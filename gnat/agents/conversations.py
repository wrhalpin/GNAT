# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.conversations
===========================

Session management for Investigation Copilot and Live Analyst Assistant.
Persistent conversation storage with turn history, context binding, and metadata.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional, Any, List, Dict
from pathlib import Path
import json
import sqlite3
import threading

from gnat.context import workspace_manager


class ConversationRole(str, Enum):
    """Message sender role."""
    ANALYST = "analyst"
    COPILOT = "copilot"
    ASSISTANT = "assistant"
    SYSTEM = "system"


@dataclass
class ConversationTurn:
    """Single conversational exchange."""
    turn_id: int
    conversation_id: str
    role: ConversationRole
    text: str
    timestamp: datetime
    agent_type: str  # "copilot" | "assistant"
    investigation_id: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['role'] = self.role.value
        d['agent_type'] = self.agent_type
        d['timestamp'] = self.timestamp.isoformat()
        return d


@dataclass
class SessionContext:
    """Bound context for a conversation session."""
    conversation_id: str
    analyst_id: str
    investigation_id: str
    workspace_id: str
    agent_type: str  # "copilot" | "assistant"
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_turn_seq: int = 0
    state: str = "IDLE"  # State machine for copilot; ignored for assistant
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d['created_at'] = self.created_at.isoformat()
        return d


class ConversationStore:
    """
    Persistent conversation storage backed by SQLite.
    Thread-safe. Supports turn history, session context, and metadata.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize store.

        Args:
            db_path: Path to SQLite DB. If None, uses workspace default (.gnat/conversations.db).
        """
        if db_path is None:
            db_dir = Path.home() / ".gnat"
            db_dir.mkdir(exist_ok=True)
            db_path = str(db_dir / "conversations.db")

        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self):
        """Create tables if not exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversation_sessions (
                    conversation_id TEXT PRIMARY KEY,
                    analyst_id TEXT NOT NULL,
                    investigation_id TEXT,
                    workspace_id TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_turn_seq INTEGER DEFAULT 0,
                    state TEXT DEFAULT 'IDLE',
                    metadata TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversation_turns (
                    turn_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    text TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    investigation_id TEXT,
                    tokens_in INTEGER DEFAULT 0,
                    tokens_out INTEGER DEFAULT 0,
                    latency_ms REAL DEFAULT 0.0,
                    metadata TEXT,
                    FOREIGN KEY (conversation_id) REFERENCES conversation_sessions(conversation_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_turns_conversation
                ON conversation_turns(conversation_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_turns_investigation
                ON conversation_turns(investigation_id)
            """)
            conn.commit()

    def create_session(
        self,
        analyst_id: str,
        investigation_id: str,
        agent_type: str,
        workspace_id: Optional[str] = None,
    ) -> SessionContext:
        """Create a new conversation session."""
        if workspace_id is None:
            workspace_id = workspace_manager.current_workspace()

        conversation_id = f"{agent_type}_{investigation_id}_{datetime.utcnow().timestamp()}"
        ctx = SessionContext(
            conversation_id=conversation_id,
            analyst_id=analyst_id,
            investigation_id=investigation_id,
            workspace_id=workspace_id,
            agent_type=agent_type,
        )

        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO conversation_sessions
                (conversation_id, analyst_id, investigation_id, workspace_id, agent_type, created_at, state, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ctx.conversation_id,
                ctx.analyst_id,
                ctx.investigation_id,
                ctx.workspace_id,
                ctx.agent_type,
                ctx.created_at.isoformat(),
                ctx.state,
                json.dumps(ctx.metadata),
            ))
            conn.commit()

        return ctx

    def get_session(self, conversation_id: str) -> Optional[SessionContext]:
        """Retrieve session by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM conversation_sessions WHERE conversation_id = ?",
                (conversation_id,)
            ).fetchone()

        if not row:
            return None

        return SessionContext(
            conversation_id=row['conversation_id'],
            analyst_id=row['analyst_id'],
            investigation_id=row['investigation_id'],
            workspace_id=row['workspace_id'],
            agent_type=row['agent_type'],
            created_at=datetime.fromisoformat(row['created_at']),
            last_turn_seq=row['last_turn_seq'],
            state=row['state'],
            metadata=json.loads(row['metadata'] or '{}'),
        )

    def add_turn(
        self,
        conversation_id: str,
        role: ConversationRole,
        text: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
        latency_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ConversationTurn:
        """Add a turn to conversation history."""
        ctx = self.get_session(conversation_id)
        if not ctx:
            raise ValueError(f"Conversation {conversation_id} not found")

        turn = ConversationTurn(
            turn_id=0,  # Will be assigned by DB
            conversation_id=conversation_id,
            role=role,
            text=text,
            timestamp=datetime.utcnow(),
            agent_type=ctx.agent_type,
            investigation_id=ctx.investigation_id,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            latency_ms=latency_ms,
            metadata=metadata or {},
        )

        with self._lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO conversation_turns
                (conversation_id, role, text, timestamp, agent_type, investigation_id, tokens_in, tokens_out, latency_ms, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                turn.conversation_id,
                turn.role.value,
                turn.text,
                turn.timestamp.isoformat(),
                turn.agent_type,
                turn.investigation_id,
                turn.tokens_in,
                turn.tokens_out,
                turn.latency_ms,
                json.dumps(turn.metadata),
            ))
            turn.turn_id = cursor.lastrowid
            conn.commit()

        return turn

    def get_turns(self, conversation_id: str, since_seq: int = 0, limit: int = 100) -> List[ConversationTurn]:
        """Fetch turns from conversation."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM conversation_turns
                WHERE conversation_id = ? AND turn_id > ?
                ORDER BY turn_id ASC
                LIMIT ?
            """, (conversation_id, since_seq, limit)).fetchall()

        turns = []
        for row in rows:
            turns.append(ConversationTurn(
                turn_id=row['turn_id'],
                conversation_id=row['conversation_id'],
                role=ConversationRole(row['role']),
                text=row['text'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                agent_type=row['agent_type'],
                investigation_id=row['investigation_id'],
                tokens_in=row['tokens_in'],
                tokens_out=row['tokens_out'],
                latency_ms=row['latency_ms'],
                metadata=json.loads(row['metadata'] or '{}'),
            ))

        return turns

    def update_session_state(self, conversation_id: str, new_state: str) -> None:
        """Update copilot state machine."""
        with self._lock, sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE conversation_sessions SET state = ? WHERE conversation_id = ?",
                (new_state, conversation_id)
            )
            conn.commit()

    def get_investigation_conversations(self, investigation_id: str) -> List[SessionContext]:
        """Fetch all conversations for an investigation."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM conversation_sessions WHERE investigation_id = ? ORDER BY created_at DESC",
                (investigation_id,)
            ).fetchall()

        contexts = []
        for row in rows:
            contexts.append(SessionContext(
                conversation_id=row['conversation_id'],
                analyst_id=row['analyst_id'],
                investigation_id=row['investigation_id'],
                workspace_id=row['workspace_id'],
                agent_type=row['agent_type'],
                created_at=datetime.fromisoformat(row['created_at']),
                last_turn_seq=row['last_turn_seq'],
                state=row['state'],
                metadata=json.loads(row['metadata'] or '{}'),
            ))

        return contexts
