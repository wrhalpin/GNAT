# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.rules.audit
=============================

Audit trail for rule firings. Every evaluation writes records BEFORE
applying decisions. Git SHA captured per rule source file.
"""

from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def rule_file_sha(path: str | Path) -> str | None:
    """Return the latest git commit SHA for a file, or None if dirty/unavailable."""
    try:
        result = subprocess.run(
            ["git", "log", "-n", "1", "--format=%H", "--", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return None


def git_file_is_clean(path: str | Path) -> bool:
    """True if the file has no uncommitted changes (staged or unstaged)."""
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip() == ""
    except Exception:  # noqa: BLE001
        pass
    return False


class AuditWriter:
    """Writes rule firing audit records.

    When SQLAlchemy is available and a session factory is provided,
    records are persisted to the ``rule_firing_audit`` table. Otherwise
    records are accumulated in memory for inspection.
    """

    def __init__(self, session_factory: Any = None) -> None:
        self._session_factory = session_factory
        self._memory_log: list[dict[str, Any]] = []
        self._next_id = 1

    def record_firing(
        self,
        result: Any,
        hypothesis: Any,
        investigation: Any,
        workspace_id: int,
    ) -> list[int]:
        """Write one audit row per firing with applied=False. Returns row IDs."""
        audit_ids: list[int] = []
        for firing in result.firings:
            record = {
                "investigation_id": getattr(investigation, "id", ""),
                "hypothesis_id": getattr(hypothesis, "id", ""),
                "workspace_id": workspace_id,
                "rule_name": firing.rule_name,
                "rule_source_file": firing.rule_source_file,
                "rule_git_sha": firing.rule_git_sha,
                "fired_at": datetime.now(timezone.utc).isoformat(),
                "decision": _serialize_decision(firing.decision),
                "applied": False,
                "applied_at": None,
                "error_message": None,
                "engine_version": getattr(result, "engine_version", "1.0.0"),
            }

            if self._session_factory is not None:
                audit_id = self._write_db(record)
            else:
                audit_id = self._write_memory(record)
            audit_ids.append(audit_id)

        return audit_ids

    def mark_applied(self, audit_id: int, error_message: str | None = None) -> None:
        """Mark an audit row as applied (or record the error)."""
        now = datetime.now(timezone.utc).isoformat()

        if self._session_factory is not None:
            self._update_db(audit_id, now, error_message)
        else:
            self._update_memory(audit_id, now, error_message)

    @property
    def memory_log(self) -> list[dict[str, Any]]:
        return list(self._memory_log)

    def _write_memory(self, record: dict[str, Any]) -> int:
        record["id"] = self._next_id
        self._next_id += 1
        self._memory_log.append(record)
        return record["id"]

    def _update_memory(self, audit_id: int, applied_at: str, error_message: str | None) -> None:
        for rec in self._memory_log:
            if rec.get("id") == audit_id:
                rec["applied"] = error_message is None
                rec["applied_at"] = applied_at
                rec["error_message"] = error_message
                break

    def _write_db(self, record: dict[str, Any]) -> int:
        try:
            with self._session_factory() as sess:
                from sqlalchemy import text

                result = sess.execute(
                    text(
                        "INSERT INTO rule_firing_audit "
                        "(investigation_id, hypothesis_id, workspace_id, "
                        "rule_name, rule_source_file, rule_git_sha, "
                        "fired_at, decision, applied, engine_version) "
                        "VALUES (:inv, :hyp, :ws, :rn, :rf, :sha, "
                        "NOW(), :dec, false, :ev) RETURNING id"
                    ),
                    {
                        "inv": record["investigation_id"],
                        "hyp": record["hypothesis_id"],
                        "ws": record["workspace_id"],
                        "rn": record["rule_name"],
                        "rf": record["rule_source_file"],
                        "sha": record["rule_git_sha"],
                        "dec": json.dumps(record["decision"]),
                        "ev": record.get("engine_version", "1.0.0"),
                    },
                )
                sess.commit()
                row = result.fetchone()
                return row[0] if row else 0
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to write audit record: %s", exc)
            return self._write_memory(record)

    def _update_db(self, audit_id: int, applied_at: str, error_message: str | None) -> None:
        try:
            with self._session_factory() as sess:
                from sqlalchemy import text

                sess.execute(
                    text(
                        "UPDATE rule_firing_audit SET applied = :app, "
                        "applied_at = NOW(), error_message = :err "
                        "WHERE id = :aid"
                    ),
                    {
                        "app": error_message is None,
                        "err": error_message,
                        "aid": audit_id,
                    },
                )
                sess.commit()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to update audit record %d: %s", audit_id, exc)


def _serialize_decision(decision: Any) -> dict[str, Any]:
    return {
        "action": decision.action.value
        if hasattr(decision.action, "value")
        else str(decision.action),
        "reason": getattr(decision, "reason", ""),
        "target_status": (
            decision.target_status.value
            if hasattr(decision, "target_status") and hasattr(decision.target_status, "value")
            else getattr(decision, "target_status", None)
        ),
        "key": getattr(decision, "key", None),
        "value": getattr(decision, "value", None),
    }
