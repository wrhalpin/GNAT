# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.triggers
=====================

External event triggers that bind events to workflow execution.

Provides three trigger types:

* :class:`AlertTrigger` — fires when a new alert arrives (callback-based)
* :class:`ScheduledTrigger` — fires on a cron schedule using croniter
* :class:`WebhookTrigger` — fires when an HTTP POST arrives on a configured path

Usage::

    from gnat.agents.triggers import AlertTrigger, ScheduledTrigger
    from gnat.agents.workflow import WorkflowContext
    from gnat.agents.workflows.auto_investigation import build_auto_investigation_workflow

    def on_alert(alert_data):
        ctx = WorkflowContext(shared={"alert": alert_data})
        wf  = build_auto_investigation_workflow(...)
        return wf.run(ctx)

    trigger = AlertTrigger("new_alert", on_alert)
    trigger.fire({"type": "phishing", "score": 0.92})
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Callable that accepts alert/event data and returns a WorkflowResult or None
WorkflowFactory = Callable[[], Any]  # () -> Workflow
ContextFactory  = Callable[[dict[str, Any]], Any]  # (event_data) -> WorkflowContext


@dataclass
class TriggerEvent:
    """
    Payload delivered to a workflow trigger.

    Parameters
    ----------
    event_type : str
        Classification of the event (e.g. ``"alert"``, ``"scheduled"``, ``"webhook"``).
    data : dict
        Arbitrary event payload forwarded to :class:`~gnat.agents.workflow.WorkflowContext`.
    source : str
        Originating system or connector name.
    occurred_at : datetime
        UTC timestamp of the event.
    """

    event_type:  str
    data:        dict[str, Any] = field(default_factory=dict)
    source:      str = ""
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WorkflowTrigger:
    """
    Base class for all workflow triggers.

    Subclasses implement :meth:`_on_event` to define trigger logic and call
    :meth:`fire` to deliver an event to the registered handler.

    Parameters
    ----------
    name : str
        Human-readable trigger name.
    workflow_factory : WorkflowFactory
        Callable returning a configured :class:`~gnat.agents.workflow.Workflow`.
    context_factory : ContextFactory | None
        Callable that builds a :class:`~gnat.agents.workflow.WorkflowContext` from
        event data.  When ``None`` a default empty context is used.
    store : WorkflowStore | None
        Optional store to persist run results.
    """

    def __init__(
        self,
        name:             str,
        workflow_factory: WorkflowFactory,
        context_factory:  ContextFactory | None = None,
        store:            Any | None = None,
    ) -> None:
        self.name             = name
        self._workflow_factory = workflow_factory
        self._context_factory  = context_factory
        self._store            = store
        self._enabled          = True

    def enable(self) -> None:
        """Enable this trigger."""
        self._enabled = True

    def disable(self) -> None:
        """Disable this trigger (events are silently dropped)."""
        self._enabled = False

    def fire(self, event: TriggerEvent) -> Any:
        """
        Execute the workflow in response to *event*.

        Returns the :class:`~gnat.agents.workflow.WorkflowResult`, or ``None``
        if the trigger is disabled or an error occurs.
        """
        if not self._enabled:
            logger.debug("Trigger %r disabled — skipping event %r", self.name, event.event_type)
            return None

        logger.info(
            "Trigger %r firing for event_type=%r source=%r",
            self.name, event.event_type, event.source,
        )

        try:
            wf = self._workflow_factory()
            if self._context_factory is not None:
                ctx = self._context_factory(event.data)
            else:
                from gnat.agents.workflow import WorkflowContext
                ctx = WorkflowContext(shared=dict(event.data))

            result = wf.run(ctx)

            if self._store is not None:
                try:
                    self._store.save(result, workflow_name=wf.name)
                except Exception as exc:
                    logger.warning("Trigger %r: failed to persist run: %s", self.name, exc)

            return result

        except Exception as exc:
            logger.error("Trigger %r: workflow execution failed: %s", self.name, exc, exc_info=True)
            return None


class AlertTrigger(WorkflowTrigger):
    """
    Trigger that fires when an alert payload is delivered.

    Designed for use with SIEM/SOAR webhooks, polling loops, or message queues
    that notify GNAT of new security alerts.

    Parameters
    ----------
    name : str
        Trigger name.
    workflow_factory : WorkflowFactory
        Returns a configured :class:`~gnat.agents.workflow.Workflow`.
    context_factory : ContextFactory | None
        Maps alert dict → :class:`~gnat.agents.workflow.WorkflowContext`.
        Defaults to loading alert data into ``ctx.shared["alert"]``.
    min_score : float
        Minimum alert confidence/severity score (0–1).  Alerts below this
        threshold are ignored.
    store : WorkflowStore | None
        Optional run persistence.
    """

    def __init__(
        self,
        name:             str,
        workflow_factory: WorkflowFactory,
        context_factory:  ContextFactory | None = None,
        min_score:        float = 0.0,
        store:            Any | None = None,
    ) -> None:
        if context_factory is None:
            def _default_ctx(data: dict[str, Any]) -> Any:
                from gnat.agents.workflow import WorkflowContext
                return WorkflowContext(shared={"alert": data, **data})
            context_factory = _default_ctx

        super().__init__(name, workflow_factory, context_factory, store)
        self._min_score = min_score

    def on_alert(self, alert_data: dict[str, Any]) -> Any:
        """
        Convenience method — wraps *alert_data* in a :class:`TriggerEvent` and
        calls :meth:`fire`.

        Parameters
        ----------
        alert_data : dict
            Alert payload (must include ``"score"`` key if ``min_score > 0``).
        """
        score = float(alert_data.get("score", alert_data.get("severity", 1.0)))
        if score < self._min_score:
            logger.debug(
                "AlertTrigger %r: score %.2f below threshold %.2f — skipping",
                self.name, score, self._min_score,
            )
            return None

        event = TriggerEvent(
            event_type  = "alert",
            data        = alert_data,
            source      = alert_data.get("source", ""),
            occurred_at = datetime.now(timezone.utc),
        )
        return self.fire(event)


class ScheduledTrigger(WorkflowTrigger):
    """
    Trigger that fires on a cron schedule.

    Uses ``croniter`` if installed; falls back to a simple ``interval_seconds``
    polling loop when ``croniter`` is not available.

    Parameters
    ----------
    name : str
        Trigger name.
    workflow_factory : WorkflowFactory
    context_factory : ContextFactory | None
    cron_expr : str | None
        Standard 5-field cron expression (e.g. ``"0 */6 * * *"``).
        Mutually exclusive with *interval_seconds*.
    interval_seconds : float
        Fixed interval between runs (used when *cron_expr* is ``None``).
    store : WorkflowStore | None
    """

    def __init__(
        self,
        name:             str,
        workflow_factory: WorkflowFactory,
        context_factory:  ContextFactory | None = None,
        cron_expr:        str | None = None,
        interval_seconds: float = 3600.0,
        store:            Any | None = None,
    ) -> None:
        super().__init__(name, workflow_factory, context_factory, store)
        self._cron_expr       = cron_expr
        self._interval        = interval_seconds
        self._thread: threading.Thread | None = None
        self._stop_event      = threading.Event()

    def start(self) -> None:
        """Start the background scheduling thread."""
        if self._thread is not None and self._thread.is_alive():
            logger.warning("ScheduledTrigger %r already running", self.name)
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name=f"trigger-{self.name}", daemon=True
        )
        self._thread.start()
        logger.info("ScheduledTrigger %r started (cron=%r interval=%.0fs)",
                    self.name, self._cron_expr, self._interval)

    def stop(self) -> None:
        """Stop the scheduling thread (non-blocking)."""
        self._stop_event.set()

    def _loop(self) -> None:
        """Background thread that fires the workflow at the scheduled time."""
        while not self._stop_event.is_set():
            sleep_secs = self._seconds_until_next_run()
            logger.debug("ScheduledTrigger %r: sleeping %.1fs until next run", self.name, sleep_secs)
            # Wait in small increments so stop_event is checked frequently
            deadline = sleep_secs
            while deadline > 0 and not self._stop_event.is_set():
                chunk = min(deadline, 5.0)
                self._stop_event.wait(chunk)
                deadline -= chunk

            if self._stop_event.is_set():
                break

            event = TriggerEvent(
                event_type  = "scheduled",
                data        = {"trigger_name": self.name},
                source      = "scheduler",
                occurred_at = datetime.now(timezone.utc),
            )
            self.fire(event)

    def _seconds_until_next_run(self) -> float:
        if self._cron_expr:
            try:
                from croniter import croniter
                it = croniter(self._cron_expr, datetime.now(timezone.utc))
                nxt = it.get_next(datetime)
                return max(0.0, (nxt - datetime.now(timezone.utc)).total_seconds())
            except Exception as exc:
                logger.warning("ScheduledTrigger %r: croniter error (%s) — using interval", self.name, exc)
        return self._interval


class WebhookTrigger(WorkflowTrigger):
    """
    Trigger that fires when an HTTP webhook payload arrives.

    This trigger is passive — call :meth:`handle_request` from a FastAPI/WSGI
    handler when a POST arrives on the configured path.

    Parameters
    ----------
    name : str
    workflow_factory : WorkflowFactory
    context_factory : ContextFactory | None
    secret : str | None
        Optional HMAC-SHA256 shared secret for request validation.
    store : WorkflowStore | None
    """

    def __init__(
        self,
        name:             str,
        workflow_factory: WorkflowFactory,
        context_factory:  ContextFactory | None = None,
        secret:           str | None = None,
        store:            Any | None = None,
    ) -> None:
        super().__init__(name, workflow_factory, context_factory, store)
        self._secret = secret

    def handle_request(self, payload: dict[str, Any], signature: str | None = None) -> Any:
        """
        Process an incoming webhook payload.

        Parameters
        ----------
        payload : dict
            Parsed JSON body from the POST request.
        signature : str | None
            HMAC-SHA256 hex digest from the ``X-Hub-Signature-256`` header.
            Validated when *secret* is set.

        Returns
        -------
        WorkflowResult | None
        """
        if self._secret and signature:
            if not self._verify_signature(payload, signature):
                logger.warning("WebhookTrigger %r: signature mismatch — request rejected", self.name)
                return None

        event = TriggerEvent(
            event_type  = "webhook",
            data        = payload,
            source      = payload.get("source", "webhook"),
            occurred_at = datetime.now(timezone.utc),
        )
        return self.fire(event)

    def _verify_signature(self, payload: dict[str, Any], signature: str) -> bool:
        import hashlib
        import hmac
        import json as _json
        body = _json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        secret_bytes = self._secret.encode("utf-8") if isinstance(self._secret, str) else self._secret
        expected = "sha256=" + hmac.new(secret_bytes, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
