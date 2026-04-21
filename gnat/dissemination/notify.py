"""
gnat.dissemination.notify
==========================

Webhook notifications for published intelligence reports.

:class:`WebhookNotifier` fans out HTTP POST notifications to registered
subscribers when a report is published or updated.  Delivery is best-effort —
failures are logged but never raised to the caller.

Usage::

    from gnat.dissemination.notify import WebhookNotifier, WebhookSubscription
    from gnat.analysis.tlp import TLPLevel

    notifier = WebhookNotifier()
    notifier.subscribe(WebhookSubscription(
        id        = "sub-001",
        url       = "https://siem.example.com/webhook/gnat",
        min_tlp   = TLPLevel.AMBER,
        secret    = "hmac-shared-secret",
    ))

    notifier.notify(report)  # POSTs JSON payload to matching subscribers
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from gnat.analysis.tlp import TLPLevel

logger = logging.getLogger(__name__)


@dataclass
class WebhookSubscription:
    """
    A registered webhook endpoint.

    Parameters
    ----------
    id : str
        Unique subscription identifier.
    url : str
        HTTP(S) endpoint to POST notifications to.
    min_tlp : TLPLevel
        Minimum TLP level this subscriber is authorized to receive.
        Notifications for reports *above* this level are suppressed.
    secret : str, optional
        HMAC-SHA256 shared secret.  When set, an ``X-GNAT-Signature`` header
        is added to each request.
    events : list[str]
        Event types to receive.  ``["published", "updated"]`` by default.
    timeout_seconds : int
        HTTP request timeout (default 10).
    """

    id: str
    url: str
    min_tlp: TLPLevel = TLPLevel.WHITE
    secret: str = ""
    events: list[str] = field(default_factory=lambda: ["published", "updated"])
    timeout_seconds: int = 10

    def matches(self, report_tlp: TLPLevel, event: str) -> bool:
        """True if this subscription should receive *event* for *report_tlp*."""
        return report_tlp.rank <= self.min_tlp.rank and event in self.events


@dataclass
class DeliveryReceipt:
    """
    Record of a single webhook delivery attempt.

    Parameters
    ----------
    subscription_id : str
    url : str
    event : str
    status_code : int | None
        HTTP status code returned by the subscriber, or ``None`` on error.
    success : bool
    error : str
        Error message if delivery failed.
    attempted_at : datetime
    """

    subscription_id: str
    url: str
    event: str
    status_code: int | None
    success: bool
    error: str = ""
    attempted_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))


class WebhookNotifier:
    """
    Fan-out HTTP POST notifications to registered webhook subscribers.

    Parameters
    ----------
    subscriptions : list[WebhookSubscription], optional
        Initial subscriptions (can also be added via :meth:`subscribe`).
    """

    def __init__(
        self,
        subscriptions: list[WebhookSubscription] | None = None,
    ) -> None:
        self._subs: dict[str, WebhookSubscription] = {}
        for sub in subscriptions or []:
            self._subs[sub.id] = sub

    # ── Subscription management ───────────────────────────────────────────────

    def subscribe(self, subscription: WebhookSubscription) -> None:
        """Register a webhook subscription."""
        self._subs[subscription.id] = subscription
        logger.debug(
            "WebhookNotifier: registered subscription %s → %s", subscription.id, subscription.url
        )

    def unsubscribe(self, subscription_id: str) -> bool:
        """Remove a subscription by ID.  Returns True if found."""
        if subscription_id in self._subs:
            del self._subs[subscription_id]
            return True
        return False

    def list_subscriptions(self) -> list[WebhookSubscription]:
        """Return all registered subscriptions."""
        return list(self._subs.values())

    # ── Notification ──────────────────────────────────────────────────────────

    def notify(
        self,
        report: Any,
        event: str = "published",
    ) -> list[DeliveryReceipt]:
        """
        Send notifications to all matching subscribers.

        Parameters
        ----------
        report : Report
            The published report object.
        event : str
            Event label (``"published"`` or ``"updated"``).

        Returns
        -------
        list[DeliveryReceipt]
            One receipt per subscriber that was contacted.
        """
        report_tlp = _get_report_tlp(report)
        payload = _build_payload(report, event)
        receipts = []

        for sub in self._subs.values():
            if not sub.matches(report_tlp, event):
                continue
            receipt = self._deliver(sub, payload, event)
            receipts.append(receipt)

        return receipts

    def _deliver(
        self,
        sub: WebhookSubscription,
        payload: dict[str, Any],
        event: str,
    ) -> DeliveryReceipt:
        body = json.dumps(payload).encode()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "GNAT-WebhookNotifier/1.0",
            "X-GNAT-Event": event,
        }
        if sub.secret:
            sig = hmac.new(
                sub.secret.encode(),
                body,
                hashlib.sha256,
            ).hexdigest()
            headers["X-GNAT-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(
            url=sub.url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=sub.timeout_seconds) as resp:  # nosec B310
                status = resp.status
                success = 200 <= status < 300
                logger.info(
                    "WebhookNotifier: %s → %s HTTP %d",
                    sub.id,
                    sub.url,
                    status,
                )
                return DeliveryReceipt(
                    subscription_id=sub.id,
                    url=sub.url,
                    event=event,
                    status_code=status,
                    success=success,
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("WebhookNotifier: delivery to %s failed: %s", sub.url, exc)
            return DeliveryReceipt(
                subscription_id=sub.id,
                url=sub.url,
                event=event,
                status_code=None,
                success=False,
                error=str(exc),
            )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_report_tlp(report: Any) -> TLPLevel:
    classification = getattr(report, "classification", None)
    if isinstance(classification, TLPLevel):
        return classification
    try:
        return TLPLevel(str(classification).lower())
    except Exception:
        return TLPLevel.WHITE


def _build_payload(report: Any, event: str) -> dict[str, Any]:
    published = getattr(report, "published_at", None)
    return {
        "event": event,
        "report_id": str(getattr(report, "id", "")),
        "title": getattr(report, "title", ""),
        "report_type": str(getattr(getattr(report, "report_type", None), "value", "")),
        "tlp": str(getattr(getattr(report, "classification", None), "value", "")),
        "published_at": published.isoformat()
        if hasattr(published, "isoformat")
        else str(published or ""),
        "stix_id": getattr(report, "stix_id", None) or f"report--{getattr(report, 'id', '')}",
    }
