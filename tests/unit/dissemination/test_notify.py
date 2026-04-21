"""
Unit tests for gnat.dissemination.notify
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from gnat.analysis.tlp import TLPLevel
from gnat.dissemination.notify import (
    DeliveryReceipt,
    WebhookNotifier,
    WebhookSubscription,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_report(tlp: TLPLevel = TLPLevel.GREEN) -> MagicMock:
    r = MagicMock()
    r.id = "rpt-test"
    r.title = "Test Report"
    r.report_type = MagicMock(value="incident")
    r.classification = tlp
    r.published_at = datetime(2025, 6, 1, tzinfo=timezone.utc)
    r.stix_id = "report--test"
    return r


def _sub(
    sub_id: str = "sub-1",
    url: str = "https://example.com/hook",
    min_tlp: TLPLevel = TLPLevel.GREEN,
    events: list | None = None,
) -> WebhookSubscription:
    return WebhookSubscription(
        id=sub_id,
        url=url,
        min_tlp=min_tlp,
        events=events or ["published", "updated"],
    )


# ── WebhookSubscription ───────────────────────────────────────────────────────


class TestWebhookSubscription:
    def test_matches_same_tlp(self):
        sub = _sub(min_tlp=TLPLevel.AMBER)
        assert sub.matches(TLPLevel.AMBER, "published")

    def test_matches_lower_tlp(self):
        sub = _sub(min_tlp=TLPLevel.AMBER)
        assert sub.matches(TLPLevel.GREEN, "published")

    def test_does_not_match_higher_tlp(self):
        sub = _sub(min_tlp=TLPLevel.GREEN)
        assert not sub.matches(TLPLevel.RED, "published")

    def test_does_not_match_wrong_event(self):
        sub = _sub(events=["published"])
        assert not sub.matches(TLPLevel.GREEN, "updated")

    def test_matches_correct_event(self):
        sub = _sub(events=["updated"])
        assert sub.matches(TLPLevel.GREEN, "updated")


# ── WebhookNotifier ───────────────────────────────────────────────────────────


class TestWebhookNotifier:
    def test_subscribe_and_list(self):
        notifier = WebhookNotifier()
        sub = _sub()
        notifier.subscribe(sub)
        assert len(notifier.list_subscriptions()) == 1

    def test_unsubscribe_returns_true(self):
        notifier = WebhookNotifier()
        sub = _sub()
        notifier.subscribe(sub)
        assert notifier.unsubscribe("sub-1") is True

    def test_unsubscribe_missing_returns_false(self):
        notifier = WebhookNotifier()
        assert notifier.unsubscribe("no-such-id") is False

    def test_notify_filters_by_tlp(self):
        """Subscribers with higher min_tlp than the report TLP should NOT be notified."""
        notifier = WebhookNotifier()
        high_sub = _sub("s1", min_tlp=TLPLevel.WHITE)  # WHITE sub: only receives WHITE
        low_sub = _sub("s2", min_tlp=TLPLevel.AMBER)  # AMBER sub: can receive up to AMBER

        notifier.subscribe(high_sub)
        notifier.subscribe(low_sub)

        # Report is RED — only RED+ subscribers should get it
        # (min_tlp=RED means subscriber is authorized for RED and below)
        red_sub = _sub("s3", min_tlp=TLPLevel.RED)
        notifier.subscribe(red_sub)

        report = _make_report(tlp=TLPLevel.RED)
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.status = 200
            mock_urlopen.return_value = mock_resp
            receipts = notifier.notify(report)

        # Only the RED-level subscription should fire
        notified_ids = {r.subscription_id for r in receipts}
        assert "s3" in notified_ids
        assert "s1" not in notified_ids
        assert "s2" not in notified_ids

    def test_notify_successful_delivery(self):
        notifier = WebhookNotifier()
        notifier.subscribe(_sub("s1"))
        report = _make_report(tlp=TLPLevel.GREEN)

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_resp.status = 200
            mock_urlopen.return_value = mock_resp
            receipts = notifier.notify(report)

        assert len(receipts) == 1
        assert receipts[0].success is True
        assert receipts[0].status_code == 200

    def test_notify_failed_delivery_does_not_raise(self):
        notifier = WebhookNotifier()
        notifier.subscribe(_sub("s1"))
        report = _make_report()

        with patch("urllib.request.urlopen", side_effect=URLError("refused")):
            receipts = notifier.notify(report)

        assert len(receipts) == 1
        assert receipts[0].success is False
        assert receipts[0].error != ""

    def test_notify_no_subscribers(self):
        notifier = WebhookNotifier()
        report = _make_report()
        receipts = notifier.notify(report)
        assert receipts == []

    def test_notify_adds_hmac_signature(self):
        sub = WebhookSubscription(
            id="s-hmac",
            url="https://example.com/hook",
            min_tlp=TLPLevel.GREEN,
            secret="mysecret",
        )
        notifier = WebhookNotifier()
        notifier.subscribe(sub)
        report = _make_report()

        captured_headers = {}

        def _fake_urlopen(req, timeout=None):
            captured_headers.update(req.headers)
            resp = MagicMock()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.status = 200
            return resp

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            notifier.notify(report)

        # Header keys are title-cased by urllib
        assert any("signature" in k.lower() or "Signature" in k for k in captured_headers)

    def test_delivery_receipt_fields(self):
        receipt = DeliveryReceipt(
            subscription_id="s1",
            url="https://example.com",
            event="published",
            status_code=200,
            success=True,
        )
        assert receipt.subscription_id == "s1"
        assert receipt.success is True
        assert receipt.attempted_at is not None

    def test_initial_subscriptions_via_constructor(self):
        subs = [_sub("s1"), _sub("s2")]
        notifier = WebhookNotifier(subscriptions=subs)
        assert len(notifier.list_subscriptions()) == 2

    def test_notify_event_label_in_payload(self):
        notifier = WebhookNotifier()
        notifier.subscribe(_sub("s1", events=["updated"]))
        report = _make_report()

        sent_payload = {}

        def _fake_urlopen(req, timeout=None):
            sent_payload.update(json.loads(req.data))
            resp = MagicMock()
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            resp.status = 200
            return resp

        with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
            notifier.notify(report, event="updated")

        assert sent_payload.get("event") == "updated"
        assert sent_payload.get("report_id") == "rpt-test"


# ── APIKey / APIKeyStore ──────────────────────────────────────────────────────
# (Tested alongside notify for convenience since both are dissemination-layer)


class TestAPIKeyStore:
    def test_add_and_retrieve_key(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        store.add_key("my-token", TLPLevel.AMBER, label="Test")
        level = store.get_tlp_level("my-token")
        assert level == TLPLevel.AMBER

    def test_unknown_token_returns_none(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        assert store.get_tlp_level("unknown") is None

    def test_revoke_disables_key(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        store.add_key("tok", TLPLevel.GREEN)
        store.revoke_key("tok")
        assert store.get_tlp_level("tok") is None

    def test_generate_key_is_unique(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        k1 = store.generate_key(TLPLevel.WHITE)
        k2 = store.generate_key(TLPLevel.WHITE)
        assert k1.token != k2.token

    def test_delete_key(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        store.add_key("del-tok", TLPLevel.RED)
        assert store.delete_key("del-tok") is True
        assert store.get_tlp_level("del-tok") is None

    def test_list_keys(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        store.add_key("t1", TLPLevel.WHITE)
        store.add_key("t2", TLPLevel.AMBER)
        keys = store.list_keys()
        assert len(keys) == 2

    def test_len(self):
        from gnat.dissemination.api.auth import APIKeyStore

        store = APIKeyStore()
        store.add_key("t1", TLPLevel.WHITE)
        assert len(store) == 1

    def test_api_key_token_hash(self):
        from gnat.dissemination.api.auth import APIKey

        key = APIKey(token="secret", tlp_level=TLPLevel.GREEN)
        assert len(key.token_hash) == 16
        assert key.token_hash != "secret"

    def test_api_key_is_valid_enabled(self):
        from gnat.dissemination.api.auth import APIKey

        key = APIKey(token="t", tlp_level=TLPLevel.WHITE, enabled=True)
        assert key.is_valid() is True

    def test_api_key_is_invalid_disabled(self):
        from gnat.dissemination.api.auth import APIKey

        key = APIKey(token="t", tlp_level=TLPLevel.WHITE, enabled=False)
        assert key.is_valid() is False

    def test_api_key_to_dict(self):
        from gnat.dissemination.api.auth import APIKey

        key = APIKey(token="tok", tlp_level=TLPLevel.AMBER, label="my key")
        d = key.to_dict()
        assert d["tlp_level"] == "amber"
        assert d["label"] == "my key"
        assert "token" not in d  # raw token not serialised
