# tests/test_interface_events.py

from __future__ import annotations

from typing import Dict, Any

from adaptive_core.interface import AdaptiveCoreInterface


def test_interface_stores_normalised_event() -> None:
    iface = AdaptiveCoreInterface()

    raw: Dict[str, Any] = {
        "event_id": 123,            # will be normalised to str
        "action": "block",
        "severity": 0.9,
        "fingerprint": "wallet-abc",
        "user_id": "user-42",
        "extra": {"reason": "test"},
    }

    iface.handle_event(raw)

    events = iface.list_events()
    assert len(events) == 1

    evt = events[0]
    assert evt["event_id"] == "123"
    assert evt["action"] == "block"
    assert evt["severity"] == 0.9
    assert evt["fingerprint"] == "wallet-abc"
    assert evt["user_id"] == "user-42"
    assert evt["extra"]["reason"] == "test"
    assert evt["source"] in ("external", "qwg")  # allow override


def test_interface_ignores_non_dict_and_never_raises() -> None:
    iface = AdaptiveCoreInterface()

    # These calls must not raise:
    iface.handle_event(None)          # type: ignore[arg-type]
    iface.handle_event("not-a-dict")  # type: ignore[arg-type]

    # No events should be stored
    assert iface.list_events() == []
