# src/adaptive_core/memory.py

from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, List, Iterable, Deque, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .models import RiskEvent, AdaptiveState, FeedbackType


@dataclass
class StateSnapshot:
    """
    Represents one saved snapshot of the adaptive state.
    Used for trending, debugging, reinforcement tuning, and cross-layer learning.
    """

    timestamp: datetime
    state: AdaptiveState


@dataclass
class InMemoryAdaptiveStore:
    """
    In-memory event + state store.

    This is used for prototypes and testing. Production deployments
    can replace this with Redis / SQL / disk-files while keeping
    the same API.

    Features in this v2 version:
      ✓ stores all adaptive events
      ✓ stores rolling snapshots of AdaptiveState
      ✓ allows querying by layer, feedback, fingerprint
      ✓ trims history to prevent memory growth
      ✓ provides clean list() helpers for engine and analytics
    """

    # Rolling event buffer (max_size prevents infinite memory usage)
    events: Deque[RiskEvent] = field(default_factory=lambda: deque(maxlen=5000))

    # Rolling snapshots (very lightweight)
    snapshots: Deque[StateSnapshot] = field(default_factory=lambda: deque(maxlen=500))

    # ------------------------------------------------------------------ #
    # Event Log
    # ------------------------------------------------------------------ #

    def add_event(self, event: RiskEvent) -> None:
        """Store a new adaptive learning event."""
        self.events.append(event)

    def list_events(self) -> List[RiskEvent]:
        """Return all events (bounded by maxlen)."""
        return list(self.events)

    def recent_events(self, limit: int = 100) -> Iterable[RiskEvent]:
        """Return the N most recent events."""
        return list(self.events)[-limit:]

    def events_by_layer(self, layer: str) -> List[RiskEvent]:
        """Filter events originating from a specific shield layer."""
        return [e for e in self.events if e.layer == layer]

    def events_by_fingerprint(self, fingerprint: str) -> List[RiskEvent]:
        """Return all events matching this attacker fingerprint."""
        return [e for e in self.events if e.fingerprint == fingerprint]

    # ------------------------------------------------------------------ #
    # Stats helpers
    # ------------------------------------------------------------------ #

    def feedback_stats(self) -> Dict[FeedbackType, int]:
        counts: Dict[FeedbackType, int] = defaultdict(int)
        for e in self.events:
            counts[e.feedback] += 1
        return dict(counts)

    def layer_stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for e in self.events:
            counts[e.layer] += 1
        return dict(counts)

    # ------------------------------------------------------------------ #
    # State Snapshots
    # ------------------------------------------------------------------ #

    def save_snapshot(self, state: AdaptiveState) -> None:
        """
        Save a copy of the current adaptive state (lightweight).
        Stored as a rolling window to prevent memory growth.
        """
        snapshot = StateSnapshot(
            timestamp=datetime.utcnow(),
            state=state.copy()  # ensure immutable snapshot
        )
        self.snapshots.append(snapshot)

    def latest_snapshot(self) -> Optional[StateSnapshot]:
        """Return the latest saved state snapshot."""
        if not self.snapshots:
            return None
        return self.snapshots[-1]

    def list_snapshots(self) -> List[StateSnapshot]:
        """List all saved snapshots."""
        return list(self.snapshots)
