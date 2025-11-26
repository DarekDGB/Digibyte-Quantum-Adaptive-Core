# src/adaptive_core/memory.py

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Iterable
from dataclasses import dataclass, field

from .models import RiskEvent, FeedbackType


@dataclass
class InMemoryAdaptiveStore:
    """
    Simple in-memory store for prototype / testing.

    Production deployments could replace this with:
      - Redis
      - SQL
      - on-disk log files
    while keeping the same interface.
    """

    events: List[RiskEvent] = field(default_factory=list)

    def add_event(self, event: RiskEvent) -> None:
        self.events.append(event)

    def list_events(self) -> List[RiskEvent]:
        return list(self.events)

    def events_by_fingerprint(self, fingerprint: str) -> List[RiskEvent]:
        return [e for e in self.events if e.fingerprint == fingerprint]

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

    def recent_events(self, limit: int = 100) -> Iterable[RiskEvent]:
        return list(self.events[-limit:])
