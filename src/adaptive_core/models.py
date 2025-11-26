# src/adaptive_core/models.py

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime


class FeedbackType(str, Enum):
    """
    How the incident was classified *after* the fact.

    This is what drives reinforcement:

      - TRUE_POSITIVE  – real attack, detection was correct
      - FALSE_POSITIVE – benign activity flagged as risky
      - MISSED_ATTACK  – attack confirmed but shield didn't react enough
      - UNKNOWN        – no clear feedback yet
    """

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    MISSED_ATTACK = "missed_attack"
    UNKNOWN = "unknown"


@dataclass
class RiskEvent:
    """
    Single incident observed by the shield.

    This is what Sentinel / DQSN / ADN / Wallet Guard / QWG
    send into the Adaptive Core.
    """

    event_id: str
    layer: str                    # e.g. "sentinel", "dqs", "adn", "wallet", "qwg"
    risk_score: float             # e.g. 0.0 – 1.0 QRI-like value
    risk_level: str               # e.g. "normal", "elevated", "high", "critical"
    fingerprint: Optional[str] = None  # hash / pattern identifier
    created_at: datetime = field(default_factory=datetime.utcnow)
    feedback: FeedbackType = FeedbackType.UNKNOWN


@dataclass
class LayerAdjustment:
    """
    Output of the adaptive engine for a single layer.
    """

    weight_delta: float = 0.0      # +0.1 means "trust this layer more"
    threshold_shift: float = 0.0   # +0.05 means "tighten thresholds"
    notes: Optional[str] = None


@dataclass
class AdaptiveState:
    """
    Snapshot of the current adaptive parameters.

    In a real deployment this would be persisted in a DB or config store.
    """

    layer_weights: Dict[str, float] = field(default_factory=dict)
    global_threshold: float = 0.5  # base QRI threshold (0–1 range)
    last_updated: datetime = field(default_factory=datetime.utcnow)

    def normalised_weights(self) -> Dict[str, float]:
        total = sum(self.layer_weights.values()) or 1.0
        return {k: v / total for k, v in self.layer_weights.items()}


@dataclass
class AdaptiveUpdateResult:
    """
    Result returned after processing a batch of events.
    """

    state: AdaptiveState
    per_layer: Dict[str, LayerAdjustment] = field(default_factory=dict)
    processed_events: List[str] = field(default_factory=list)

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any


@dataclass
class AdaptiveEvent:
    """
    Generic event coming from Sentinel, DQSN, ADN, Wallet Guardian, or QWG.
    This allows Adaptive Core to learn attacker behavior over time.
    """

    layer: str
    anomaly_type: str
    severity: float
    qri_delta: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
