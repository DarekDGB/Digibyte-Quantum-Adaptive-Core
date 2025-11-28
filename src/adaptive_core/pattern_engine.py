# src/adaptive_core/pattern_engine.py

from __future__ import annotations

from typing import Dict, Any, List

from .threat_memory import ThreatMemory
from .threat_packet import ThreatPacket


class DeepPatternEngine:
    """
    DeepPatternEngine v2

    A lightweight "deep pattern" scanner over ThreatMemory.

    Goals:
      - compare short-term vs long-term activity
      - detect spikes in threat volume
      - measure diversity of threat types
      - emit a composite risk score in [0.0, 1.0]

    This is intentionally simple and deterministic so it is easy to
    test and safe to evolve later.
    """

    def __init__(
        self,
        memory: ThreatMemory,
        short_window: int = 50,
        long_window: int = 500,
    ) -> None:
        self.memory = memory
        self.short_window = max(1, short_window)
        self.long_window = max(self.short_window, long_window)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def analyze(self, min_severity: int = 0) -> Dict[str, Any]:
        """
        Run deep pattern analysis on the current ThreatMemory state.

        Returns a dictionary with:
          - total_packets
          - short_window
          - long_window
          - short_count
          - long_count
          - spike_ratio
          - spike_score       (0.0 .. 1.0)
          - diversity_score   (0.0 .. 1.0)
          - composite_risk    (0.0 .. 1.0)
        """
        packets: List[ThreatPacket] = [
            p
            for p in self.memory.list_packets()
            if p.severity >= min_severity
        ]
        total = len(packets)

        if total == 0:
            return {
                "total_packets": 0,
                "short_window": self.short_window,
                "long_window": self.long_window,
                "short_count": 0,
                "long_count": 0,
                "spike_ratio": 0.0,
                "spike_score": 0.0,
                "diversity_score": 0.0,
                "composite_risk": 0.0,
            }

        # Long window (older + recent)
        long_slice = packets[-self.long_window :]
        long_count = len(long_slice)

        # Short window (most recent activity)
        short_slice = packets[-self.short_window :]
        short_count = len(short_slice)

        # ------------------------------------------------------------------
        # Spike score: is recent activity much higher than long-term average?
        # ------------------------------------------------------------------
        long_rate = long_count / float(self.long_window)
        short_rate = short_count / float(self.short_window)

        if long_rate == 0.0:
            spike_ratio = 1.0 if short_rate > 0.0 else 0.0
        else:
            spike_ratio = short_rate / long_rate

        # Map spike_ratio into [0, 1]:
        #  - 1.0  → no spike (score 0)
        #  - 2.0+ → strong spike (score approaches 1)
        raw_spike = max(0.0, spike_ratio - 1.0)
        spike_score = self._clamp(raw_spike / 1.0, 0.0, 1.0)

        # ------------------------------------------------------------------
        # Diversity score: how many different threat types appear recently?
        # ------------------------------------------------------------------
        if short_count == 0:
            diversity_score = 0.0
        else:
            unique_types = {p.threat_type for p in short_slice}
            diversity_score = self._clamp(
                len(unique_types) / float(short_count),
                0.0,
                1.0,
            )

        # ------------------------------------------------------------------
        # Composite risk: weighted mix of spike & diversity.
        # ------------------------------------------------------------------
        composite = 0.6 * spike_score + 0.4 * diversity_score
        composite_risk = self._clamp(composite, 0.0, 1.0)

        return {
            "total_packets": total,
            "short_window": self.short_window,
            "long_window": self.long_window,
            "short_count": short_count,
            "long_count": long_count,
            "spike_ratio": spike_ratio,
            "spike_score": spike_score,
            "diversity_score": diversity_score,
            "composite_risk": composite_risk,
        }

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _clamp(value: float, lower: float, upper: float) -> float:
        return max(lower, min(upper, value))
