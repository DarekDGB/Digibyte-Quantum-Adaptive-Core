# src/adaptive_core/engine.py

from __future__ import annotations

from typing import Dict, Iterable, List

from .models import (
    RiskEvent,
    FeedbackType,
    AdaptiveState,
    AdaptiveUpdateResult,
    LayerAdjustment,
)
from .memory import InMemoryAdaptiveStore
from .threat_memory import ThreatMemory
from .threat_packet import ThreatPacket


class AdaptiveEngine:
    """
    Reinforcement-style adaptive core for the DigiByte Quantum Shield.

    Very simple v0.1/v2 logic:

      - TRUE_POSITIVE:
          * increase weight of the reporting layer
          * slightly tighten global threshold

      - FALSE_POSITIVE:
          * decrease weight of the reporting layer
          * slightly relax global threshold

      - MISSED_ATTACK:
          * increase all layer weights a bit
          * tighten global threshold more

    All changes are small and bounded, to avoid oscillations.
    """

    def __init__(
        self,
        store: InMemoryAdaptiveStore | None = None,
        initial_state: AdaptiveState | None = None,
    ) -> None:
        # Store keeps a history of raw events (and in future, snapshots).
        self.store = store or InMemoryAdaptiveStore()
        # If no initial state is provided, start with an empty mapping and
        # default global_threshold from AdaptiveState.
        self.state = initial_state or AdaptiveState(layer_weights={})

        # Threat memory: stores unified ThreatPacket objects coming
        # from all shield layers. Loaded from disk if present.
        self.threat_memory = ThreatMemory()
        self.threat_memory.load()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def record_events(self, events: Iterable[RiskEvent]) -> None:
        """
        Add incoming risk events to the adaptive store and ensure each
        referenced layer has an initial neutral weight.
        """
        for e in events:
            self.store.add_event(e)
            if e.layer not in self.state.layer_weights:
                # start with neutral weight for new layers
                self.state.layer_weights[e.layer] = 1.0

    def apply_learning(self, events: Iterable[RiskEvent]) -> AdaptiveUpdateResult:
        """
        Apply reinforcement-style updates based on feedback for a batch
        of RiskEvents.
        """
        events_list: List[RiskEvent] = list(events)

        per_layer: Dict[str, LayerAdjustment] = {
            layer: LayerAdjustment() for layer in self.state.layer_weights
        }

        for event in events_list:
            self._apply_single_event(event, per_layer)

        self._clamp_state()

        return AdaptiveUpdateResult(
            state=self.state,
            per_layer=per_layer,
            processed_events=[e.event_id for e in events_list],
        )

    def receive_threat_packet(self, packet: ThreatPacket) -> None:
        """
        Receive a ThreatPacket from any shield layer and persist it
        into ThreatMemory.
        """
        self.threat_memory.add_packet(packet)
        self.threat_memory.save()

    def summarize_threats(self, min_severity: int = 0) -> Dict[str, int]:
        """
        Simple analysis of stored ThreatPackets.
        Returns: threat_type -> count
        """
        packets = self.threat_memory.list_packets()
        summary: Dict[str, int] = {}

        for p in packets:
            if p.severity < min_severity:
                continue
            summary[p.threat_type] = summary.get(p.threat_type, 0) + 1

        return summary

    def threat_insights(self, min_severity: int = 0) -> str:
        """
        Produce a human-readable summary of threat patterns stored in memory.
        Example output:
            High severity reorg patterns: 4
            Wallet anomalies: 2
            PQC entropy warnings: 1
        """
        summary = self.summarize_threats(min_severity=min_severity)

        if not summary:
            return "No threats recorded yet."

        lines = []
        for threat_type, count in summary.items():
            # Format the type nicely for humans
            label = threat_type.replace("_", " ").title()
            lines.append(f"{label}: {count}")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _apply_single_event(
        self,
        event: RiskEvent,
        per_layer: Dict[str, LayerAdjustment],
    ) -> None:
        layer = event.layer

        if layer not in self.state.layer_weights:
            self.state.layer_weights[layer] = 1.0
            per_layer[layer] = LayerAdjustment()

        adj = per_layer[layer]

        if event.feedback == FeedbackType.TRUE_POSITIVE:
            self.state.layer_weights[layer] += 0.05
            self.state.global_threshold += 0.01
            adj.weight_delta += 0.05
            adj.threshold_shift += 0.01

        elif event.feedback == FeedbackType.FALSE_POSITIVE:
            self.state.layer_weights[layer] -= 0.05
            self.state.global_threshold -= 0.01
            adj.weight_delta -= 0.05
            adj.threshold_shift -= 0.01

        elif event.feedback == FeedbackType.MISSED_ATTACK:
            for l in self.state.layer_weights:
                self.state.layer_weights[l] += 0.02
                per_layer.setdefault(l, LayerAdjustment()).weight_delta += 0.02
            self.state.global_threshold += 0.02

    def _clamp_state(self) -> None:
        """
        Keep weights and thresholds within safe bounded ranges.
        """
        for layer, w in list(self.state.layer_weights.items()):
            self.state.layer_weights[layer] = max(0.1, min(5.0, w))

        self.state.global_threshold = max(0.1, min(0.9, self.state.global_threshold))
