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

        Returns an AdaptiveUpdateResult with:
          - updated global AdaptiveState
          - per-layer adjustment summary
          - list of processed event IDs
        """
        # Materialise iterable once so we can loop and also collect IDs safely.
        events_list: List[RiskEvent] = list(events)

        per_layer: Dict[str, LayerAdjustment] = {
            layer: LayerAdjustment() for layer in self.state.layer_weights
        }

        for event in events_list:
            self._apply_single_event(event, per_layer)

        # Clamp values to safe ranges.
        self._clamp_state()

        result = AdaptiveUpdateResult(
            state=self.state,
            per_layer=per_layer,
            processed_events=[e.event_id for e in events_list],
        )
        return result

    def summarize_threats(self, min_severity: int = 0) -> Dict[str, int]:
        """
        Simple analysis of stored ThreatPackets.

        Returns a mapping:
            threat_type -> count

        You can filter out low-severity noise by setting min_severity.
        """
        packets = self.threat_memory.list_packets()
        summary: Dict[str, int] = {}

        for p in packets:
            if p.severity < min_severity:
                continue
            summary[p.threat_type] = summary.get(p.threat_type, 0) + 1

        return summary

    def receive_threat_packet(self, packet: ThreatPacket) -> None:
        """
        Receive a ThreatPacket from any shield layer and persist it
        into ThreatMemory.

        Later, this stored history will be used for deeper analysis
        and pattern-based adaptation.
        """
        self.threat_memory.add_packet(packet)
        self.threat_memory.save()

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
            # New layer encountered during learning – start neutral.
            self.state.layer_weights[layer] = 1.0
            per_layer[layer] = LayerAdjustment()

        adj = per_layer[layer]

        if event.feedback == FeedbackType.TRUE_POSITIVE:
            # The reporting layer was correct → trust it a bit more,
            # and make the system slightly stricter.
            self.state.layer_weights[layer] += 0.05
            self.state.global_threshold += 0.01
            adj.weight_delta += 0.05
            adj.threshold_shift += 0.01

        elif event.feedback == FeedbackType.FALSE_POSITIVE:
            # The reporting layer overreacted → trust it a bit less,
            # and relax the global threshold slightly.
            self.state.layer_weights[layer] -= 0.05
            self.state.global_threshold -= 0.01
            adj.weight_delta -= 0.05
            adj.threshold_shift -= 0.01

        elif event.feedback == FeedbackType.MISSED_ATTACK:
            # A real attack slipped through → *all* layers need to become
            # more sensitive, and the global threshold tightens more.
            for l in self.state.layer_weights:
                self.state.layer_weights[l] += 0.02
                per_layer.setdefault(l, LayerAdjustment()).weight_delta += 0.02
            self.state.global_threshold += 0.02

        # UNKNOWN feedback → no learning

    def _clamp_state(self) -> None:
        """
        Keep the adaptive parameters within safe, bounded ranges to avoid
        runaway behaviour or oscillations.
        """
        # keep weights within [0.1, 5.0]
        for layer, w in list(self.state.layer_weights.items()):
            self.state.layer_weights[layer] = max(0.1, min(5.0, w))

        # keep threshold within [0.1, 0.9]
        self.state.global_threshold = max(0.1, min(0.9, self.state.global_threshold))
