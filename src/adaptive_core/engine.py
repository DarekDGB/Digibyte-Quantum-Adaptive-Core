# src/adaptive_core/engine.py

from __future__ import annotations

from typing import Dict, Iterable, List, Any
from datetime import datetime

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

    def analyze_threats(
        self,
        min_severity: int = 0,
        last_n: int = 5,
    ) -> Dict[str, Any]:
        """
        Basic threat analysis stub.

        Returns a dictionary with:
            - total_count: total number of recorded threats (after filter)
            - average_severity: float (0 if no threats)
            - max_severity: highest severity seen (0 if none)
            - most_common_type: threat_type string or None
            - last_threats: list of last N threats (dicts with key details)
        """
        packets = [
            p for p in self.threat_memory.list_packets()
            if p.severity >= min_severity
        ]

        if not packets:
            return {
                "total_count": 0,
                "average_severity": 0.0,
                "max_severity": 0,
                "most_common_type": None,
                "last_threats": [],
            }

        total_count = len(packets)
        severities = [p.severity for p in packets]
        average_severity = sum(severities) / float(total_count)
        max_severity = max(severities)

        # most common threat_type
        type_counts: Dict[str, int] = {}
        for p in packets:
            type_counts[p.threat_type] = type_counts.get(p.threat_type, 0) + 1
        most_common_type = max(type_counts.items(), key=lambda x: x[1])[0]

        # last N threats (most recent at the end of memory list)
        last = packets[-last_n:]
        last_threats = [
            {
                "source_layer": p.source_layer,
                "threat_type": p.threat_type,
                "severity": p.severity,
                "timestamp": p.timestamp,
                "node_id": p.node_id,
                "wallet_id": p.wallet_id,
                "tx_id": p.tx_id,
                "block_height": p.block_height,
            }
            for p in last
        ]

        return {
            "total_count": total_count,
            "average_severity": average_severity,
            "max_severity": max_severity,
            "most_common_type": most_common_type,
            "last_threats": last_threats,
        }

    def detect_threat_patterns(
        self,
        min_severity: int = 0,
        window: int = 20,
    ) -> Dict[str, Any]:
        """
        Detect simple threat patterns in recent history.
        """
        packets = [
            p for p in self.threat_memory.list_packets()
            if p.severity >= min_severity
        ]

        if not packets:
            return {
                "window_size": window,
                "total_considered": 0,
                "rising_patterns": [],
                "hotspot_layers": [],
            }

        total_considered = len(packets)
        recent = packets[-window:]

        total_type_counts: Dict[str, int] = {}
        recent_type_counts: Dict[str, int] = {}
        for p in packets:
            total_type_counts[p.threat_type] = total_type_counts.get(p.threat_type, 0) + 1
        for p in recent:
            recent_type_counts[p.threat_type] = recent_type_counts.get(p.threat_type, 0) + 1

        rising_patterns = []
        for t, recent_count in recent_type_counts.items():
            total_count = total_type_counts.get(t, 0)
            if total_count == 0:
                continue

            recent_freq = recent_count / float(len(recent))
            overall_freq = total_count / float(total_considered)

            if recent_count >= 2 and recent_freq > overall_freq * 1.5:
                rising_patterns.append(
                    {
                        "threat_type": t,
                        "recent_count": recent_count,
                        "total_count": total_count,
                        "recent_frequency": recent_freq,
                        "overall_frequency": overall_freq,
                    }
                )

        layer_counts: Dict[str, int] = {}
        for p in recent:
            layer_counts[p.source_layer] = layer_counts.get(p.source_layer, 0) + 1

        hotspot_layers = [
            {"source_layer": layer, "recent_count": count}
            for layer, count in sorted(
                layer_counts.items(), key=lambda x: x[1], reverse=True
            )
        ]

        return {
            "window_size": len(recent),
            "total_considered": total_considered,
            "rising_patterns": rising_patterns,
            "hotspot_layers": hotspot_layers,
        }

    def detect_threat_correlations(
        self,
        min_severity: int = 0,
    ) -> Dict[str, Any]:
        """
        Detect simple correlations between threats.

        Looks for:
            - frequent adjacent threat-type pairs
            - common (source_layer, threat_type) combinations
        """
        packets = [
            p for p in self.threat_memory.list_packets()
            if p.severity >= min_severity
        ]

        if len(packets) < 2:
            return {
                "pair_correlations": [],
                "layer_threat_combos": [],
            }

        # Adjacent threat-type pairs
        pair_counts: Dict[tuple[str, str], int] = {}
        for i in range(len(packets) - 1):
            a = packets[i].threat_type
            b = packets[i + 1].threat_type
            key = (a, b)
            pair_counts[key] = pair_counts.get(key, 0) + 1

        pair_correlations = [
            {
                "from_type": a,
                "to_type": b,
                "count": count,
            }
            for (a, b), count in sorted(
                pair_counts.items(), key=lambda x: x[1], reverse=True
            )
        ]

        # (layer, threat_type) combinations
        combo_counts: Dict[tuple[str, str], int] = {}
        for p in packets:
            key = (p.source_layer, p.threat_type)
            combo_counts[key] = combo_counts.get(key, 0) + 1

        layer_threat_combos = [
            {
                "source_layer": layer,
                "threat_type": ttype,
                "count": count,
            }
            for (layer, ttype), count in sorted(
                combo_counts.items(), key=lambda x: x[1], reverse=True
            )
        ]

        return {
            "pair_correlations": pair_correlations,
            "layer_threat_combos": layer_threat_combos,
        }

    def detect_threat_trends(
        self,
        min_severity: int = 0,
        bucket: str = "hour",
    ) -> Dict[str, Any]:
        """
        Detect simple time-based trends in threat activity.

        bucket:
            - "hour" → group by YYYY-MM-DD HH:00
            - "day"  → group by YYYY-MM-DD
        """
        packets = [
            p for p in self.threat_memory.list_packets()
            if p.severity >= min_severity
        ]

        if not packets:
            return {
                "bucket": bucket,
                "points": [],
                "trend_direction": "unknown",
                "start_total": 0,
                "end_total": 0,
            }

        bucket_counts: Dict[str, int] = {}
        bucket_high: Dict[str, int] = {}

        for p in packets:
            try:
                ts = datetime.fromisoformat(p.timestamp.replace("Z", ""))
            except Exception:
                continue

            if bucket == "day":
                key = ts.strftime("%Y-%m-%d")
            else:
                key = ts.strftime("%Y-%m-%d %H:00")

            bucket_counts[key] = bucket_counts.get(key, 0) + 1
            if p.severity >= 8:
                bucket_high[key] = bucket_high.get(key, 0) + 1

        if not bucket_counts:
            return {
                "bucket": bucket,
                "points": [],
                "trend_direction": "unknown",
                "start_total": 0,
                "end_total": 0,
            }

        keys_sorted = sorted(bucket_counts.keys())
        points = [
            {
                "bucket": k,
                "total": bucket_counts[k],
                "high_severity": bucket_high.get(k, 0),
            }
            for k in keys_sorted
        ]

        start_total = bucket_counts[keys_sorted[0]]
        end_total = bucket_counts[keys_sorted[-1]]

        if len(keys_sorted) < 2:
            trend_direction = "unknown"
        elif end_total > start_total:
            trend_direction = "increasing"
        elif end_total < start_total:
            trend_direction = "decreasing"
        else:
            trend_direction = "flat"

        return {
            "bucket": bucket,
            "points": points,
            "trend_direction": trend_direction,
            "start_total": start_total,
            "end_total": end_total,
        }

    def generate_immune_report(
        self,
        min_severity: int = 0,
        pattern_window: int = 20,
        trend_bucket: str = "hour",
        last_n: int = 5,
    ) -> Dict[str, Any]:
        """
        High-level immune system report combining all analysis components.

        Returns a dictionary with:
            - summary
            - analysis
            - patterns
            - correlations
            - trends
            - text: multi-line human-readable report
        """
        summary = self.summarize_threats(min_severity=min_severity)
        analysis = self.analyze_threats(
            min_severity=min_severity,
            last_n=last_n,
        )
        patterns = self.detect_threat_patterns(
            min_severity=min_severity,
            window=pattern_window,
        )
        correlations = self.detect_threat_correlations(
            min_severity=min_severity,
        )
        trends = self.detect_threat_trends(
            min_severity=min_severity,
            bucket=trend_bucket,
        )

        # Build human-readable text
        lines: List[str] = []
        lines.append("=== DigiByte Quantum Adaptive Core — Immune Report ===")
        lines.append(f"Min severity filter: {min_severity}")
        lines.append("")

        # Summary section
        lines.append(">> Threat Summary:")
        if not summary:
            lines.append("  No threats recorded yet.")
        else:
            for t, count in summary.items():
                label = t.replace("_", " ").title()
                lines.append(f"  - {label}: {count}")
        lines.append("")

        # Analysis section
        lines.append(">> Analysis:")
        lines.append(f"  Total threats: {analysis['total_count']}")
        lines.append(f"  Average severity: {analysis['average_severity']:.2f}")
        lines.append(f"  Max severity: {analysis['max_severity']}")
        lines.append(f"  Most common type: {analysis['most_common_type']}")
        lines.append("")

        # Patterns
        lines.append(">> Rising Patterns (recent vs overall):")
        if not patterns["rising_patterns"]:
            lines.append("  None detected.")
        else:
            for p in patterns["rising_patterns"]:
                label = p["threat_type"].replace("_", " ").title()
                lines.append(
                    f"  - {label}: recent {p['recent_count']} "
                    f"(freq {p['recent_frequency']:.2f}) "
                    f"vs overall {p['total_count']} "
                    f"(freq {p['overall_frequency']:.2f})"
                )
        lines.append("")

        # Hotspot layers
        lines.append(">> Hotspot Layers (most active in recent window):")
        if not patterns["hotspot_layers"]:
            lines.append("  None detected.")
        else:
            for h in patterns["hotspot_layers"]:
                lines.append(
                    f"  - {h['source_layer']}: {h['recent_count']} recent events"
                )
        lines.append("")

        # Correlations
        lines.append(">> Correlations:")
        if not correlations["pair_correlations"]:
            lines.append("  No adjacent threat-type correlations detected.")
        else:
            top_pairs = correlations["pair_correlations"][:5]
            lines.append("  Most common threat-type pairs:")
            for pair in top_pairs:
                a = pair["from_type"].replace("_", " ").title()
                b = pair["to_type"].replace("_", " ").title()
                lines.append(f"    - {a} → {b}: {pair['count']} times")

        if not correlations["layer_threat_combos"]:
            lines.append("  No strong (layer, threat) combinations.")
        else:
            top_combos = correlations["layer_threat_combos"][:5]
            lines.append("  Most active (layer, threat) combinations:")
            for c in top_combos:
                tlabel = c["threat_type"].replace("_", " ").title()
                lines.append(
                    f"    - {c['source_layer']} / {tlabel}: {c['count']} events"
                )
        lines.append("")

        # Trends
        lines.append(">> Time Trends:")
        lines.append(
            f"  Trend direction ({trends['bucket']}): {trends['trend_direction']}"
        )
        lines.append(
            f"  Start total: {trends['start_total']}, "
            f"End total: {trends['end_total']}"
        )
        if trends["points"]:
            lines.append("  Points:")
            for p in trends["points"]:
                lines.append(
                    f"    - {p['bucket']}: total={p['total']}, "
                    f"high_severity={p['high_severity']}"
                )
        lines.append("")

        return {
            "summary": summary,
            "analysis": analysis,
            "patterns": patterns,
            "correlations": correlations,
            "trends": trends,
            "text": "\n".join(lines),
        }

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
