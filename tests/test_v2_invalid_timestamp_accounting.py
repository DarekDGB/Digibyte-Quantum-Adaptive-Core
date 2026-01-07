from __future__ import annotations

from adaptive_core.engine import AdaptiveEngine
from adaptive_core.threat_packet import ThreatPacket


def test_detect_threat_trends_counts_invalid_timestamps():
    engine = AdaptiveEngine()

    good = ThreatPacket(
        source_layer="sentinel_ai_v2",
        threat_type="TEST_GOOD",
        severity=5,
        description="good packet",
        timestamp="2026-01-01T12:00:00Z",
    )

    bad = ThreatPacket(
        source_layer="sentinel_ai_v2",
        threat_type="TEST_BAD",
        severity=5,
        description="bad packet (corrupted timestamp)",
        timestamp="2026-01-01T13:00:00Z",
    )

    # Simulate legacy/corrupted data already present in memory:
    bad.timestamp = "not-a-timestamp"

    engine.receive_threat_packet(good)
    engine.receive_threat_packet(bad)

    trends = engine.detect_threat_trends(bucket="day")

    assert trends["invalid_timestamp_count"] == 1
    assert isinstance(trends["points"], list)
    assert len(trends["points"]) >= 1
