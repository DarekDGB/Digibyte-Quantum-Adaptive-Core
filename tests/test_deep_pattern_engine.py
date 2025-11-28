# tests/test_deep_pattern_engine.py

from __future__ import annotations

from pathlib import Path

from adaptive_core.threat_memory import ThreatMemory
from adaptive_core.threat_packet import ThreatPacket
from adaptive_core.pattern_engine import DeepPatternEngine


def _packet(i: int, severity: int = 5, threat_type: str = "test_threat") -> ThreatPacket:
    return ThreatPacket(
        source_layer="sentinel",
        threat_type=threat_type,
        severity=severity,
        description="deep-pattern-test",
        timestamp="2025-01-01T00:00:00Z",
        node_id=f"node-{i}",
        wallet_id=None,
        tx_id=None,
        block_height=i,
    )


def test_deep_pattern_engine_empty(tmp_path) -> None:
    """
    With no packets, DeepPatternEngine should return a safe,
    zeroed-out structure and risk == 0.
    """
    path: Path = tmp_path / "memory.json"
    mem = ThreatMemory(path=path, max_packets=1000)
    engine = DeepPatternEngine(memory=mem)

    result = engine.analyze()

    assert result["total_packets"] == 0
    assert result["composite_risk"] == 0.0
    assert result["spike_score"] == 0.0
    assert result["diversity_score"] == 0.0


def test_deep_pattern_engine_basic_spike_and_diversity(tmp_path) -> None:
    """
    When we add a bunch of recent packets, the engine should
    produce a non-zero risk and scores within [0, 1].
    """
    path: Path = tmp_path / "memory.json"
    mem = ThreatMemory(path=path, max_packets=1000)

    # Older, low-volume history
    for i in range(40):
        mem.add_packet(_packet(i, severity=3, threat_type="old_noise"))

    # Recent spike with more diverse threat types
    for i in range(40, 70):
        ttype = "type_a" if i % 2 == 0 else "type_b"
        mem.add_packet(_packet(i, severity=7, threat_type=ttype))

    mem.save()

    engine = DeepPatternEngine(memory=mem, short_window=20, long_window=100)
    result = engine.analyze(min_severity=0)

    # Structure checks
    for key in [
        "total_packets",
        "short_window",
        "long_window",
        "short_count",
        "long_count",
        "spike_ratio",
        "spike_score",
        "diversity_score",
        "composite_risk",
    ]:
        assert key in result

    # Score sanity: all are within [0, 1]
    assert 0.0 <= result["spike_score"] <= 1.0
    assert 0.0 <= result["diversity_score"] <= 1.0
    assert 0.0 <= result["composite_risk"] <= 1.0

    # With a spike and diversity, composite risk should be > 0
    assert result["composite_risk"] > 0.0
