# tests/test_pattern_engine.py

from adaptive_core.engine import AdaptiveEngine
from adaptive_core.threat_memory import ThreatMemory
from adaptive_core.threat_packet import ThreatPacket
from pathlib import Path


def _packet(i: int) -> ThreatPacket:
    return ThreatPacket(
        source_layer="sentinel",
        threat_type="anomaly",
        severity=3,
        description="pattern-test",
        timestamp="2025-01-01T00:00:00Z",
        node_id=f"node-{i}",
        wallet_id=None,
        tx_id=None,
        block_height=i,
    )


def test_engine_pattern_detector_runs(tmp_path):
    """
    Ensure AdaptiveEngine._run_pattern_detector executes
    without raising errors with sample packets.
    """
    mem_path = tmp_path / "memory.json"
    store = ThreatMemory(path=mem_path, max_packets=200)
    engine = AdaptiveEngine(store=store)

    # Add packets to memory
    for i in range(10):
        engine.receive_threat_packet(_packet(i))

    # Call the pattern detector — should return a dict (stub)
    result = engine._run_pattern_detector()

    assert isinstance(result, dict)
    assert "pattern_found" in result


def test_engine_correlation_detector_runs(tmp_path):
    """
    Ensure AdaptiveEngine._run_correlation_detector runs
    with stored packets and returns a dict (stub).
    """
    mem_path = tmp_path / "memory.json"
    store = ThreatMemory(path=mem_path, max_packets=200)
    engine = AdaptiveEngine(store=store)

    for i in range(10):
        engine.receive_threat_packet(_packet(i))

    result = engine._run_correlation_detector()

    assert isinstance(result, dict)
    assert "correlation_score" in result
