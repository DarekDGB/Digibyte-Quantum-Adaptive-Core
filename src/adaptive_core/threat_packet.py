# src/adaptive_core/threat_packet.py

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Optional
import uuid


@dataclass
class ThreatPacket:
    """
    Unified threat message used by all DigiByte Quantum Shield layers
    when talking to the Adaptive Core.

    v2 hygiene rules (Patch D/E):
      - Keep v2 convenience (auto-fill timestamp/correlation_id if empty).
      - If timestamp is PROVIDED (non-empty), it must be ISO-parseable.
      - If correlation_id is PROVIDED (non-empty), it must be non-empty string.
      - Severity is clamped into [0, 10] (existing v2 behavior).
      - metadata is always a dict (existing v2 behavior).
    """

    # Which layer sent this packet (e.g. "sentinel_ai_v2", "adn_v2", etc.)
    source_layer: str

    # Short label of what type of threat this is (e.g. "reorg", "pqc_risk", "wallet_anomaly")
    threat_type: str

    # Numerical severity level: 0–10 (0 = info, 10 = critical)
    severity: int

    # Human-readable short description for logs and debugging
    description: str

    # Optional node / wallet / tx / block ids
    node_id: Optional[str] = None
    wallet_id: Optional[str] = None
    tx_id: Optional[str] = None
    block_height: Optional[int] = None

    # Extra data specific to each layer
    metadata: Optional[Dict[str, Any]] = None

    # Correlation id to link multiple packets from the same incident
    correlation_id: str = ""
    # ISO timestamp (UTC, may end with 'Z')
    timestamp: str = ""

    def __post_init__(self) -> None:
        # --- Validate required string fields (light v2 hygiene, no breaking changes) ---
        # We do not raise for empty values here because v2 may be permissive,
        # but we normalise to strings to avoid type confusion.
        self.source_layer = str(self.source_layer)
        self.threat_type = str(self.threat_type)
        self.description = str(self.description)

        # --- Timestamp handling ---
        # Keep v2 convenience: auto-fill timestamp if missing/empty.
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
        else:
            # If caller provided a timestamp, it must be parseable.
            # Accept the common trailing Z by stripping it for fromisoformat().
            ts = str(self.timestamp)
            try:
                datetime.fromisoformat(ts.replace("Z", ""))
            except ValueError as e:
                raise ValueError(f"Invalid timestamp format: {self.timestamp!r}") from e
            self.timestamp = ts

        # --- Correlation ID handling ---
        # Keep v2 convenience: auto-generate correlation_id if missing/empty.
        if not self.correlation_id:
            self.correlation_id = str(uuid.uuid4())
        else:
            cid = str(self.correlation_id).strip()
            if not cid:
                raise ValueError("correlation_id must be a non-empty string when provided")
            self.correlation_id = cid

        # --- Clamp severity between 0 and 10 (existing v2 behavior) ---
        try:
            sev = int(self.severity)
        except Exception as e:
            raise ValueError(f"severity must be an int-like value, got {self.severity!r}") from e

        if sev < 0:
            sev = 0
        if sev > 10:
            sev = 10
        self.severity = sev

        # --- Ensure metadata is always a dict (existing v2 behavior) ---
        if self.metadata is None:
            self.metadata = {}
        elif not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dict when provided")

    def to_dict(self) -> Dict[str, Any]:
        """Convert ThreatPacket to a plain dict (for JSON, logging, etc.)."""
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ThreatPacket":
        """Rebuild ThreatPacket from a dict."""
        if not isinstance(data, dict):
            raise ValueError("ThreatPacket.from_dict expects a dict")
        return ThreatPacket(**data)
