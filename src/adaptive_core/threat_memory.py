# src/adaptive_core/threat_memory.py

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from .threat_packet import ThreatPacket


class ThreatMemory:
    """
    Lightweight persistent store for ThreatPacket objects.

    Design goals:
      - very small footprint (default cap: 10_000 packets)
      - simple JSON representation
      - safe to load/save repeatedly
      - pruning of oldest entries to avoid unbounded growth
    """

    def __init__(
        self,
        path: Optional[Path] = None,
        max_packets: int = 10_000,
    ) -> None:
        # Where the JSON file is stored on disk.
        self.path: Path = path or Path("threat_memory.json")

        # In-memory list of ThreatPacket objects.
        self._packets: List[ThreatPacket] = []

        # Hard cap on how many packets we keep.
        # With compact JSON this keeps us safely in the sub-10 MB range
        # even with thousands of stored entries.
        self.max_packets: int = max_packets

    # ------------------------------------------------------------------ #
    # Basic operations
    # ------------------------------------------------------------------ #

    def add_packet(self, packet: ThreatPacket) -> None:
        """
        Append a new ThreatPacket and prune oldest entries if we exceed
        max_packets.
        """
        self._packets.append(packet)
        self._enforce_limit()

    def list_packets(self) -> List[ThreatPacket]:
        """
        Return a shallow copy of all stored packets.
        """
        return list(self._packets)

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #

    def load(self) -> None:
        """
        Load packets from disk if the file exists.

        Any excess entries beyond max_packets are pruned from the front
        (oldest first) to keep the memory bounded.
        """
        if not self.path.exists():
            self._packets = []
            return

        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            # On any parse error, start from a clean state.
            self._packets = []
            return

        packets: List[ThreatPacket] = []
        for item in raw:
            try:
                packets.append(ThreatPacket.from_dict(item))
            except Exception:
                # Skip malformed entries rather than failing hard.
                continue

        self._packets = packets
        self._enforce_limit()

    def save(self) -> None:
        """
        Persist the current packet list to disk as JSON.
        """
        data = [p.to_dict() for p in self._packets]
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _enforce_limit(self) -> None:
        """
        Ensure the in-memory packet list does not exceed max_packets.
        Oldest entries are discarded first (FIFO pruning).
        """
        if self.max_packets <= 0:
            # Treat non-positive caps as "no storage".
            self._packets = []
            return

        excess = len(self._packets) - self.max_packets
        if excess > 0:
            # Drop the oldest 'excess' packets from the front.
            self._packets = self._packets[excess:]
