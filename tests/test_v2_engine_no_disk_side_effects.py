from __future__ import annotations

from adaptive_core.engine import AdaptiveEngine


def test_engine_does_not_write_files_by_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    _ = AdaptiveEngine()  # default engine must not create files

    # If anything writes to disk by default, it will show up here.
    assert list(tmp_path.iterdir()) == []
