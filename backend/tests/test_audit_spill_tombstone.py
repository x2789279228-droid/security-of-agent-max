# -*- coding: utf-8 -*-
"""spill 日志：drop 用墓碑追加，不截断重写。"""
from __future__ import annotations

import audit_spill


def _use(tmp_path, monkeypatch):
    path = tmp_path / "spill.jsonl"
    monkeypatch.setattr(audit_spill, "spill_path", lambda: path)
    return path


def test_drop_appends_tombstone_and_keeps_other_records(tmp_path, monkeypatch):
    path = _use(tmp_path, monkeypatch)
    assert audit_spill.append_record({"event_id": 1, "tier": "P0"})
    assert audit_spill.append_record({"event_id": 2, "tier": "P1"})
    assert audit_spill.append_record({"event_id": 3, "tier": "P1"})

    size_before = path.stat().st_size
    audit_spill.drop_event(2)
    assert path.stat().st_size > size_before, "drop 不应截断文件"
    assert {r["event_id"] for r in audit_spill.read_records()} == {1, 3}


def test_reappending_after_drop_reactivates_event(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    audit_spill.append_record({"event_id": 7, "tier": "P0"})
    audit_spill.drop_event(7)
    assert audit_spill.read_records() == []
    audit_spill.append_record({"event_id": 7, "tier": "P0"})
    rows = audit_spill.read_records()
    assert [r["event_id"] for r in rows] == [7]


def test_compact_keeps_only_active_records(tmp_path, monkeypatch):
    _use(tmp_path, monkeypatch)
    audit_spill.append_record({"event_id": 1})
    audit_spill.append_record({"event_id": 2})
    audit_spill.drop_event(1)
    audit_spill.compact()
    rows = audit_spill.read_records()
    assert [r["event_id"] for r in rows] == [2]


def test_bad_line_is_skipped(tmp_path, monkeypatch):
    path = _use(tmp_path, monkeypatch)
    audit_spill.append_record({"event_id": 5})
    with open(path, "a", encoding="utf-8") as f:
        f.write("{not-json}\n")
    assert [r["event_id"] for r in audit_spill.read_records()] == [5]
