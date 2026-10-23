"""审计任务的本地可恢复日志。

内存队列和兜底 deque 扛不住进程退出。写进这个文件并 fsync 之后，
下次启动可以再放回 worker。它覆盖进程崩溃，不覆盖磁盘本身损坏。
Kafka overflow 或 Redis PQ 成功时不必再写这里。

2026-10-21：`drop_event` 从“截断重写”改为**追加墓碑行**：
  * 每完成一个任务只 append 一行 `{"event_id": n, "_drop": true}` + fsync；
  * 崩溃不会把整个 spill 文件截断（旧实现写一半就丢全部）；
  * 文件超过阈值时才做一次 compact，compact 用临时文件 + os.replace。
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from config import settings

logger = logging.getLogger(__name__)

_COMPACT_BYTES = 1_000_000


def spill_path() -> Path:
    raw = str(getattr(settings, "audit_spill_path", "") or "").strip()
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parent / "runtime" / "audit-spill.jsonl"


def append_record(record: dict) -> bool:
    path = spill_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except Exception as exc:
        logger.error("audit spill append failed path=%s: %s", path, exc)
        return False


def read_records() -> list[dict]:
    """重放日志：普通行 = 任务，`_drop` 行 = 墓碑。"""
    path = spill_path()
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        logger.error("audit spill read failed path=%s: %s", path, exc)
        return []

    latest: dict[int, dict] = {}
    order: list[int] = []
    dropped: set[int] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            logger.error("audit spill skipped bad line")
            continue
        if not isinstance(item, dict):
            continue
        try:
            eid = int(item.get("event_id") or 0)
        except (TypeError, ValueError):
            continue
        if eid <= 0:
            continue
        if item.get("_drop"):
            dropped.add(eid)
            continue
        if eid not in latest:
            order.append(eid)
        latest[eid] = item
        # 同一 event_id 重新入队 → 撤销之前的墓碑。
        dropped.discard(eid)

    return [latest[eid] for eid in order if eid not in dropped]


def drop_event(event_id: int) -> None:
    eid = int(event_id or 0)
    if eid <= 0 or not spill_path().is_file():
        return
    # 追加墓碑，而不是重写整个文件。
    if not append_record({"event_id": eid, "_drop": True}):
        return
    try:
        path = spill_path()
        if path.stat().st_size > _COMPACT_BYTES:
            compact()
    except Exception as exc:
        logger.error("audit spill drop/compact failed event_id=%s: %s", eid, exc)


def replace_records(records: list[dict]) -> None:
    """原子替换（供 compact / 测试使用）：临时文件 + fsync + os.replace。"""
    path = spill_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not records:
        if path.exists():
            path.unlink()
        return
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = "".join(json.dumps(row, ensure_ascii=False, default=str) + "\n" for row in records)
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def compact() -> None:
    """把追加日志压缩为当前活跃任务，保留墓碑语义。"""
    records = read_records()
    replace_records(records)
    logger.info("audit spill compacted: %d active records", len(records))
