"""审计死信闭环（2026-10-23 第二阶段）

Redis PQ 的 payload 有 TTL（分档 5min-1h）。payload 先过期、ZSET 成员
还在时，任务不可恢复地丢失 —— 修复前只剩一个 inc_audit_pq_lost 计数器，
漏审既不可见也不可补救。

闭环三步：
  1) record():  audit_pq 三个 LOST 点 + purge_stale 幽灵清理时, 把
     event_id 落库（同 event+reason 唯一, 重复发现不膨胀）;
  2) replay():  启动时(lifespan)把未重放且事件仍未分析的重新提交
     audit worker（复用 recover_unanalyzed 的重建逻辑）;
  3) 指标:      soc_audit_dead_letter_total / _replayed_total。

写失败只告警不抛 —— 死信是"最后痕迹"，不能反过来弄垮检测主路径。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


async def record(event_id: int, reason: str = "payload_missing", detail: str = "") -> bool:
    """记一条死信。幂等：(event_id, reason) 唯一。"""
    if not event_id:
        return False
    try:
        from models import AuditDeadLetter, async_session
        from sqlalchemy.exc import IntegrityError
        async with async_session() as s:
            s.add(AuditDeadLetter(
                event_id=int(event_id), reason=str(reason or "payload_missing")[:60],
                detail=str(detail or "")[:2000],
            ))
            await s.commit()
        try:
            from metrics import AUDIT_DEAD_LETTER
            AUDIT_DEAD_LETTER.labels(reason=str(reason or "?")).inc()
        except Exception:
            pass
        logger.error(
            "[AuditDeadLetter] event#%s reason=%s —— PQ 任务丢失已落库, 启动时将重放",
            event_id, reason,
        )
        return True
    except IntegrityError:
        return True  # 已登记过, 视为成功
    except Exception as e:
        logger.warning(f"[AuditDeadLetter] record event#{event_id} failed: {e}")
        return False


async def replay_dead_letters(limit: int = 200) -> int:
    """把未重放的死信再送进 audit worker。返回实际重放数。

    判定: 事件已不存在/已 analyzed → 直接标记完成（不再是漏审）;
          仍未分析 → 按 recover_unanalyzed 同样的方式重建任务提交。
    """
    from sqlalchemy import select

    from models import AuditDeadLetter, SecurityEvent, async_session

    try:
        async with async_session() as s:
            rows = (await s.execute(
                select(AuditDeadLetter)
                .where(AuditDeadLetter.replayed_at.is_(None))
                .order_by(AuditDeadLetter.id.asc())
                .limit(max(1, int(limit)))
            )).scalars().all()
            if not rows:
                return 0
            ids = [r.event_id for r in rows]
            events = {}
            ev_rows = (await s.execute(
                select(SecurityEvent).where(SecurityEvent.id.in_(ids))
            )).scalars().all()
            for ev in ev_rows:
                events[int(ev.id)] = ev
    except Exception as e:
        logger.warning(f"[AuditDeadLetter] replay scan failed: {e}")
        return 0

    from anomaly_detector import AnomalyReport
    from audit_worker import audit_worker

    replayed = 0
    for row in rows:
        note = ""
        try:
            ev = events.get(int(row.event_id))
            if ev is None:
                note = "event_missing"
            elif bool(ev.analyzed):
                note = "already_analyzed"
            elif not audit_worker.started:
                note = "worker_not_started"
            else:
                raw = dict(ev.raw_data or {})
                score = float(ev.anomaly_score or 0)
                anomaly = raw.get("_anomaly") if isinstance(raw.get("_anomaly"), dict) else {}
                report = AnomalyReport(
                    event_id=int(ev.id),
                    anomaly_score=score,
                    is_anomaly=score >= 0.6,
                    deviation_sigma=0.0,
                    reasons=list(anomaly.get("reasons") or []),
                )
                status = await audit_worker.submit(
                    session_id=ev.session_id or "",
                    event_id=int(ev.id),
                    log_data=raw,
                    anomaly_report=report,
                )
                note = f"resubmit:{status}"
                if status in ("queued", "shed", "deferred", "spilled", "direct"):
                    replayed += 1
                    try:
                        from metrics import AUDIT_DEAD_LETTER_REPLAYED
                        AUDIT_DEAD_LETTER_REPLAYED.inc()
                    except Exception:
                        pass
        except Exception as e:
            note = f"error:{e}"[:180]
            logger.warning(f"[AuditDeadLetter] replay event#{row.event_id} failed: {e}")
        # 无论结果如何都标记已处理(带 note), 避免每次启动都重扫同一批
        try:
            from models import async_session as _sf
            async with _sf() as s:
                db_row = await s.get(AuditDeadLetter, row.id)
                if db_row is not None:
                    db_row.replayed_at = datetime.now(timezone.utc)
                    db_row.replay_note = note[:190]
                    db_row.replay_attempts = int(db_row.replay_attempts or 0) + 1
                    await s.commit()
        except Exception as e:
            logger.warning(f"[AuditDeadLetter] mark replayed event#{row.event_id} failed: {e}")

    if rows:
        logger.warning(
            "[AuditDeadLetter] replayed %d/%d dead letter(s) (resubmitted=%d)",
            len(rows), len(rows), replayed,
        )
    return replayed
