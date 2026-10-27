"""评测战绩 — 只读暴露 docs/benchmark 下的机器可读评测结果。

用途:把分层消融 / 对抗保持率 / CSIC-2010 回放 / 压测的定量结论搬进前端战绩页。
口径纪律:scope_note/note 原样透出(诚实口径本身是演示加分项,不许在展示层改写);
本 router 无任何写操作,文件缺失静默跳过(汇总)或 404(单份直取)。
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from auth import get_current_user, UserInfo

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/benchmark", tags=["benchmark"])

# docs/benchmark 位于仓库根:backend/routers/../../docs/benchmark。
# 容器内若为单层布局(backend 与 docs 同级拷贝)则退回第二候选。
_CANDIDATE_ROOTS = [
    Path(__file__).resolve().parent.parent.parent / "docs" / "benchmark",
    Path(__file__).resolve().parent.parent / "docs" / "benchmark",
]

# key → (文件名, 展示标题);*_pre 为规范化整改前的同口径结果,供前后对比
REPORTS: dict[str, tuple[str, str]] = {
    "replay_csic": ("REPLAY-CSIC-2010-result.json", "CSIC-2010 全量回放"),
    "replay_csic_pre": ("REPLAY-CSIC-2010-result-pre-normalization.json", "CSIC-2010 回放(规范化改前)"),
    "evasion": ("EVASION-result.json", "对抗保持率"),
    "evasion_pre": ("EVASION-result-pre-normalization.json", "对抗保持率(规范化改前)"),
    "ablation": ("ABLATION-result.json", "分层消融 L1→L5"),
    "ablation_pre": ("ABLATION-result-pre-normalization.json", "分层消融(规范化改前)"),
    "perf": ("PERF-2026-10-26-result.json", "大规模压测与故障注入"),
}


def _benchmark_dir() -> Path:
    for candidate in _CANDIDATE_ROOTS:
        if candidate.is_dir():
            return candidate
    raise HTTPException(status_code=404, detail="benchmark 结果目录不存在")


def _scope_note(data: dict[str, Any]) -> str:
    note = data.get("scope_note")
    if isinstance(note, str) and note:
        return note
    meta = data.get("meta")
    if isinstance(meta, dict) and isinstance(meta.get("note"), str):
        return meta["note"]
    note = data.get("note")
    return note if isinstance(note, str) else ""


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise HTTPException(status_code=500, detail=f"报告读取失败: {path.name}: {e}") from e
    return data if isinstance(data, dict) else {}


@router.get("/reports")
async def benchmark_reports(user: UserInfo = Depends(get_current_user)):
    """全部评测报告一次拉取(带标题与口径注释)。缺失的文件静默跳过。"""
    dir_path = _benchmark_dir()
    reports = []
    for key, (filename, title) in REPORTS.items():
        path = dir_path / filename
        if not path.is_file():
            continue
        try:
            data = _load(path)
        except HTTPException:
            continue
        reports.append({
            "key": key,
            "title": title,
            "file": filename,
            "scope_note": _scope_note(data),
            "data": data,
        })
    return {"reports": reports, "source": "docs/benchmark"}


@router.get("/reports/{key}")
async def benchmark_report(key: str, user: UserInfo = Depends(get_current_user)):
    """单份报告直取(key 见 REPORTS 表)。"""
    entry = REPORTS.get(key)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"未知报告 key: {key}")
    path = _benchmark_dir() / entry[0]
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"报告不存在: {entry[0]}")
    data = _load(path)
    return {
        "key": key,
        "title": entry[1],
        "file": entry[0],
        "scope_note": _scope_note(data),
        "data": data,
    }
